#!/usr/bin/env python3
"""One comparison round: AnLiu (realnet, current main) and SRT (srtnet) side by
side on one path at the same time, each in its own tc band on the sender
(TBF RATE, burst 16k, latency 100 ms) with the same random loss in both
directions done by tc (multi_tc.py --loss: gact on the sender's egress filter
and on its ingress for the peer's datagrams) - no in-application drop.

Usage: cmp_round.py SENDER RECEIVER RATE_KBPS LOSS SEED PORTBASE [--dur S] [--anl VARIANT]
                    [--protos NAME,...] [--drive-check]
Hosts from ANL_REALNET_HOSTS (../hosts.py). --anl names the AnLiu variant
deployed with ../deploy.py (default main); srtnet is expected at
base/ANL_REALNET_REMOTE_DIR/srt/srtnet on both hosts (deploy_srt.py).
--protos picks the protocols run side by side (default anl,srt-b,srt-fec,srt-rec;
ports PORTBASE+0.. in that order); --drive-check drives AnLiu by anl_check
(REALNET_DRIVE=check) instead of 1 ms polling. Protocols:
  anl      realnet --proto anl, RTT-auto FEC, fixed video scale 1000 (no encoder feedback)
  anl-nf   the same with FEC off (--fec-rtt-auto 0): retransmission only
  anl-nf-aN  anl-nf with the audio receiver gap wait at N ms (--rcv-deadline-audio N)
  NAME@VARIANT  an AnLiu lane run from another deployed variant (e.g. anl-nf@cand)
  srt-b    SRT latency audio 120 / video 250 ms (the budgets 150 / 300 less margin)
  srt-fec  srt-b + packetfilter fec,cols:10,rows:5,layout:staircase,arq:onreq
  srt-rec  SRT latency max(120, 4 x RTT) for both (SRT's usual guidance)
Logs and per-band tc counters go to ANL_REALNET_WORK/results/<tag>.*; analysis: cmp_ana.py."""
import sys, os, re, json, time, subprocess, shlex, gzip, hashlib, pathlib
B = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(B.parent))
import hosts as H
HOSTS = H.load()
argv = sys.argv[1:]
dur = 600; anl_variant = 'main'
if '--dur' in argv:
    i = argv.index('--dur'); dur = int(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
if '--anl' in argv:
    i = argv.index('--anl'); anl_variant = argv[i + 1]; argv = argv[:i] + argv[i + 2:]
want = ['anl', 'srt-b', 'srt-fec', 'srt-rec']
if '--protos' in argv:
    i = argv.index('--protos'); want = argv[i + 1].split(','); argv = argv[:i] + argv[i + 2:]
drive_check = '--drive-check' in argv
argv = [a for a in argv if a != '--drive-check']
snd, rcv, rate, loss, seed, pbase = argv[0], argv[1], int(argv[2]), int(argv[3]), int(argv[4]), int(argv[5])
S, C = HOSTS[snd], HOSTS[rcv]
assert S['shape'], 'sender cannot shape'
q = shlex.quote
tag = f'cmp_{snd}{rcv}_{rate}_l{loss}_seed{seed}_{time.time_ns()}'
RES = H.WORK / 'results'; RES.mkdir(exist_ok=True)
SSH = ['ssh', '-x', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12', '-o', 'ServerAliveInterval=10',
       '-o', 'ControlMaster=auto', '-o', 'ControlPath=/tmp/anliu-cmp-%C', '-o', 'ControlPersist=900']


def ssh(h, cmd, check=True, timeout=120):
    for attempt in range(4):
        try:
            r = subprocess.run(SSH + [h['ssh'], cmd], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            if attempt == 3: raise
            time.sleep(10); continue
        if r.returncode == 255 and attempt < 3:
            time.sleep(10); continue
        if check and r.returncode: raise RuntimeError(f"{h['ssh']}: {cmd[:80]}: rc={r.returncode} {r.stderr.decode()[:300]}")
        return r
    raise RuntimeError('ssh retries exhausted')


CMP = lambda h: H.remote(h, 'srt')
lane_variant = lambda name: name.partition('@')[2] or anl_variant     # NAME@VARIANT: this lane's own variant
RN = lambda h, name: '$HOME/' + H.remote(h, lane_variant(name)) + '/src/bench/realnet_trace'
manifest = json.loads((H.WORK / anl_variant / 'deployment-manifest.json').read_text())
ping = None
meta = dict(tag=tag, sender=snd, receiver=rcv, rate_kbps=rate, loss_pct=loss, seed=seed, duration_s=dur,
            anliu_revision=manifest['revision'], srt='1.5.4 static, encryption off', loss_method='tc gact both directions on the sender',
            valid=False, protocols={})
bands = {}
procs = []
try:
    # the path's RTT for srt-rec
    for h, peer in ((C, S), (S, C)):          # ICMP is filtered one way on some paths
        out = ssh(h, f"ping -c 10 -i 0.2 -q {peer['ip']} | tail -1", check=False).stdout.decode()
        m = re.search(r'= ([\d.]+)/([\d.]+)/', out)
        ping = float(m.group(1)) if m else None
        if ping is not None: break
    if ping is None: raise RuntimeError('no ping: ' + out)
    meta['rtt_min_ms'] = ping
    rec_lat = max(120, int(4 * ping))
    known = dict([('anl', 1), ('anl-nf', 0), ('srt-b', (120, 250, '')), ('srt-fec', (120, 250, 'fec,cols:10,rows:5,layout:staircase,arq:onreq')),
                  ('srt-rec', (rec_lat, rec_lat, ''))])
    for n in want:
        base = n.partition('@')[0]
        if base.startswith('anl-nf-a'): known[n] = (0, int(base[8:]))
        elif '@' in n: known[n] = known[base]
    protos = [(n, known[n]) for n in want]
    meta['drive'] = 'check' if drive_check else 'poll1ms'
    subprocess.run(['scp', '-q', '-o', 'BatchMode=yes', str(B.parent / 'multi_tc.py'),
                    S['ssh'] + ':' + CMP(S) + '/multi_tc.py'], check=True, timeout=120)
    for k, (name, cfg) in enumerate(protos):
        port = pbase + k
        busy = ssh(S, f"ss -uan | grep -E '[:.]{port}[[:space:]]' || true").stdout.strip()
        if busy: raise RuntimeError(f'port {port} busy')
        state = CMP(S) + f'/mtc-state-{tag}-{name}.json'
        o = ssh(S, f"python3 {CMP(S)}/multi_tc.py setup --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --loss {loss} --state {state}").stdout.decode()
        band = int(o.split('band')[-1].split()[0])
        bands[name] = (port, band, state)
        ssh(S, f"nohup python3 {CMP(S)}/multi_tc.py deadman --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --loss {loss} --state {state} --hold {dur + 900} </dev/null > {CMP(S)}/logs/deadman_{port}.log 2>&1 &")
        meta['protocols'][name] = dict(port=port, band=band, cfg=cfg)
        if name.startswith('anl'):
            meta['protocols'][name]['revision'] = json.loads((H.WORK / lane_variant(name) / 'deployment-manifest.json').read_text())['revision']

    def start(h, name, role, cmd, env=''):
        rel = f"logs/{tag}.{name}.{role}"; log = f"{CMP(h)}/{rel}"
        ssh(h, f"cd $HOME/{CMP(h)} || exit 1; {env} setsid nohup {cmd} > {rel} 2>&1 < /dev/null & echo $! > $HOME/{log}.pid")
        procs.append((h, log))
        return log

    def anl_args(cfg):
        fec, rda = cfg if isinstance(cfg, tuple) else (cfg, None)
        return (f"--proto anl --test media --dir down --dur {dur} --interval 10 --loss 0 --rx-loss 0 --seed {seed} --rcv-deadline -1 "
                f"--init-cwnd 16 --fec-rtt-auto {fec} --adapt 0 --prio-audio 0 --prio-video 1"
                + (f" --rcv-deadline-audio {rda}" if rda is not None else ''))
    anl_env = 'REALNET_MDIAG=1 REALNET_TIMEBASE=1 REALNET_CLOCK=1 REALNET_FECCOST=1 REALNET_FIXED_SCALE=1000' + (' REALNET_DRIVE=check' if drive_check else '')
    logs = {}
    for name, cfg in protos:
        port = bands[name][0]
        if name.startswith('anl'):
            logs[name, 'srv'] = start(S, name, 'srv', f"{RN(S, name)} server --port {port} {anl_args(cfg)}", anl_env)
        else:
            logs[name, 'srv'] = start(S, name, 'srv', f"./srtnet server --port {port} --dur {dur} --seed {seed}")
    for _ in range(40):
        ready = ssh(S, ' && '.join(f"grep -q WORKLOAD_READY {logs[n, 'srv']}" for n, _ in protos) + ' && echo READY', check=False).stdout
        if b'READY' in ready: break
        time.sleep(1)
    else:
        raise RuntimeError('servers not ready')
    for name, cfg in protos:
        port = bands[name][0]
        if name.startswith('anl'):
            logs[name, 'cli'] = start(C, name, 'cli', f"{RN(C, name)} client --host {S['ip']} --port {port} {anl_args(cfg)}", anl_env)
        else:
            la, lv, fec = cfg
            logs[name, 'cli'] = start(C, name, 'cli', f"./srtnet client --host {S['ip']} --port {port} --lat-audio {la} --lat-video {lv} --dur {dur}"
                                      + (f" --fec {q(fec)}" if fec else ''))
    time.sleep(dur + 15)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        alive = [l for h, l in procs if ssh(h, f"kill -0 $(cat {l}.pid) 2>/dev/null && echo ALIVE", check=False).stdout.strip() == b'ALIVE']
        if not alive: break
        time.sleep(5)
    else:
        raise RuntimeError('processes still running: ' + str(alive))
    # tc counters of each band before clearing
    tcj = json.loads(ssh(S, f"sudo -n /usr/sbin/tc -s -j qdisc show dev {S['dev']}").stdout)
    for name, (port, band, state) in bands.items():
        qd = [x for x in tcj if x.get('handle') == f'{0x6b0 + band:x}:']
        meta['protocols'][name]['tc'] = {k: qd[0].get(k) for k in ('bytes', 'packets', 'drops', 'overlimits')} if qd else None
    for (name, role), log in logs.items():
        h = S if role == 'srv' else C
        data = gzip.decompress(ssh(h, 'gzip -c ' + q(log), timeout=300).stdout)
        (RES / f'{tag}.{name}.{role}').write_bytes(data)
        meta['protocols'][name][role + '_sha256'] = hashlib.sha256(data).hexdigest()
    meta['valid'] = True
except Exception as e:
    meta['errors'] = [str(e)]
    print('CMP_FAILURE', e, flush=True)
finally:
    for h, log in procs:
        ssh(h, f"kill $(cat {log}.pid) 2>/dev/null; true", check=False)
    for name, (port, band, state) in bands.items():
        try:
            o = ssh(S, f"python3 {CMP(S)}/multi_tc.py clear --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --loss {loss} --state {state}").stdout.decode()
            m = re.search(r'LOSS_STATS fwd_pkts (\d+) fwd_drop (\d+) rev_pkts (\d+) rev_drop (\d+)', o)
            if m: meta['protocols'][name]['loss_stats'] = dict(zip(('fwd_pkts', 'fwd_drop', 'rev_pkts', 'rev_drop'), map(int, m.groups())))
        except Exception as e:
            meta.setdefault('errors', []).append('clear ' + str(e)); meta['valid'] = False
    (RES / f'{tag}.json').write_text(json.dumps(meta, indent=1))
    print('CMP_DONE', tag, meta['valid'], flush=True)
