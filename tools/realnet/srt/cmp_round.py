#!/usr/bin/env python3
"""One comparison round: AnLiu (realnet, current main) and SRT (srtnet) side by
side on one path at the same time, each in its own tc band on the sender
(TBF RATE, burst 16k, latency 100 ms) with the same random loss in both
directions done by tc (multi_tc.py --loss: gact on the sender's egress filter
and on its ingress for the peer's datagrams) - no in-application drop.

Usage: cmp_round.py SENDER RECEIVER RATE_KBPS LOSS SEED PORTBASE [--dur S] [--anl VARIANT]
                    [--protos NAME,...] [--drive-check] [--delay MS] [--video-scale N] [--start-rate KBPS]
Hosts from ANL_REALNET_HOSTS (../hosts.py). --anl names the AnLiu variant
deployed with ../deploy.py (default main); srtnet is expected at
base/ANL_REALNET_REMOTE_DIR/srt/srtnet on both hosts (deploy_srt.py).
--protos picks the protocols run side by side (default anl,srt-b,srt-fec,srt-rec;
ports PORTBASE+0.. in that order); --drive-check drives AnLiu by anl_check
(REALNET_DRIVE=check) instead of 1 ms polling; --delay adds MS of one-way
delay (tc netem under each band's TBF, sender to receiver: the RTT grows by
MS). Protocols:
  anl      realnet --proto anl, RTT-auto FEC, fixed video scale 1000 (no encoder feedback)
  anl-nf   the same with FEC off (--fec-rtt-auto 0): retransmission only
  anl-nf-aN  anl-nf with the audio receiver gap wait at N ms (--rcv-deadline-audio N)
  anl-aNvM, anl-nf-aNvM  anl / anl-nf with the receiver gap wait at N ms for audio and M ms
           for video (--rcv-deadline-audio N --rcv-deadline-video M): a hole is given up
           near the playout budget, as SRT's latency does, instead of at max_age
  NAME@VARIANT  an AnLiu lane run from another deployed variant (e.g. anl-nf@cand)
  srt-b    SRT latency audio 120 / video 250 ms (the budgets 150 / 300 less margin)
  srt-fec  srt-b + packetfilter fec,cols:10,rows:5,layout:staircase,arq:onreq
  srt-rec  SRT latency max(120, 4 x RTT) for both (SRT's usual guidance)
  anl-ref  AnLiu audio only (64 kbps, FEC off): the one-way delay base of a round whose other
           lanes are SRT (cmp_ana takes the base from AnLiu audio); not a compared lane
--video-scale N runs the video of every lane at N per mille of the nominal ~940 kbit/s
(realnet REALNET_FIXED_SCALE, srtnet --scale; 21277 is ~20 Mbit/s); above 4000 the AnLiu
video stream gets a 4096-segment window (REALNET_VIDEO_WND) so that a key frame fits.
--start-rate KBPS sets anl_config.start_rate of the AnLiu lanes (VIDEO_GUIDE: 1.5..2 x the media
rate, at most a known bottleneck); default off, as the library.
With --budgets A,V (V a number, "rec" = max(120, 4 x RTT), or "rec+N" = that plus N ms - e.g. the
send time of a large key frame) the round is scored at
A / V ms plus BUDGET_TOL (SRT delivers a few ms after its latency) instead of 150 / 300,
and three more lanes exist:
  srt-r    SRT latency A for audio, V for video
  anl-nf-g AnLiu FEC off set up for the budgets as VIDEO_GUIDE.md says: max_age A + 50 /
           V + 200, receiver gap wait A - 20 / V - 50
  anl-nf-d the same max_age, the gap wait left at its default
  anl-d    anl-nf-d with RTT-auto FEC
Logs and per-band tc counters go to ANL_REALNET_WORK/results/<tag>.*; analysis: cmp_ana.py."""
import sys, os, re, json, time, subprocess, shlex, gzip, hashlib, pathlib
from cmp_checks import recommended_latency, validate_lane
B = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(B.parent))
import hosts as H
import rnlib as R
HOSTS = H.load()
argv = sys.argv[1:]
dur = 600; anl_variant = 'main'; delay = 0
start_rate = 0
if '--start-rate' in argv:
    i = argv.index('--start-rate'); start_rate = int(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
video_scale = 1000
if '--video-scale' in argv:
    i = argv.index('--video-scale'); video_scale = int(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
    if not 1 <= video_scale <= 40000: raise SystemExit('video-scale 1..40000')
if '--delay' in argv:
    i = argv.index('--delay'); delay = int(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
if '--dur' in argv:
    i = argv.index('--dur'); dur = int(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
if '--anl' in argv:
    i = argv.index('--anl'); anl_variant = argv[i + 1]; argv = argv[:i] + argv[i + 2:]
want = ['anl', 'srt-b', 'srt-fec', 'srt-rec']
if '--protos' in argv:
    i = argv.index('--protos'); want = argv[i + 1].split(','); argv = argv[:i] + argv[i + 2:]
budgets = None
if '--budgets' in argv:
    i = argv.index('--budgets'); budgets = argv[i + 1].split(','); argv = argv[:i] + argv[i + 2:]
    if len(budgets) != 2: raise SystemExit('--budgets AUDIO_MS,VIDEO_MS|rec')
BUDGET_TOL = 10
drive_check = '--drive-check' in argv
argv = [a for a in argv if a != '--drive-check']
snd, rcv, rate, loss, seed, pbase = argv[0], argv[1], int(argv[2]), int(argv[3]), int(argv[4]), int(argv[5])
S, C = HOSTS[snd], HOSTS[rcv]
assert S['shape'], 'sender cannot shape'
q = shlex.quote
tag = f'cmp_{snd}{rcv}_{rate}_l{loss}' + (f'_vs{video_scale}' if video_scale != 1000 else '') + (f'_sr{start_rate}' if start_rate else '') + f'_seed{seed}_{time.time_ns()}'
RES = H.WORK / 'results'; RES.mkdir(exist_ok=True)
SSH = ['ssh', '-x', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12', '-o', 'ServerAliveInterval=10',
       # one control master per lane (port base): two lanes racing to create the same master
       # stalled an ssh for 30 s, long enough for a waiting AnLiu server to die of idleness
       '-o', 'ControlMaster=auto', '-o', f'ControlPath=/tmp/anliu-cmp-%C-{pbase}', '-o', 'ControlPersist=900']


# once the clients are started the round runs on the hosts without us (each band's deadman counts and
# clears it when its server exits): a lost connection on our side is then waited out until patient_until
patient_until = 0.0


def ssh(h, cmd, check=True, timeout=120):
    attempt = 0
    while True:
        try:
            r = subprocess.run(SSH + [h['ssh'], cmd], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            r = None
        if r is not None and r.returncode != 255: break
        attempt += 1
        if attempt >= 4 and time.monotonic() >= patient_until:
            if r is None: raise subprocess.TimeoutExpired(cmd, timeout)
            break
        time.sleep(10 if attempt < 4 else 30)
    if check and r.returncode: raise RuntimeError(f"{h['ssh']}: {cmd[:80]}: rc={r.returncode} {r.stderr.decode()[:300]}")
    return r


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
finished = set()


def tc_finish(name):
    """a band's counters and release: its deadman's clear output, or a clear run now"""
    port, band, state = bands[name]
    o = ssh(S, f"cat {CMP(S)}/logs/{tag}.{name}.deadman 2>/dev/null", check=False).stdout.decode(errors='replace')
    if 'CLEARED' not in o:
        o = ssh(S, f"python3 {CMP(S)}/multi_tc.py clear --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --loss {loss} --state {state}").stdout.decode()
    finished.add(name)
    m = re.search(r'LOSS_STATS fwd_pkts (\d+) fwd_drop (\d+) rev_pkts (\d+) rev_drop (\d+)', o)
    if m: meta['protocols'][name]['loss_stats'] = dict(zip(('fwd_pkts', 'fwd_drop', 'rev_pkts', 'rev_drop'), map(int, m.groups())))
    m = re.search(r'QDISC_STATS (\{.*\})', o)
    if m: meta['protocols'][name]['tc'] = json.loads(m.group(1))


try:
    # the path's RTT for srt-rec
    for h, peer in ((C, S), (S, C)):          # ICMP is filtered one way on some paths
        out = ssh(h, f"ping -c 10 -i 0.2 -q {peer['ip']} | tail -1", check=False).stdout.decode()
        m = re.search(r'= ([\d.]+)/([\d.]+)/', out)
        ping = float(m.group(1)) if m else None
        if ping is not None: break
    if ping is None: raise RuntimeError('no ping: ' + out)
    meta['rtt_min_ms'] = ping
    rec_lat = recommended_latency(ping, delay)
    meta['effective_rtt_ms'] = ping + delay
    meta['validation_version'] = 1
    known = dict([('anl', 1), ('anl-nf', 0), ('anl-ref', 0), ('srt-b', (120, 250, '')), ('srt-fec', (120, 250, 'fec,cols:10,rows:5,layout:staircase,arq:onreq')),
                  ('srt-rec', (rec_lat, rec_lat, ''))])
    if budgets:
        ba = int(budgets[0])
        bv = rec_lat + int(budgets[1][4:]) if budgets[1].startswith('rec+') else rec_lat if budgets[1] == 'rec' else int(budgets[1])
        meta['latency_ms'] = {'audio': ba, 'video': bv}
        meta['budget_ms'] = {'1': ba + BUDGET_TOL, '2': bv + BUDGET_TOL}     # the scoring budgets (cmp_ana)
        known['srt-r'] = (ba, bv, '')
        known['anl-nf-g'] = dict(fec=0, rda=max(ba - 20, 1), rdv=max(bv - 50, 1), ama=ba + 50, vma=bv + 200)
        known['anl-nf-d'] = dict(fec=0, ama=ba + 50, vma=bv + 200)
        known['anl-d'] = dict(fec=1, ama=ba + 50, vma=bv + 200)
    for n in want:
        base = n.partition('@')[0]
        if base in ('srt-r', 'anl-nf-g', 'anl-nf-d', 'anl-d') and not budgets: raise SystemExit(f'{base} needs --budgets')
        g = re.fullmatch(r'(anl|anl-nf)-a(\d+)(?:v(\d+))?', base)
        if g: known[n] = (0 if g[1] == 'anl-nf' else 1, int(g[2]), int(g[3]) if g[3] else None)
        elif '@' in n: known[n] = known[base]
    protos = [(n, known[n]) for n in want]
    meta['drive'] = 'check' if drive_check else 'poll1ms'
    meta['delay_ms'] = delay
    meta['video_scale'] = video_scale
    meta['start_rate_kbps'] = start_rate
    # over the ssh master connection, retried (a public sshd drops some new logins)
    R.upload(S, B.parent / 'multi_tc.py', CMP(S) + '/multi_tc.py')
    for k, (name, cfg) in enumerate(protos):
        port = pbase + k
        busy = ssh(S, f"ss -uan | grep -E '[:.]{port}[[:space:]]' || true").stdout.strip()
        if busy: raise RuntimeError(f'port {port} busy')
        state = CMP(S) + f'/mtc-state-{tag}-{name}.json'
        o = ssh(S, f"python3 {CMP(S)}/multi_tc.py setup --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --loss {loss} --delay {delay} --state {state}").stdout.decode()
        band = int(o.split('band')[-1].split()[0])
        bands[name] = (port, band, state)
        ssh(S, f"nohup python3 {CMP(S)}/multi_tc.py deadman --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --loss {loss} --state {state} --hold {dur + 2700}"
               f" --done {CMP(S)}/logs/{tag}.{name}.srv.rc </dev/null > {CMP(S)}/logs/{tag}.{name}.deadman 2>&1 &")
        meta['protocols'][name] = dict(port=port, band=band, cfg=cfg)
        if name.startswith('anl'):
            meta['protocols'][name]['revision'] = json.loads((H.WORK / lane_variant(name) / 'deployment-manifest.json').read_text())['revision']

    def start(h, name, role, cmd, env=''):
        rel = f"logs/{tag}.{name}.{role}"; log = f"{CMP(h)}/{rel}"
        # The detached shell records the child's exit, including a crash. Its
        # process group is retained for cleanup if the command does not finish.
        # timeout: the process ends on the host even if we never come back to stop it; the .rc
        # file tells the band's deadman that the server is done
        wrapped = (f'cmp_begin=$(date +%s); timeout --foreground -k 10 {dur + 300} ' + cmd + '; cmp_rc=$?; '
                   'cmp_end=$(date +%s); '
                   'printf "CMP_EXIT rc=%s elapsed_s=%s\\n" "$cmp_rc" "$((cmp_end-cmp_begin))"; '
                   f'echo "$cmp_rc" > {rel}.rc; '
                   'exit "$cmp_rc"')
        ssh(h, f"cd $HOME/{CMP(h)} || exit 1; {env} setsid nohup sh -c {q(wrapped)} > {rel} 2>&1 < /dev/null & echo $! > $HOME/{log}.pid")
        procs.append((h, log))
        return log

    def anl_args(cfg):
        if isinstance(cfg, dict): fec, rda, rdv = cfg['fec'], cfg.get('rda'), cfg.get('rdv')
        else: fec, rda, rdv = cfg if isinstance(cfg, tuple) else (cfg, None, None)
        return (f"--proto anl --test media --dir down --dur {dur} --interval 10 --loss 0 --rx-loss 0 --seed {seed} --rcv-deadline -1 "
                f"--init-cwnd 16 --fec-rtt-auto {fec} --adapt 0 --prio-audio 0 --prio-video 1"
                + (f" --rcv-deadline-audio {rda}" if rda is not None else '')
                + (f" --rcv-deadline-video {rdv}" if rdv is not None else '')
                + (f" --start-rate {start_rate * 125}" if start_rate else ''))
    anl_env = 'REALNET_MDIAG=1 REALNET_TIMEBASE=1 REALNET_CLOCK=1 REALNET_FECCOST=1' + (' REALNET_DRIVE=check' if drive_check else '')
    def lane_env(cfg, name):
        e = anl_env + (f" REALNET_AUDIO_MAX_AGE={cfg['ama']} REALNET_VIDEO_MAX_AGE={cfg['vma']}" if isinstance(cfg, dict) else '')
        if name.partition('@')[0] == 'anl-ref': return e + ' REALNET_FIXED_SCALE=1000 REALNET_AUDIO_ONLY=1'
        return e + f' REALNET_FIXED_SCALE={video_scale}' + (' REALNET_VIDEO_WND=4096' if video_scale > 4000 else '')
    logs = {}
    for name, cfg in protos:
        port = bands[name][0]
        if name.startswith('anl'):
            logs[name, 'srv'] = start(S, name, 'srv', f"{RN(S, name)} server --port {port} {anl_args(cfg)}", lane_env(cfg, name))
        else:
            logs[name, 'srv'] = start(S, name, 'srv', f"./srtnet server --port {port} --dur {dur} --seed {seed} --scale {video_scale}")
    for _ in range(40):
        ready = ssh(S, ' && '.join(f"grep -q WORKLOAD_READY {logs[n, 'srv']}" for n, _ in protos) + ' && echo READY', check=False).stdout
        if b'READY' in ready: break
        time.sleep(1)
    else:
        raise RuntimeError('servers not ready')
    for name, cfg in protos:
        port = bands[name][0]
        if name.startswith('anl'):
            logs[name, 'cli'] = start(C, name, 'cli', f"{RN(C, name)} client --host {S['ip']} --port {port} {anl_args(cfg)}", lane_env(cfg, name))
        else:
            la, lv, fec = cfg
            logs[name, 'cli'] = start(C, name, 'cli', f"./srtnet client --host {S['ip']} --port {port} --lat-audio {la} --lat-video {lv} --dur {dur}"
                                      + (f" --fec {q(fec)}" if fec else ''))
    patient_until = time.monotonic() + dur + 3600
    time.sleep(dur + 15)
    deadline = time.monotonic() + 120
    while True:
        # an unreachable host blocks in ssh() until it answers: the deadline only fails a process seen running
        alive = [l for h, l in procs if ssh(h, f"kill -0 $(cat {l}.pid) 2>/dev/null && echo ALIVE", check=False).stdout.strip() == b'ALIVE']
        if not alive: break
        if time.monotonic() > deadline: raise RuntimeError('processes still running: ' + str(alive))
        time.sleep(5)
    # each band's TBF and loss counters, from its deadman's clear (or a clear now if it has not run)
    for name in bands: tc_finish(name)
    for name in bands:
        if (meta['protocols'][name].get('tc') or {}).get('bytes') is None:
            raise RuntimeError(f'{name}: missing tc byte counter')
    fetched = {}
    for (name, role), log in logs.items():
        h = S if role == 'srv' else C
        data = gzip.decompress(ssh(h, 'gzip -c ' + q(log), timeout=300).stdout)
        (RES / f'{tag}.{name}.{role}').write_bytes(data)
        fetched[name, role] = data.decode(errors='replace')
        meta['protocols'][name][role + '_sha256'] = hashlib.sha256(data).hexdigest()
    for name, _ in protos:
        errors = validate_lane(name, dur, fetched[name, 'srv'], fetched[name, 'cli'])
        if errors:
            raise RuntimeError(f'{name}: ' + '; '.join(errors))
    meta['valid'] = True
except Exception as e:
    meta['errors'] = [str(e)]
    print('CMP_FAILURE', e, flush=True)
finally:
    for h, log in procs:
        try:
            ssh(h, f"kill -- -$(cat {log}.pid) 2>/dev/null; true", check=False)
        except Exception as e:
            meta.setdefault('errors', []).append('stop ' + str(e)); meta['valid'] = False
    for name in bands:
        if name in finished: continue
        try: tc_finish(name)
        except Exception as e:
            meta.setdefault('errors', []).append('clear ' + str(e)); meta['valid'] = False
    (RES / f'{tag}.json').write_text(json.dumps(meta, indent=1))
    print('CMP_DONE', tag, meta['valid'], flush=True)
