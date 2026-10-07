#!/usr/bin/env python3
"""Stream open/close churn on a real path (bench/churn.c): the close
handshake, the places it holds and what the peer reads, under tc loss/delay.

  churn_round.py deploy VARIANT REV HOST...
      package anliu.c / anliu.h from git REV ("WORKTREE": the working tree) and
      bench/churn.c from the working tree; build `churn` on the hosts
  churn_round.py run SERVER CLIENT VARIANT SEED PORT [--loss PCT] [--delay MS]
      [--conc N] [--dur S] [--rate KBPS]
      one round: the server (a host that can shape) gets its own multi_tc.py
      band - TBF at RATE (default 8000 kbit, a cap, not the bottleneck), random
      loss PCT in both directions, extra one-way delay MS - then both ends run
      churn for S seconds (default 600) with N own streams each (default 31)

Results: ANL_REALNET_WORK/results/<tag>.{json,srv,cli}. A round is valid when
both ends exit 0: HEALTH errors=0 ok=1 - no refused open, no integrity error,
every close confirmed and both connections back to the default stream alone."""
import sys, json, time, hashlib, re, tarfile, datetime, subprocess as sp, concurrent.futures as cf
import hosts as H
import rnlib as R

HERE = H.Path(__file__).resolve().parent
REPO = HERE.parents[1]
FILES = ['anliu.c', 'anliu.h', 'bench/churn.c']


def git_file(rev, path):
    if rev == 'WORKTREE' or path.startswith('bench/'): return (REPO / path).read_bytes()
    return sp.run(['git', '-C', str(REPO), 'show', f'{rev}:{path}'], capture_output=True, check=True).stdout


def deploy(variant, rev, names):
    hs = H.load()
    d = H.WORK / variant; src = d / 'src'
    (src / 'bench').mkdir(parents=True, exist_ok=True)
    for p in FILES: (src / p).write_bytes(git_file(rev, p))
    files = {p: hashlib.sha256((src / p).read_bytes()).hexdigest() for p in FILES}
    desc = 'working tree' if rev == 'WORKTREE' else sp.run(['git', '-C', str(REPO), 'log', '-1', '--format=%h %s', rev],
                                                            capture_output=True, text=True, check=True).stdout.strip()
    (d / 'deployment-manifest.json').write_text(json.dumps(dict(revision=desc, time=datetime.datetime.now().astimezone().isoformat(),
                                                                files=files), indent=2))
    with tarfile.open(d / 'src.tgz', 'w:gz') as t: t.add(src, arcname='.')

    def one(n):
        h = hs[n]; rd = H.remote(h, variant)
        R.ssh(h, f'mkdir -p {rd}/src {rd}/logs')
        R.upload(h, d / 'src.tgz', f'{rd}/src.tgz')
        out = R.ssh(h, f'cd {rd} && tar xzf src.tgz -C src && cd src/bench && gcc -std=gnu99 -O2 -I.. churn.c -lm -o churn && '
                       'python3 -c "import hashlib,sys;[print(hashlib.sha256(open(f,\'rb\').read()).hexdigest()) for f in sys.argv[1:]]" '
                       '../anliu.c churn.c', timeout=300).stdout.decode().split()
        ok = out[0] == files['anliu.c'] and out[1] == files['bench/churn.c']
        return f"{n}: {'ok' if ok else 'HASH MISMATCH'} {files['anliu.c'][:12]}"
    with cf.ThreadPoolExecutor(len(names)) as ex:
        for line in ex.map(one, names): print(line)


LAUNCHER = '''import subprocess,os,pathlib,signal
root=pathlib.Path.home()/REMOTEDIR
log=root/'logs'/LOGNAME
src=root/'src/bench'
with log.open('w') as f:
 child=subprocess.Popen([str(src/'churn'),*ARGLIST],cwd=src,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
 pathlib.Path(str(log)+'.bin.pid').write_text(str(child.pid))
 try:rc=child.wait(timeout=TIMEOUT)
 except subprocess.TimeoutExpired:
  os.killpg(child.pid,signal.SIGTERM)
  try:child.wait(timeout=3)
  except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL)
  rc=124
 pathlib.Path(str(log)+'.rc').write_text(str(rc)+'\\n')
'''
STOPPER = '''import pathlib,subprocess,os,signal,time
p=pathlib.Path.home()/PATHNAME
try:pid=int(pathlib.Path(str(p)+'.bin.pid').read_text())
except (FileNotFoundError,ValueError):raise SystemExit(0)
def owned():
 r=subprocess.run(['ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
 return r.returncode==0 and BINARY in r.stdout
if owned():
 os.killpg(pid,signal.SIGTERM);time.sleep(.5)
 if owned():os.killpg(pid,signal.SIGKILL)
'''


def parse(text):
    """the CHURN / HEALTH lines of one end as dicts"""
    out = {}
    for line in text.splitlines():
        m = re.match(r'^(CHURN_\w+|HEALTH|DEAD)\b(.*)$', line)
        if not m: continue
        key = m[1]
        v = {k: (int(x) if re.fullmatch(r'-?\d+', x) else x) for k, x in re.findall(r'(\w+)=(\S+)', m[2])}
        if key == 'CHURN_CONFIRM': key += '_' + v.get('by', '')
        out[key] = v if v else m[2].strip()
    return out


def run(argv):
    def opt(name, default):
        if name not in argv: return default
        i = argv.index(name); v = int(argv[i + 1]); del argv[i:i + 2]; return v
    loss = opt('--loss', 0); delay = opt('--delay', 0); conc = opt('--conc', 31); dur = opt('--dur', 600); rate = opt('--rate', 8000)
    if not 0 <= loss <= 20 or not 0 <= delay <= 300 or not 1 <= conc <= 31: raise SystemExit('loss 0..20, delay 0..300, conc 1..31')
    snd, rcv, variant, seed, port = argv[0], argv[1], argv[2], int(argv[3]), int(argv[4])
    hs = H.load(); S, C = hs[snd], hs[rcv]
    if not S['shape']: raise SystemExit('server cannot shape')
    RS, RC = H.remote(S, variant), H.remote(C, variant)
    manifest = json.loads((H.WORK / variant / 'deployment-manifest.json').read_text())
    tag = f'churn_{variant}_{snd}{rcv}_l{loss}' + (f'_d{delay}' if delay else '') + f'_c{conc}_seed{seed}_{time.time_ns()}'
    RES = H.WORK / 'results'; RES.mkdir(exist_ok=True)
    meta = dict(tag=tag, server=snd, client=rcv, variant=variant, revision=manifest['revision'], loss_pct=loss, extra_delay_ms=delay,
                conc=conc, duration_s=dur, rate_kbps=rate, seed=seed, port=port, valid=False)
    state = f'{RS}/mtc-state-{tag}.json'
    tcbase = f'python3 {RS}/multi_tc.py'
    tcargs = (f" --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --state {state} --hold {dur + 400}"
              + (f' --loss {loss}' if loss else '') + (f' --delay {delay}' if delay else ''))
    scripts = []; started = False

    def launch(h, rd, role):
        path = f"{rd}/logs/{tag}.{'srv' if role == 'server' else 'cli'}"
        args = [role, '--port', str(port), '--dur', str(dur), '--conc', str(conc), '--seed', str(seed)]
        if role == 'client': args += ['--host', S['ip']]
        code = (LAUNCHER.replace('REMOTEDIR', repr(rd)).replace('LOGNAME', repr(path.rsplit('/', 1)[1]))
                .replace('ARGLIST', repr(args)).replace('TIMEOUT', str(dur + 150)))
        scripts.append((h, rd, path))
        R.ssh(h, f'mkdir -p {rd}/logs && printf %s {R.q(code)} > {R.q(path + ".py")} || exit; '
                 f'nohup python3 {R.q(path + ".py")} </dev/null > {R.q(path + ".outer")} 2>&1 & echo launched')

    try:
        for h, rd in ((S, RS), (C, RC)):
            if h is S and R.ssh(h, f"(ss -uan 2>/dev/null || netstat -an -p udp) | grep -E '[:.]{port}[[:space:]]' || true").stdout.strip():
                raise RuntimeError(f"{h['name']} port {port} busy")
            got = R.ssh(h, f'cd {rd}/src && python3 -c "import hashlib,sys;[print(hashlib.sha256(open(f,\'rb\').read()).hexdigest()) for f in sys.argv[1:]]" '
                           + ' '.join(FILES)).stdout.decode().split()
            if got != [manifest['files'][f] for f in FILES]: raise RuntimeError(f"{h['name']} source mismatch")
        R.upload(S, HERE / 'multi_tc.py', f'{RS}/multi_tc.py')
        started = True
        out = R.ssh(S, tcbase + ' setup' + tcargs).stdout.decode()
        meta['tc_band'] = int(out.split('band')[-1].split()[0])
        R.ssh(S, f'nohup {tcbase} deadman{tcargs} </dev/null > {RS}/deadman_{port}.log 2>&1 &')
        R.save_meta(RES / f'{tag}.json', meta); R.event('churn_start', tag=tag, variant=variant, loss=loss, delay=delay, conc=conc, port=port)
        launch(S, RS, 'server')
        srv = f'{RS}/logs/{tag}.srv'
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if R.ssh(S, f'grep -q WORKLOAD_READY {srv} 2>/dev/null && echo READY', check=False).stdout.strip() == b'READY': break
            time.sleep(1)
        else:
            raise RuntimeError('server not ready')
        launch(C, RC, 'client')
        deadline = time.monotonic() + dur + 240; rc = {}
        time.sleep(min(dur, 60))
        while time.monotonic() < deadline:
            for h, rd, path in scripts:
                if h['name'] not in rc:
                    o = R.ssh(h, 'cat ' + R.q(path + '.rc') + ' 2>/dev/null', check=False)
                    if o.returncode == 0 and o.stdout.strip(): rc[h['name']] = int(o.stdout)
            if len(rc) == 2: break
            time.sleep(10)
        meta['rc'] = rc
        logs = {}
        for h, rd, path in scripts:
            ext = path.rsplit('.', 1)[1]
            data = R.fetch(h, path)
            (RES / f'{tag}.{ext}').write_bytes(data)
            logs[ext] = data.decode(errors='replace')
        meta['srv'] = parse(logs.get('srv', '')); meta['cli'] = parse(logs.get('cli', ''))
        errors = []
        if len(rc) != 2 or any(rc.values()): errors.append('exit ' + str(rc))
        for end in ('srv', 'cli'):
            hl = meta[end].get('HEALTH', {})
            if not isinstance(hl, dict) or hl.get('errors') != 0 or hl.get('ok') != 1 or hl.get('state') != 0:
                errors.append(f'{end} HEALTH {hl}')
        if errors: raise RuntimeError('; '.join(errors))
        meta['valid'] = True
    except Exception as e:
        meta.setdefault('errors', []).append(str(e))
    finally:
        for h, rd, path in scripts:
            code = STOPPER.replace('PATHNAME', repr(path)).replace('BINARY', repr(f'{rd}/src/bench/churn'))
            try: R.ssh(h, 'python3 -c ' + R.q(code), check=False)
            except Exception as e: meta.setdefault('errors', []).append('owned stop ' + str(e)); meta['valid'] = False
        if started:
            try:
                out = R.ssh(S, tcbase + ' clear' + tcargs).stdout.decode()
                m = re.search(r'LOSS_STATS fwd_pkts (\d+) fwd_drop (\d+) rev_pkts (\d+) rev_drop (\d+)', out)
                if m:
                    fp, fd, rp, rdp = map(int, m.groups())
                    meta['tc_loss'] = dict(fwd_pkts=fp, fwd_drop=fd, rev_pkts=rp, rev_drop=rdp,
                                           fwd_pct=round(100 * fd / max(1, fp), 3), rev_pct=round(100 * rdp / max(1, rp), 3))
            except Exception as e: meta.setdefault('errors', []).append('cleanup ' + str(e)); meta['valid'] = False
            if loss and meta.get('tc_loss', {}).get('fwd_pkts', 0) == 0:
                # the filter matches the peer's address in the host table: behind NAT
                # the datagrams come from another one, and no loss was applied
                meta.setdefault('errors', []).append('tc band matched no packets: no loss applied'); meta['valid'] = False
        R.save_meta(RES / f'{tag}.json', meta)
        print('CHURN_DONE', tag, meta['valid'], '; '.join(meta.get('errors', [])), flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'deploy': deploy(sys.argv[2], sys.argv[3], sys.argv[4:])
    elif len(sys.argv) > 1 and sys.argv[1] == 'run': run(sys.argv[2:])
    else: raise SystemExit(__doc__)
