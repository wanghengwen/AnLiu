#!/usr/bin/env python3
"""One 600 s media round between two test hosts; several can run at once.

Usage: multi_round.py SENDER RECEIVER VARIANT SEED RATE_KBPS PORT [FIXED_SCALE]
         [--loss PCT]        receive-side random loss at both ends (realnet --rx-loss), default 20
         [--unlimited]       a 1 Gbit TBF band only counts the sender's bytes; RATE_KBPS ignored
         [--delay MS]        extra one-way delay on the sender (netem under the TBF)
         [--burst BYTES]     TBF bucket (default 16 KB); ~3200 makes it a FIFO at the rate
         [--audio-only] [--audio-max-age MS] [--video-max PERMILLE]
         [--drive-check]     the endpoints drive anl_update from anl_check, as an application does

Hosts come from ANL_REALNET_HOSTS (hosts.py). The sender is the server (UDP
PORT, its own multi_tc.py band), the receiver the client. VARIANT is a
directory under ANL_REALNET_WORK made by deploy.py; results go to
ANL_REALNET_WORK/results/<tag>.{json,srv,cli,bw}."""
import sys, json, time, hashlib
import hosts as H
import rnlib as R

HERE = H.Path(__file__).resolve().parent
argv = sys.argv[1:]


def opt(name, conv=int, default=0):
    global argv
    if name not in argv:
        return default
    i = argv.index(name); v = conv(argv[i + 1]); argv = argv[:i] + argv[i + 2:]
    return v


def flag(name):
    global argv
    if name not in argv:
        return False
    argv.remove(name)
    return True


loss = opt('--loss', default=20)
delay = opt('--delay'); burst = opt('--burst'); video_max = opt('--video-max'); audio_max_age = opt('--audio-max-age')
unlimited = flag('--unlimited'); audio_only = flag('--audio-only'); drive_check = flag('--drive-check')
if not 0 <= loss <= 20: raise SystemExit('loss 0..20')
if not 0 <= delay <= 200: raise SystemExit('delay 0..200')
if burst and not 1600 <= burst <= 65536: raise SystemExit('burst 1600..65536 bytes')
if video_max and not 1000 <= video_max <= 20000: raise SystemExit('video-max 1000..20000')
snd, rcv, variant, seed, rate, port = argv[0], argv[1], argv[2], int(argv[3]), int(argv[4]), int(argv[5])
fixed = int(argv[6]) if len(argv) > 6 else 0
if unlimited: rate = 1000000
HOSTS = H.load()
S, C = HOSTS[snd], HOSTS[rcv]
if not S['shape']: raise SystemExit('sender cannot shape')
RS, RC = H.remote(S, variant), H.remote(C, variant)
LOCAL = H.WORK / variant
kind = 'unl' if unlimited else 'multi'
tag = (f'{variant}_{kind}_{snd}{rcv}_{rate}_l{loss}' + (f'_am{audio_max_age}' if audio_max_age else '') + (f'_d{delay}' if delay else '')
       + ('_ao' if audio_only else '') + (f'_vm{video_max}' if video_max else '') + (f'_b{burst}' if burst else '')
       + ('_chk' if drive_check else '') + f'_seed{seed}' + (f'_fx{fixed}' if fixed else '') + f'_{time.time_ns()}')
RES = H.WORK / 'results'; RES.mkdir(exist_ok=True)
manifest = json.loads((LOCAL / 'deployment-manifest.json').read_text())
meta = dict(tag=tag, sender=snd, receiver=rcv, server=snd, client=rcv, direction='down', rate_kbps=rate, loss_pct=loss,
            unlimited=unlimited, audio_max_age=audio_max_age or 200, extra_delay_ms=delay, audio_only=audio_only,
            video_max=video_max or 1000, tbf_burst=burst or 16384, drive='check' if drive_check else 'poll1ms',
            workload='media', duration_s=R.DUR, seed=seed, revision=manifest['revision'], variant=variant,
            fixed_scale=fixed, port=port, valid=False)
state = f'{RS}/mtc-state-{tag}.json'
tcbase = f'python3 {RS}/multi_tc.py'
tcargs = (f" --dev {S['dev']} --peer {C['ip']} --port {port} --rate {rate} --state {state}"
          + (f' --delay {delay}' if delay else '') + (f' --burst {burst}' if burst else ''))
env = {'REALNET_MDIAG': '1', 'REALNET_TIMEBASE': '1', 'REALNET_CLOCK': '1', 'REALNET_RATE': '1', 'REALNET_FECCOST': '1',
       'REALNET_TRACE': '1000'}
if fixed: env['REALNET_FIXED_SCALE'] = str(fixed)
if audio_max_age: env['REALNET_AUDIO_MAX_AGE'] = str(audio_max_age)
if audio_only: env['REALNET_AUDIO_ONLY'] = '1'
if video_max: env['REALNET_VIDEO_MAX'] = str(video_max)
if drive_check: env['REALNET_DRIVE'] = 'check'
# runs on the host: hashes of the sources first, then realnet_trace, its pid and exit code
LAUNCHER = '''import subprocess,os,pathlib,hashlib,signal
root=pathlib.Path.home()/REMOTEDIR
log=root/'logs'/LOGNAME
src=root/'src/bench'
with log.open('w') as f:
 for name,label in [('anliu.c','../anliu.c'),('anliu.h','../anliu.h'),('bench/realnet.c','realnet.c')]:
  f.write(hashlib.sha256((root/'src'/name).read_bytes()).hexdigest()+'  '+label+'\\n')
 f.flush()
 env=os.environ.copy();env.update(ENVIRON)
 child=subprocess.Popen([str(src/'realnet_trace'),*ARGLIST],cwd=src,stdout=f,stderr=subprocess.STDOUT,env=env,start_new_session=True)
 pathlib.Path(str(log)+'.bin.pid').write_text(str(child.pid))
 try:rc=child.wait(timeout=760)
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
scripts = []; started = False


def launch(h, rd, role):
    path = f"{rd}/logs/{tag}.{'srv' if role == 'server' else 'cli'}"
    args = [role, '--port', str(port), '--proto', 'anl', '--test', 'media', '--dir', 'down', '--dur', str(R.DUR),
            '--interval', '10', '--loss', '0', '--rx-loss', str(loss), '--seed', str(seed), '--rcv-deadline', '-1',
            '--init-cwnd', '16', '--fec-rtt-auto', '1', '--adapt', '0' if fixed else '1', '--prio-audio', '0', '--prio-video', '1']
    if role == 'client': args += ['--host', S['ip']]
    code = (LAUNCHER.replace('REMOTEDIR', repr(rd)).replace('LOGNAME', repr(path.rsplit('/', 1)[1]))
            .replace('ENVIRON', repr(env)).replace('ARGLIST', repr(args)))
    scripts.append((h, rd, path))
    R.ssh(h, f'mkdir -p {rd}/logs && printf %s {R.q(code)} > {R.q(path + ".py")} || exit; '
             f'nohup python3 {R.q(path + ".py")} </dev/null > {R.q(path + ".outer")} 2>&1 & echo launched')


def fetch(h, path, ext):
    data = R.fetch(h, path)
    (RES / f'{tag}.{ext}').write_bytes(data)
    return data.decode(), hashlib.sha256(data).hexdigest()


try:
    for h, rd in ((S, RS), (C, RC)):
        busy = R.ssh(h, f"(ss -uan 2>/dev/null || netstat -an -p udp) | grep -E '[:.]{port}[[:space:]]' || true").stdout.strip()
        if h is S and busy: raise RuntimeError(f"{h['name']} port {port} busy")
        check = 'python3 -c ' + R.q('import pathlib,hashlib,json; b=pathlib.Path.home()/' + repr(rd + '/src') +
                                    '; print(json.dumps({str(p.relative_to(b)):hashlib.sha256(p.read_bytes()).hexdigest() '
                                    'for p in b.rglob("*") if p.is_file() and p.name!="realnet_trace"}))')
        actual = json.loads(R.ssh(h, check).stdout)
        for name, digest in manifest['files'].items():
            if actual.get(name) != digest: raise RuntimeError(f"{h['name']} source mismatch {name}")
    R.upload(S, HERE / 'multi_tc.py', f'{RS}/multi_tc.py')
    R.upload(S, HERE / 'sample_bandwidth.py', f'{RS}/sample_bandwidth.py')
    # cleared in any case: a setup that failed after it registered its band left the band
    # (and its filter, ahead of later rounds' on the same port and peer) behind
    started = True
    out = R.ssh(S, tcbase + ' setup' + tcargs).stdout.decode()
    band = int(out.split('band')[-1].split()[0]); meta['tc_band'] = band
    R.ssh(S, f'nohup {tcbase} deadman{tcargs} </dev/null > {RS}/deadman_{port}.log 2>&1 &')
    R.save_meta(RES / f'{tag}.json', meta); R.event('multi_start', tag=tag, variant=variant, rate=rate, seed=seed, port=port)
    launch(S, RS, 'server')
    srv = f'{RS}/logs/{tag}.srv'
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if R.ssh(S, f'grep -q WORKLOAD_READY {srv} 2>/dev/null && echo READY', check=False).stdout.strip() == b'READY': break
        time.sleep(1)
    else:
        raise RuntimeError('server not ready')
    bw = f'{RS}/logs/{tag}.bw'
    R.ssh(S, f"nohup python3 {RS}/sample_bandwidth.py {srv} {R.DUR} {S['dev']} {0x6b0 + band:x}: > {bw} 2> {bw}.err </dev/null &")
    launch(C, RC, 'client')
    deadline = time.monotonic() + R.DUR + 180; rc = {}
    while time.monotonic() < deadline:
        for h, rd, path in scripts:
            if h['name'] not in rc:
                o = R.ssh(h, 'cat ' + R.q(path + '.rc') + ' 2>/dev/null', check=False)
                if o.returncode == 0: rc[h['name']] = int(o.stdout)
        if len(rc) == 2: break
        time.sleep(10)
    if len(rc) != 2 or any(rc.values()): raise RuntimeError('round exit failure ' + str(rc))
    s, sh = fetch(S, srv, 'srv'); c, ch = fetch(C, f'{RC}/logs/{tag}.cli', 'cli'); b, bh = fetch(S, bw, 'bw')
    row, errors = R.metrics(meta, s, c, manifest['files']); R.more_metrics(meta, s, c, b, row, errors)
    if audio_only: errors = [e for e in errors if e != 'incomplete source generation: video']
    if row.get('actual_bandwidth', {}).get('packets', 1) == 0: errors.append('tc band counted no packets (filter did not match)')
    if errors: raise RuntimeError(str(errors))
    meta.update(valid=True, metrics=row, rc=rc, fetch={'srv': {'sha256': sh}, 'cli': {'sha256': ch}, 'bw': {'sha256': bh}})
    print('MULTI_RESULT', json.dumps(row), flush=True)
except Exception as e:
    meta.update(errors=[str(e)]); print('MULTI_FAILURE', str(e), flush=True)
finally:
    for h, rd, path in scripts:
        code = STOPPER.replace('PATHNAME', repr(path)).replace('BINARY', repr(f'{rd}/src/bench/realnet_trace'))
        try: R.ssh(h, 'python3 -c ' + R.q(code), check=False)
        except Exception as e: meta.setdefault('errors', []).append('owned stop ' + str(e)); meta['valid'] = False
    if started:
        try: R.ssh(S, tcbase + ' clear' + tcargs)
        except Exception as e: meta.setdefault('errors', []).append('cleanup ' + str(e)); meta['valid'] = False
    R.save_meta(RES / f'{tag}.json', meta)
    print('MULTI_DONE', meta['valid'], flush=True)
