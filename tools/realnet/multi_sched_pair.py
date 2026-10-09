#!/usr/bin/env python3
"""Run multi_round.py jobs in parallel within each host's budget.

Usage: multi_sched_pair.py JOBFILE LOGDIR

JOBFILE: one JSON object per line - snd rcv variant seed rate, optional loss,
fixed (video per mille, no encoder feedback), unlimited, audio_only,
audio_max_age, delay, burst, queue_ms, video_max, drive ("check"), tc_loss (loss by
tc, true), fec_off (true), police (true: tc police at rate, bucket burst, in front of
a line of `line` kbit, default 40000; charge it the line), charge (the
bandwidth the job takes instead of rate - an unlimited round's real peak).

Budget per host (hosts.py: cap_kbps, slots, pool): the concurrent jobs'
rates stay 5 Mbit below cap_kbps, charged on the sender and the receiver;
at most `slots` processes per pool (hosts on one machine share a pool).
Consecutive jobs that differ only in variant (or fec_off) form a group that starts
together (both fit or neither starts) - baseline and candidate share the
path at the same time - and is run again as a whole when any member fails
(at most twice). The first start waits until no multi_round.py of an
earlier batch runs. Ports start at each sender's port_base (default 9900)."""
import sys, json, subprocess, time, pathlib, threading, re
import hosts as H

HERE = pathlib.Path(__file__).resolve().parent
HOSTS = H.load()
RESERVE = 5000
jobs = [json.loads(l) for l in open(sys.argv[1]) if l.strip() and not l.startswith('#')]
logdir = pathlib.Path(sys.argv[2]); logdir.mkdir(parents=True, exist_ok=True)
used_bw = {h: 0 for h in HOSTS}; used_slot = {}; lock = threading.Lock(); running = []
pool = lambda h: HOSTS[h]['pool']
slots_of = lambda h: max(HOSTS[x]['slots'] for x in HOSTS if pool(x) == pool(h))


def take(j, sign):
    for h in (j['snd'], j['rcv']):
        used_bw[h] += sign * j.get('charge', j['rate']); used_slot[pool(h)] = used_slot.get(pool(h), 0) + sign


def port_for(s):
    used = {x['port'] for x in running if x['snd'] == s}
    p = HOSTS[s].get('port_base', 9900)
    while p in used: p += 1
    return p


def command(j):
    return (['python3', str(HERE / 'multi_round.py'), j['snd'], j['rcv'], j['variant'], str(j['seed']), str(j['rate']), str(j['port'])]
            + ([str(j['fixed'])] if j.get('fixed') else []) + (['--loss', str(j['loss'])] if 'loss' in j else [])
            + (['--unlimited'] if j.get('unlimited') else []) + (['--audio-max-age', str(j['audio_max_age'])] if j.get('audio_max_age') else [])
            + (['--delay', str(j['delay'])] if j.get('delay') else []) + (['--audio-only'] if j.get('audio_only') else [])
            + (['--video-max', str(j['video_max'])] if j.get('video_max') else []) + (['--burst', str(j['burst'])] if j.get('burst') else []) + (['--queue-ms', str(j['queue_ms'])] if j.get('queue_ms') else [])
            + (['--drive-check'] if j.get('drive') == 'check' else []) + (['--tc-loss'] if j.get('tc_loss') else [])
            + (['--fec-off'] if j.get('fec_off') else []) + (['--police', '--line', str(j.get('line', 40000))] if j.get('police') else []))


def one(j, k, attempt):
    cmd = command(j)
    t0 = time.strftime('%F %T'); out = subprocess.run(cmd, cwd=H.WORK, capture_output=True, text=True)
    ok = 'MULTI_DONE True' in out.stdout
    with open(logdir / 'sched.log', 'a') as f:
        f.write(f"{t0} -> {time.strftime('%F %T')} job{k} attempt{attempt} {' '.join(cmd[2:])} ok={ok} "
                f"{(re.findall(r'MULTI_FAILURE.*', out.stdout) or [''])[0][:200]}\n")
    return ok


def run_group(g):
    # the whole group again when any member failed: a lone retry is no longer a same-time pair
    for attempt in (1, 2):
        res = {}; ts = []
        for k, j in g:
            t = threading.Thread(target=lambda j=j, k=k: res.__setitem__(k, one(j, k, attempt))); t.start(); ts.append(t); time.sleep(3)
        for t in ts: t.join()
        if all(res.values()): break
        time.sleep(30)
    with lock:
        for k, j in g: take(j, -1); running.remove(j)


# a group: consecutive jobs that differ only in the variant or in fec_off (lanes
# compared on the same path at the same time)
def key(j): return json.dumps({k: v for k, v in j.items() if k not in ('variant', 'port', 'audio_max_age', 'fec_off')}, sort_keys=True)


groups = []
for k, j in enumerate(jobs):
    if j['snd'] not in HOSTS or j['rcv'] not in HOSTS: raise SystemExit(f'job {k}: unknown host')
    if groups and key(groups[-1][-1][1]) == key(j): groups[-1].append((k, j))
    else: groups.append([(k, j)])


def fits_all(g):
    for _, j in g: take(j, 1)
    ok = all(used_bw[h] <= HOSTS[h]['cap_kbps'] - RESERVE and used_slot.get(pool(h), 0) <= slots_of(h)
             for _, j in g for h in (j['snd'], j['rcv']))
    for _, j in g: take(j, -1)
    return ok


while subprocess.run(['pgrep', '-f', 'multi_round.py'], capture_output=True).returncode == 0: time.sleep(20)
pending = groups; threads = []
with open(logdir / 'sched.log', 'a') as f: f.write(f"{time.strftime('%F %T')} start {len(jobs)} jobs\n")
while pending or running:
    with lock:
        for g in list(pending):
            if fits_all(g):
                pending.remove(g)
                for k, j in g: j['port'] = port_for(j['snd']); take(j, 1); running.append(j)
                t = threading.Thread(target=run_group, args=(g,)); t.start(); threads.append(t)
                time.sleep(3 * len(g))
    time.sleep(10)
for t in threads: t.join()
with open(logdir / 'sched.log', 'a') as f: f.write(f"{time.strftime('%F %T')} all done\n")
