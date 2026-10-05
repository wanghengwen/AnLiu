#!/usr/bin/env python3
"""Pairs of the review-scenario batch (jobs-m2b): chk-v (b602cec, anl_check fix
only) vs m2c-v (6481143, + flat-queue PROBE_RTT re-arm fix); 2 Mbit with a
3200-byte bucket (a FIFO), encoder following target_rate up to 8000 per mille,
both driven by anl_check like an application. Per run: on-time audio / video
/ key frames, timely video kbps, shaper drops, the path's min RTT (paired
flows can take different routes), samples in PROBE_RTT and of a probed
min_rtt (does the fixed case occur at all), anl_update calls and CPU."""
import json, glob, collections, statistics, re
from pathlib import Path
def rtt_of(d):
    """the path's RTT class from the client's ping (metrics.ping) or the sender's min RTT"""
    m = re.search(r'rtt_min=([\d.]+)', d.get('metrics', {}).get('ping') or '')
    return float(m.group(1)) if m else 0.0


def path_class(rtt):
    return 'lan' if rtt < 10 else f'~{int(round(rtt, -1))}'

B = Path(__import__('os').environ.get('ANL_REALNET_WORK', '.')).resolve()   # where multi_round.py wrote results/
runs = collections.defaultdict(dict)
path_lab = {}         # path -> RTT class, from the runs themselves
for f in glob.glob(str(B / 'results' / '*-v_multi_*_chk_seed8*.json')):
    d = json.load(open(f))
    if not d.get('valid') or d['variant'] not in ('chk-v', 'm2c-v'):
        continue
    tr = [dict(x.split('=', 1) for x in l.split()[1:] if '=' in x) for l in open(f[:-5] + '.srv') if l.startswith('TRACE ')]
    srv = open(f[:-5] + '.srv').read(); cli = open(f[:-5] + '.cli').read()
    drv = lambda t: re.search(r'^DRIVE mode=\S+ updates=(\d+) cpu_user_ms=(\d+) cpu_sys_ms=(\d+)', t, re.M)
    ds, dc = drv(srv), drv(cli)
    m = d['metrics']
    d['_x'] = dict(au=m['audio']['ontime_pct'], vi=m['video']['ontime_pct'], key=m['video']['keys_ontime_pct'],
                   tv=m['video']['timely_payload_kbps'], qd=m['actual_bandwidth']['queue_drops'] / 600,
                   rtt=min(int(x['minrtt']) for x in tr if int(x['minrtt']) > 0) if tr else 0,
                   prtt=sum(1 for x in tr if x['st'] == '3'), probed=sum(1 for x in tr if x.get('probed') == '1'),
                   upd_s=int(ds[1]) / 600 if ds else float('nan'), upd_c=int(dc[1]) / 600 if dc else float('nan'),
                   cpu=(int(ds[2]) + int(ds[3])) / 600 / 10 if ds else float('nan'))       # % of a core
    path = d['receiver'] + (f"+{d['extra_delay_ms']}" if d.get('extra_delay_ms') else '')
    path_lab.setdefault(path, path_class(rtt_of(d)))
    runs[(path, d['loss_pct'], d['seed'])][d['variant']] = d

print(f"{'path':7} loss seed | chk-v: au vi key tvk qd/s rtt prtt probed upd/s(s,c) cpu% | m2c-v: same")
agg = collections.defaultdict(list)
lab = lambda p: path_lab[p]
for k in sorted(runs, key=lambda k: (lab(k[0]), k[1], k[2])):
    p = runs[k]
    if len(p) < 2:
        continue
    a, b = p['chk-v']['_x'], p['m2c-v']['_x']
    agg[(lab(k[0]), k[1])].append((a, b))
    fmt = lambda x: f"{x['au']:6.2f} {x['vi']:6.2f} {x['key']:5.1f} {x['tv']:5.0f} {x['qd']:4.1f} {x['rtt']:3} {x['prtt']:3} {x['probed']:3} {x['upd_s']:4.0f},{x['upd_c']:4.0f} {x['cpu']:4.1f}"
    print(f"{lab(k[0]):7} {k[1]:2}% {k[2]} | {fmt(a)} | {fmt(b)}")
print("\npath    loss n | d_audio d_video d_keys d_tvk% d_qdrop/s | rtt differs >5 ms in n pairs")
for (c, l), xs in sorted(agg.items()):
    mm = lambda f: statistics.mean(f(a, b) for a, b in xs)
    print(f"{c:7} {l:2}% {len(xs)} | {mm(lambda a,b:b['au']-a['au']):+6.2f} {mm(lambda a,b:b['vi']-a['vi']):+6.2f} {mm(lambda a,b:b['key']-a['key']):+5.1f}"
          f" {mm(lambda a,b:100*(b['tv']/a['tv']-1)):+5.1f} {mm(lambda a,b:b['qd']-a['qd']):+5.2f} | {sum(abs(a['rtt']-b['rtt'])>5 for a,b in xs)}")
