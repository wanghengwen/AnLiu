#!/usr/bin/env python3
"""Pairs of the headroom batch (jobs-hr): main-v vs hr-v on the same path,
seed, rate, loss and encoder cap, started together. Per pair: audio / video /
key frames on time, timely video kbps, wire kbps and shaper drops, and from
the sender's TRACE (after 30 s) the median pace and target over the TBF rate."""
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
recv_class = {}       # receiver -> RTT class, from the runs themselves
for f in glob.glob(str(B / 'results' / '*-v_multi_*.json')):
    d = json.load(open(f))
    if not d.get('valid') or d['variant'] not in ('main-v', 'hr-v'):
        continue
    tr = [l for l in open(f[:-5] + '.srv') if l.startswith('TRACE ')]
    kv = [dict(x.split('=', 1) for x in l.split()[1:] if '=' in x) for l in tr]
    kv = [x for x in kv if float(x['t']) >= 30]
    m = d['metrics']; bw = m['actual_bandwidth']
    d['_x'] = dict(au=m['audio']['ontime_pct'], vi=m['video']['ontime_pct'], key=m['video']['keys_ontime_pct'],
                   tv=m['video']['timely_payload_kbps'], wire=bw['mean_kbps'], qd=bw['queue_drops'] / 600,
                   pace=statistics.median(int(x['pace']) for x in kv) * 8 / 1000 / d['rate_kbps'] if kv else float('nan'),
                   tgt=statistics.median(int(x['target']) for x in kv) * 8 / 1000 / d['rate_kbps'] if kv else float('nan'))
    recv_class.setdefault(d['receiver'], path_class(rtt_of(d)))
    runs[(d['sender'], d['receiver'], d['seed'], d['rate_kbps'], d['loss_pct'], d.get('video_max', 1000))][d['variant']] = d

F = ['au', 'vi', 'key', 'tv', 'wire', 'qd', 'pace', 'tgt']
print(f"{'path':7} {'rtt':>3} {'rate':>5} {'cap':>4} {'loss':>4} | main-v: au vi key tvk wire qd/s pace/L tgt/L | hr-v: same")
agg = collections.defaultdict(list)
cls = lambda r: recv_class[r]
for k in sorted(runs, key=lambda k: (k[5], k[3], cls(k[1]), k[4])):
    p = runs[k]
    if len(p) < 2:
        continue
    a, b = p['main-v']['_x'], p['hr-v']['_x']
    agg[(k[5], k[3], cls(k[1]))].append((a, b))
    fmt = lambda x: f"{x['au']:6.2f} {x['vi']:6.2f} {x['key']:5.1f} {x['tv']:5.0f} {x['wire']:5.0f} {x['qd']:5.1f} {x['pace']:5.2f} {x['tgt']:5.2f}"
    print(f"{k[0]+'>'+k[1]:7} {cls(k[1]):>3} {k[3]:5} {k[5]:4} {k[4]:3}% | {fmt(a)} | {fmt(b)}")
print("\ncap rate rtt n | d_audio d_video d_keys d_tvk% d_wire% d_qdrop/s")
for (cap, rate, c), xs in sorted(agg.items()):
    m = lambda f: statistics.mean(f(a, b) for a, b in xs)
    print(f"{cap:4} {rate:5} {c:>3} {len(xs)} | {m(lambda a,b:b['au']-a['au']):+6.2f} {m(lambda a,b:b['vi']-a['vi']):+6.2f} {m(lambda a,b:b['key']-a['key']):+6.1f}"
          f" {m(lambda a,b:100*(b['tv']/a['tv']-1)):+6.1f} {m(lambda a,b:100*(b['wire']/a['wire']-1)):+6.1f} {m(lambda a,b:b['qd']-a['qd']):+6.2f}")
