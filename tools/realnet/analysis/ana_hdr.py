#!/usr/bin/env python3
"""Pairs of the compact wire format batch (jobs-hdr): hr-v (old format) vs
hdr-v (19-byte datagram header, 1-byte sid, implicit last length, 16-bit
ts / echo, unpadded data datagrams) on the same path, seed and loss, started
together. Forward / reverse IP+UDP kbps from the sockets' own counters,
protocol overhead per forward datagram (FECCOST: all bytes but segment
bytes), audio / video / key frames on time."""
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
for f in glob.glob(str(B / 'results' / 'hd*-v_*.json')) + glob.glob(str(B / 'results' / 'hr-v_*.json')):
    d = json.load(open(f))
    if not d.get('valid') or d['variant'] not in ('hr-v', 'hdr-v') or d['seed'] < 600:
        continue
    m = d['metrics']; ft = m['fec_total']; dc = m['datagram_cost']['sender']
    kind = 'audio' if d.get('audio_only') else 'unl_av' if d.get('unlimited') else 'tbf2m'
    d['_x'] = dict(fwd=dc['tx_ipudp_bytes'] * 8 / 600 / 1000, rev=m['reverse_ipudp_kbps'], pps=dc['tx_packets'] / 600,
                   ovh=ft['overhead_bytes'] / max(1, ft['datagrams']), au=m['audio']['ontime_pct'],
                   vi=m['video']['ontime_pct'] if not d.get('audio_only') else float('nan'),
                   key=m['video']['keys_ontime_pct'] if not d.get('audio_only') else float('nan'),
                   tv=m['video']['timely_payload_kbps'] if not d.get('audio_only') else 0)
    recv_class.setdefault(d['receiver'], path_class(rtt_of(d)))
    runs[(kind, d['sender'], d['receiver'], d['seed'], d['loss_pct'])][d['variant']] = d

print(f"{'kind':6} {'path':7} {'rtt':>3} loss | old: fwd rev pps ovh/dg au vi key | new: same | d_fwd% d_rev%")
agg = collections.defaultdict(list)
cls = lambda r: recv_class[r]
for k in sorted(runs, key=lambda k: (k[0], cls(k[2]), k[4])):
    p = runs[k]
    if len(p) < 2:
        continue
    a, b = p['hr-v']['_x'], p['hdr-v']['_x']
    agg[(k[0], cls(k[2]))].append((a, b))
    fmt = lambda x: f"{x['fwd']:7.1f} {x['rev']:5.1f} {x['pps']:4.0f} {x['ovh']:5.1f} {x['au']:6.2f} {x['vi']:6.2f} {x['key']:5.1f}"
    print(f"{k[0]:6} {k[1]+'>'+k[2]:7} {cls(k[2]):>3} {k[4]:2}% | {fmt(a)} | {fmt(b)} | {100*(b['fwd']/a['fwd']-1):+5.1f} {100*(b['rev']/a['rev']-1):+5.1f}")
print("\nkind   rtt n | d_fwd% d_rev% | ovh/dg old new | d_audio d_video d_keys d_tvk%")
for (kind, c), xs in sorted(agg.items()):
    m = lambda f: statistics.mean(f(a, b) for a, b in xs)
    print(f"{kind:6} {c:>3} {len(xs)} | {m(lambda a,b:100*(b['fwd']/a['fwd']-1)):+5.1f} {m(lambda a,b:100*(b['rev']/a['rev']-1)):+5.1f} | "
          f"{m(lambda a,b:a['ovh']):5.1f} {m(lambda a,b:b['ovh']):5.1f} | {m(lambda a,b:b['au']-a['au']):+6.2f} "
          f"{m(lambda a,b:b['vi']-a['vi']):+6.2f} {m(lambda a,b:b['key']-a['key']):+5.1f} "
          f"{m(lambda a,b:100*(b['tv']/a['tv']-1) if a['tv'] else 0):+5.1f}")
