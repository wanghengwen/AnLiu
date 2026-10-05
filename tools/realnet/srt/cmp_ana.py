#!/usr/bin/env python3
"""Analysis of cmp_round.py rounds. Per round and protocol: audio / video /
key frames on time (extra one-way delay within 150 / 300 ms), delivered at
all, extra delay p50 / p95, timely video kbps, wire kbps (tc band bytes) and
the tc loss actually applied.

One-way delays are absolute (CLOCK_REALTIME): srtnet stamps both ends with
it; realnet's monotonic stamps are converted with each host's TIMEBASE
(wall_us - event_mono_us). The base is the smallest AnLiu audio delay of the
same round (same hosts, same time, so the hosts' clock offset cancels): it
stands for the path's propagation delay. SRT delivers every packet a fixed
latency after it was sent (TSBPD), so subtracting its own minimum would hide
that latency; this base does not."""
import json, glob, re, statistics, collections, sys
from pathlib import Path
B = Path(__import__('os').environ.get('ANL_REALNET_WORK', '.')).resolve()   # results/ of cmp_round.py
BUDGET = {1: 150000, 2: 300000}
DUR_DEFAULT = 600


def anl_delays(srv, cli):
    def off(t):
        m = re.search(r'^TIMEBASE event=traffic_start event_mono_us=(\d+) .*wall_us=(\d+)', t, re.M)
        return int(m[2]) - int(m[1])
    o = off(cli) - off(srv)
    sent = {}
    for l in srv.splitlines():
        if l.startswith('MDIAG_S '):         # flow seq key len ...
            v = l.split(); sent[int(v[1]), int(v[2])] = (int(v[4]), int(v[3]))
    rcv = {}
    for l in cli.splitlines():
        if l.startswith('MDIAG_R '):
            v = l.split(); rcv[int(v[1]), int(v[2])] = int(v[6]) + o
    return sent, rcv


def srt_delays(srv, cli):
    sent = {}
    for l in srv.splitlines():
        if l.startswith('SRTS '):            # flow seq key len send_wall rc
            v = l.split(); sent[int(v[1]), int(v[2])] = (int(v[4]), int(v[3]))
    rcv = {}
    for l in cli.splitlines():
        if l.startswith('SRTR '):
            v = l.split(); rcv[int(v[1]), int(v[2])] = int(v[6]) - int(v[5])
    return sent, rcv


def analyse(meta):
    tag = meta['tag']; dur = meta.get('duration_s', DUR_DEFAULT)
    rows = {}; raw = {}
    for name in meta['protocols']:
        srv = (B / 'results' / f'{tag}.{name}.srv').read_text(errors='replace')
        cli = (B / 'results' / f'{tag}.{name}.cli').read_text(errors='replace')
        raw[name] = (anl_delays if name == 'anl' else srt_delays)(srv, cli)
        rows[name] = {'srt_stats': [l for l in srv.splitlines() + cli.splitlines() if l.startswith('SRTSTAT')]}
    base = min(d for (f, s), d in raw['anl'][1].items() if f == 1)
    for name, (sent, rcv) in raw.items():
        r = rows[name]
        for f, fname in ((1, 'audio'), (2, 'video')):
            keys = [k for k in sent if k[0] == f]
            ex = {k: rcv[k] - base for k in keys if k in rcv}
            good = [k for k in keys if k in ex and ex[k] <= BUDGET[f]]
            d = sorted(ex.values())
            r[fname] = dict(n=len(keys), delivered=100 * len(ex) / max(1, len(keys)), ontime=100 * len(good) / max(1, len(keys)),
                            p50=d[len(d) // 2] / 1000 if d else None, p95=d[int(.95 * (len(d) - 1))] / 1000 if d else None,
                            timely_kbps=sum(sent[k][0] for k in good) * 8 / dur / 1000)
            if f == 2:
                kk = [k for k in keys if sent[k][1] == 1]      # sent: (len, key)
                r['keys'] = 100 * sum(k in good for k in kk) / max(1, len(kk))
        tc = meta['protocols'][name].get('tc') or {}
        r['wire_kbps'] = (tc.get('bytes') or 0) * 8 / dur / 1000
        r['tc_drops'] = tc.get('drops')
        ls = meta['protocols'][name].get('loss_stats')
        r['loss_fwd'] = 100 * ls['fwd_drop'] / ls['fwd_pkts'] if ls and ls['fwd_pkts'] else None
        r['loss_rev'] = 100 * ls['rev_drop'] / ls['rev_pkts'] if ls and ls['rev_pkts'] else None
    return rows


if __name__ == '__main__':
    path_of = lambda m: 'LAN' if m['rtt_min_ms'] < 10 else f"{m['rtt_min_ms']:.0f}ms"
    agg = collections.defaultdict(list)
    for f in sorted(glob.glob(str(B / 'results' / 'cmp_*.json'))):
        m = json.load(open(f))
        if not m.get('valid'):
            continue
        rows = analyse(m)
        print(f"{m['sender']}>{m['receiver']} rtt {m['rtt_min_ms']:.1f} rate {m['rate_kbps']} loss {m['loss_pct']}% seed {m['seed']}")
        for name, r in rows.items():
            lf = f"{r['loss_fwd']:.2f}/{r['loss_rev']:.2f}" if r['loss_fwd'] is not None else '-'
            print(f"  {name:8} audio {r['audio']['ontime']:6.2f} ({r['audio']['delivered']:6.2f} p50 {r['audio']['p50']:6.1f}) "
                  f"video {r['video']['ontime']:6.2f} ({r['video']['delivered']:6.2f} p95 {r['video']['p95']:6.1f}) keys {r['keys']:5.1f} "
                  f"tvk {r['video']['timely_kbps']:6.1f} wire {r['wire_kbps']:6.1f} loss {lf}")
            agg[(path_of(m), m['loss_pct'], name)].append(r)
    print('\npath loss proto n | audio on (delivered) | video on (delivered) | keys | timely video kbps | wire kbps | audio p50 / video p95 ms')
    for k in sorted(agg, key=lambda k: (k[0], k[1], ['anl', 'srt-b', 'srt-fec', 'srt-rec'].index(k[2]))):
        xs = agg[k]; mn = lambda f: statistics.mean(f(x) for x in xs)
        print(f"{k[0]:6} {k[1]:2}% {k[2]:8} {len(xs)} | {mn(lambda x: x['audio']['ontime']):6.2f} ({mn(lambda x: x['audio']['delivered']):6.2f}) | "
              f"{mn(lambda x: x['video']['ontime']):6.2f} ({mn(lambda x: x['video']['delivered']):6.2f}) | {mn(lambda x: x['keys']):5.1f} | "
              f"{mn(lambda x: x['video']['timely_kbps']):6.1f} | {mn(lambda x: x['wire_kbps']):6.1f} | {mn(lambda x: x['audio']['p50']):6.1f} / {mn(lambda x: x['video']['p95']):6.1f}")
