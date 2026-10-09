#!/usr/bin/env python3
"""Paired difference of multi_round.py rounds of two lanes (candidate minus
baseline), matched on everything else: path, rate, loss, delay, burst, seed,
loss method and drive. A lane is the variant plus its FEC / key-frame
switch: "cand", "cand+nf" (--fec-off).

Usage: multi_pair.py BASE_LANE CAND_LANE     (ANL_REALNET_WORK holds results/)

A round is left out (SKIP) when its datagram loss beyond tc and the TBF
(sender DATAGRAM_COST tx_packets less the receiver's rx_packets, the TBF's
drops, the tc loss drops and a --police round's policer drops) is more
than 2% of what was sent: the path or the receiver dropped on its own,
e.g. concurrent rounds over the path's capacity
(docs/testcases/realnet/README.md, egress capacity). Not for --unlimited
rounds: there the path's own limit (a provider's token-bucket policer) is
the bottleneck under test.

Metrics: audio / video / key frames on time (percentage points), timely
video payload kbps and tc-counted sender bandwidth (percent of the
baseline), encoder level (points). Per scenario and over all pairs: the mean
and its 95% interval (t distribution)."""
import sys, json, glob, re, statistics, collections
import hosts as H

T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26, 10: 2.23, 15: 2.13, 20: 2.09, 30: 2.04}
METRICS = {
    'audio': (lambda r: r['audio']['ontime_pct'], 'pp'),
    'video': (lambda r: r['video']['ontime_pct'], 'pp'),
    'keys':  (lambda r: r['video']['keys_ontime_pct'], 'pp'),
    'tvk':   (lambda r: r['video']['timely_payload_kbps'], '%'),
    'bw':    (lambda r: r['actual_bandwidth']['mean_kbps'], '%'),
    'enc':   (lambda r: r.get('encoder_mean_pct') or 0, 'pp'),
}
KEY = ('sender', 'receiver', 'rate_kbps', 'loss_pct', 'extra_delay_ms', 'tbf_burst', 'seed', 'tc_loss',
       'fixed_scale', 'audio_only', 'drive', 'unlimited', 'video_max', 'tbf_queue_ms', 'line_kbps')


def lane(m):
    return m['variant'] + ('+nf' if m.get('fec_off') else '')


def other_loss(f, m):
    """percent of the sent datagrams lost beyond tc and the TBF; None when a count is missing"""
    base = f[:-len('.json')]
    try:
        tx = int(re.search(r'tx_packets=(\d+)', open(base + '.srv', errors='replace').read())[1])
        rx = int(re.search(r'rx_packets=(\d+)', open(base + '.cli', errors='replace').read())[1])
        tbf = [e for e in map(json.loads, open(base + '.bw')) if e.get('kind') == 'tbf']
    except (OSError, TypeError, ValueError):
        return None
    if not tx or not tbf: return None
    drop = tbf[-1]['drops'] + (m.get('tc_loss_stats') or {}).get('fwd_drop', 0) + (m.get('police_stats') or {}).get('drop', 0)
    return 100 * (tx - rx - drop) / tx


def ci(ds):
    n = len(ds); m = statistics.mean(ds)
    if n < 2: return m, None
    return m, T95[max(x for x in T95 if x <= n - 1)] * statistics.stdev(ds) / n ** 0.5


def main():
    if len(sys.argv) != 3: raise SystemExit(__doc__)
    base, cand = sys.argv[1:]
    runs = collections.defaultdict(dict)
    for f in sorted(glob.glob(str(H.WORK / 'results' / '*_multi_*.json')) + glob.glob(str(H.WORK / 'results' / '*_unl_*.json'))):
        m = json.load(open(f))
        if not m.get('valid') or lane(m) not in (base, cand): continue
        ol = None if m.get('unlimited') else other_loss(f, m)
        if ol is not None and ol > 2:
            print(f"SKIP {m['tag']}: {ol:.1f}% lost beyond tc and the TBF", file=sys.stderr); continue
        runs[tuple(m.get(k) for k in KEY)][lane(m)] = m['metrics']
    diffs = collections.defaultdict(lambda: collections.defaultdict(list))
    for k, v in sorted(runs.items(), key=lambda kv: str(kv[0])):
        if base not in v or cand not in v: continue
        scen = f'{k[0]}>{k[1]} {k[2]}k b{k[5]} q{k[-2]}' + (f' police/line {k[-1] // 1000}M' if k[-1] else '') + f' +{k[4]}ms {k[3]}%'
        line = []
        for name, (get, unit) in METRICS.items():
            b, c = get(v[base]), get(v[cand])
            d = (c / b - 1) * 100 if unit == '%' and b else c - b
            diffs[scen][name].append(d); diffs['ALL'][name].append(d); line.append(f'{name} {d:+.2f}')
        print(f'{scen:28} seed {k[6]}: ' + ' '.join(line))
    print(f"\n{len(diffs['ALL']['audio'])} pairs; mean {cand} - {base} [95% interval]")
    if not diffs: return
    for scen in sorted(diffs, key=lambda s: (s == 'ALL', s)):
        parts = []
        for name, (_, unit) in METRICS.items():
            m, h = ci(diffs[scen][name])
            parts.append(f'{name} {m:+.2f}{unit}' + (f' ±{h:.2f}' if h is not None else ''))
        print(f"{scen:28} n={len(diffs[scen]['audio'])}: " + '  '.join(parts))


if __name__ == '__main__':
    main()
