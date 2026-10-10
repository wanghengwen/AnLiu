#!/usr/bin/env python3
"""Paired difference of two AnLiu lanes of cmp_round.py rounds (candidate
minus baseline, same path, same time), per scenario and over all rounds.

Usage: cmp_pair.py BASE_LANE CAND_LANE [--limits]
  e.g. cmp_pair.py anl-nf anl-nf@cand      (ANL_REALNET_WORK holds results/)

Per round the differences; per scenario and over all rounds the mean
difference and its 95% interval (t distribution over the rounds). Metrics: audio / video / key
frames on time and video on time and decodable (percentage points), audio
p50 and video p95 extra delay (ms), wire kbps (percent of the baseline).
A round is left out (SKIP) when a lane's end-to-end datagram loss (sender
DATAGRAM_COST tx_packets against the receiver's rx_packets) is more than
2 points above the tc loss: the path or the sender's egress dropped on its
own (docs/testcases/03-realnet.md, egress capacity).
--limits checks the overall means against the regression limits of
docs/testcases/RN-02-media-delay-pair.md and prints LIMIT lines (FAIL when a mean is
worse than its limit and the interval excludes 0)."""
import sys, json, glob, re, statistics, collections
from pathlib import Path
import cmp_ana as A

T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36, 8: 2.31, 9: 2.26, 10: 2.23, 15: 2.13, 20: 2.09, 30: 2.04}
# metric: (getter, unit, worse-direction sign, limit in that unit); a mean worse than the limit is a regression
METRICS = {
    'audio':  (lambda r: r['audio']['ontime'], 'pp', -1, 0.5),
    'video':  (lambda r: r['video']['ontime'], 'pp', -1, 1.0),
    'dec':    (lambda r: r['dec'], 'pp', -1, 1.0),
    'keys':   (lambda r: r['keys'], 'pp', -1, 2.0),
    'a_p50':  (lambda r: r['audio']['p50'], 'ms', +1, 5.0),
    'v_p95':  (lambda r: r['video']['p95'], 'ms', +1, 15.0),
    'wire':   (lambda r: r['wire_kbps'], '%', +1, 3.0),
}


def e2e_loss(tag, lane):
    """forward datagram loss of one AnLiu lane, percent; None when the counters are missing"""
    def count(ext, key):
        f = A.B / 'results' / f'{tag}.{lane}.{ext}'
        m = re.search(r'^DATAGRAM_COST .*\b' + key + r'=(\d+)', f.read_text(errors='replace'), re.M) if f.exists() else None
        return int(m[1]) if m else None
    tx, rx = count('srv', 'tx_packets'), count('cli', 'rx_packets')
    return 100 * (1 - rx / tx) if tx and rx is not None else None


def t95(n):
    k = max(x for x in T95 if x <= max(n - 1, 1))
    return T95[k]


def summary(ds):
    n = len(ds); m = statistics.mean(ds)
    h = t95(n) * statistics.stdev(ds) / n ** 0.5 if n > 1 else float('inf')
    return n, m, m - h, m + h


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if len(args) != 2: raise SystemExit(__doc__)
    base, cand = args
    diffs = collections.defaultdict(lambda: collections.defaultdict(list))
    rounds = 0
    for f in sorted(glob.glob(str(A.B / 'results' / 'cmp_*.json'))):
        m = json.load(open(f))
        if not m.get('valid'): continue
        try: rows = A.analyse(m)
        except (OSError, ValueError) as e:
            print(f'SKIP {Path(f).name}: {e}', file=sys.stderr); continue
        if not rows or base not in rows or cand not in rows: continue
        el = {ln: e2e_loss(m['tag'], ln) for ln in (base, cand)}
        if any(v is not None and v > m['loss_pct'] + 2 for v in el.values()):
            print(f"SKIP {m['tag']}: end-to-end loss " + ' / '.join(f'{v:.1f}%' for v in el.values() if v is not None)
                  + f" with tc {m['loss_pct']}%", file=sys.stderr); continue
        rounds += 1
        scen = f"{m['sender']}>{m['receiver']} +{m.get('delay_ms', 0)} {m['loss_pct']}%"
        b, c = rows[base], rows[cand]
        line = []
        for k, (get, unit, _, _) in METRICS.items():
            d = (get(c) / get(b) - 1) * 100 if unit == '%' else get(c) - get(b)
            diffs[scen][k].append(d); diffs['ALL'][k].append(d)
            line.append(f'{k} {d:+.2f}')
        print(f"{scen:24} seed {m['seed']}: " + ' '.join(line))
    print(f'\n{rounds} paired rounds; mean difference {cand} - {base} [95% interval]')
    for scen in sorted(diffs, key=lambda s: (s == 'ALL', s)):
        parts = []
        for k, (_, unit, _, _) in METRICS.items():
            n, mval, lo, hi = summary(diffs[scen][k])
            parts.append(f'{k} {mval:+.2f}{unit}' + (f' [{lo:+.2f},{hi:+.2f}]' if n > 1 else ''))
        print(f'{scen:24} n={len(diffs[scen]["audio"])}: ' + '  '.join(parts))
    if '--limits' in sys.argv and diffs:
        bad = 0
        for k, (_, unit, sign, lim) in METRICS.items():
            n, mval, lo, hi = summary(diffs['ALL'][k])
            worse = mval * sign > lim                     # the mean beyond the limit
            sure = (lo > 0 or hi < 0) and n > 1           # and the interval excludes 0
            st = 'FAIL' if worse and sure else 'WARN' if worse else 'OK'
            bad += st == 'FAIL'
            print(f'LIMIT {k} mean {mval:+.2f}{unit} [{lo:+.2f},{hi:+.2f}] limit {"-" if sign < 0 else "+"}{lim}{unit} {st}')
        print('LIMITS', 'FAIL' if bad else 'OK')


if __name__ == '__main__':
    main()
