#!/usr/bin/env python3
"""Summary of the churn rounds (churn_round.py) in ANL_REALNET_WORK/results:
one row per round, both ends added up; the round is listed even when it is
invalid, with the reason."""
import json, sys
import hosts as H


def main():
    rows = []
    for p in sorted((H.WORK / 'results').glob('churn_*.json')):
        m = json.loads(p.read_text())
        if 'srv' not in m: continue
        ends = [m['srv'], m['cli']]

        def tot(key, field):
            return sum(e.get(key, {}).get(field, 0) for e in ends if isinstance(e.get(key), dict))
        conf = [e.get(f'CHURN_CONFIRM_{by}', {}) for e in ends for by in ('opener', 'acceptor')]
        conf = [c for c in conf if isinstance(c, dict) and c.get('n')]
        n = sum(c['n'] for c in conf)
        p50 = max((c['p50_ms'] for c in conf), default=0)
        p99 = max((c['p99_ms'] for c in conf), default=0)
        mx = max((c['max_ms'] for c in conf), default=0)
        srtt = max((e.get('CHURN_FINAL', {}).get('srtt', 0) for e in ends), default=0)
        loss = m.get('tc_loss', {})
        if m['loss_pct'] and loss.get('fwd_pkts', 0) == 0 and m['valid']:   # rounds from before churn_round.py checked it
            m['valid'] = False; m.setdefault('errors', []).append('tc band matched no packets: no loss applied')
        rows.append(dict(
            path=f"{m['server']}>{m['client']}", loss=m['loss_pct'], delay=m['extra_delay_ms'], conc=m['conc'], seed=m['seed'],
            tc=f"{loss.get('fwd_pct', '-')}/{loss.get('rev_pct', '-')}", srtt=srtt,
            opened=tot('CHURN_OPEN', 'opened'), ebusy=tot('CHURN_OPEN', 'ebusy'), refused=tot('CHURN_OPEN', 'refused'),
            told=tot('CHURN_CLOSE', 'told'), confirmed=n, p50=p50, p99=p99, max=mx,
            graceful=f"{tot('CHURN_READ', 'graceful_ok')}/{tot('CHURN_READ', 'graceful_ok') + tot('CHURN_READ', 'graceful_short')}",
            integrity=tot('CHURN_READ', 'order_errors') + tot('CHURN_READ', 'pattern_errors'),
            final='ok' if all(e.get('CHURN_FINAL', {}).get('ok') == 1 for e in ends) else 'FAIL',
            valid=m['valid'], why='; '.join(m.get('errors', []))[:80]))
    if '--json' in sys.argv:
        print(json.dumps(rows, indent=1)); return
    cols = ['path', 'loss', 'delay', 'conc', 'seed', 'tc', 'srtt', 'opened', 'ebusy', 'refused', 'told', 'confirmed',
            'p50', 'p99', 'max', 'graceful', 'integrity', 'final', 'valid']
    print('\t'.join(cols))
    for r in rows: print('\t'.join(str(r[c]) for c in cols) + ('\t' + r['why'] if r['why'] else ''))
    v = [r for r in rows if r['valid']]
    print(f"valid {len(v)}/{len(rows)}; opened {sum(r['opened'] for r in v)}, closes told {sum(r['told'] for r in v)}, "
          f"confirmed {sum(r['confirmed'] for r in v)}, refused {sum(r['refused'] for r in rows)}, "
          f"integrity errors {sum(r['integrity'] for r in rows)}")


if __name__ == '__main__':
    main()
