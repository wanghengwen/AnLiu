#!/usr/bin/env python3
"""Playout-buffer view of cmp_round.py rounds: every protocol is scored as an
application with a fixed playout buffer would see it.

SRT delivers each packet a fixed latency D after its source time (TSBPD); its
time base is set once at connection setup, so its actual delay is D plus that
base's error (`play`). AnLiu delivers a frame as soon as it is complete; here
it gets the same kind of buffer: frame i plays at send_i + anchor + D, where D
is the SRT latency of that flow in the round (meta latency_ms, else the SRT
lane's) and anchor is the smallest one-way delay the receiver has seen so far
(running minimum over both flows of the lane, in arrival order). A frame is on time when it has
arrived by its playout time + TOL. SRT's TSBPD is its playout buffer (a
packet that misses its time is dropped), so an SRT frame is on time when it
was delivered at all; where its time base sits shows in `play`. dec: the frame and every earlier frame of
its GOP on time (an IPPP decoder cannot use a P frame after a lost or late
one).

play a/v: the delay the application sees, D + (anchor - path minimum), median
(and p99 for video: SRT's time base can move during a round); the path
minimum is the smallest AnLiu audio delay of the round (as in cmp_ana.py). need: the smallest buffer D that would have made 99 / 99.9 % of
the video frames decodable (each frame needs the largest delay over its GOP
up to itself, so one slow key frame holds back its whole GOP) and 99.9 % of
the audio frames on time; '-' when more than that share never arrived. ss:
the same from second WARM_S on (the first key frame is sent before the
sender knows the path's rate). Not given for SRT, which plays at D by design."""
import json, glob, statistics, collections, sys
from pathlib import Path
from cmp_checks import validate_lane
from cmp_ana import anl_delays, srt_delays, B, DUR_DEFAULT
TOL = 10000                         # us, as cmp_round.py's budgets (latency + 10 ms)
FRAME_US = {1: 20000, 2: 1000000 / 30}
WARM_S = 10


def quant(xs, q):
    """q-quantile of xs where None (never arrived) counts as infinite; None if that is infinite."""
    xs = sorted(float('inf') if x is None else x for x in xs)
    v = xs[min(len(xs) - 1, int(q * len(xs)))] if xs else float('inf')
    return None if v == float('inf') else v


def lane(name, sent, rcv, lat, base):
    """Per flow: on time, dec, keys, play delay and the buffer needed. rcv holds one-way delays (us)."""
    srt = not name.startswith('anl')
    got = sorted((k[1] * FRAME_US[k[0]] + rcv[k], k) for k in sent if k in rcv)
    anchor, run = {}, float('inf')
    for _, k in got:                # the receiver's running minimum, in arrival order
        run = min(run, rcv[k]); anchor[k] = run
    if srt:                         # TSBPD is SRT's playout buffer: what it delivered, it delivered on its own schedule
        anchor = {k: rcv[k] - lat[k[0]] for k in rcv}
    r = {}
    for f in (1, 2):
        keys = sorted(k for k in sent if k[0] == f)
        ex = {k: rcv[k] - anchor[k] for k in keys if k in rcv}
        on = {k for k in ex if ex[k] <= lat[f] + TOL}
        pl = sorted(lat[f] + anchor[k] - base for k in ex) or [lat[f]]
        x = dict(ontime=100 * len(on) / max(1, len(keys)), play=pl[len(pl) // 2] / 1000, play99=pl[int(.99 * (len(pl) - 1))] / 1000)
        if f == 1:
            x['need999'] = quant([ex.get(k) for k in keys], .999)
        else:
            ok, dec, need, worst = False, 0, [], 0
            for k in keys:
                if sent[k][1] == 1:
                    worst = 0           # a key frame starts a GOP
                worst = None if worst is None or k not in ex else max(worst, ex[k])
                need.append(worst)
                ok = (k in on) and (ok or sent[k][1] == 1)
                dec += ok
            x['dec'] = 100 * dec / max(1, len(keys))
            kk = [k for k in keys if sent[k][1] == 1]
            x['keys'] = 100 * sum(k in on for k in kk) / max(1, len(kk))
            x['need99'], x['need999'] = quant(need, .99), quant(need, .999)
            ss = [v for k, v in zip(keys, need) if k[1] * FRAME_US[2] >= WARM_S * 1e6]
            x['ss99'], x['ss999'] = quant(ss, .99), quant(ss, .999)
        if srt:
            x = {k: (None if k.startswith(('need', 'ss')) else v) for k, v in x.items()}
        r[f] = x
    return r


def latency(meta):
    """(audio, video) latency in ms: the round's --budgets, else that of its only SRT lane (srt-b: 120 / 250)."""
    if meta.get('latency_ms'):
        return meta['latency_ms']['audio'], meta['latency_ms']['video']
    srt = {tuple(c['cfg'][:2]) for n, c in meta['protocols'].items() if not n.startswith('anl')}
    return srt.pop() if len(srt) == 1 else None


def analyse(meta):
    tag = meta['tag']; dur = meta.get('duration_s', DUR_DEFAULT)
    la, lv = latency(meta)
    lat = {1: la * 1000, 2: lv * 1000}
    raw = {}
    for name in meta['protocols']:
        srv = (B / 'results' / f'{tag}.{name}.srv').read_text(errors='replace')
        cli = (B / 'results' / f'{tag}.{name}.cli').read_text(errors='replace')
        errors = validate_lane(name, dur, srv, cli, require_exit=bool(meta.get('validation_version')))
        if errors:
            raise ValueError(f'{tag} {name}: ' + '; '.join(errors))
        raw[name] = (anl_delays if name.startswith('anl') else srt_delays)(srv, cli)
    anl_audio = [d for n in raw if n.startswith('anl') for (f, s), d in raw[n][1].items() if f == 1]
    if not anl_audio:
        return None
    base = min(anl_audio)
    rows = {}
    for name, (sent, rcv) in raw.items():
        if name.partition('@')[0] == 'anl-ref':
            continue                # audio only: the delay base of an SRT round
        rows[name] = lane(name, sent, rcv, lat, base)
        tc = meta['protocols'][name].get('tc') or {}
        rows[name]['wire'] = (tc.get('bytes') or 0) * 8 / dur / 1000
    return rows


if __name__ == '__main__':
    fm = lambda v: '     -' if v is None else f'{v / 1000:6.0f}'
    fn = lambda name, v: '      ' if not name.startswith('anl') else fm(v)
    path_of = lambda m: ('LAN' if m['rtt_min_ms'] < 10 else '~100ms' if m['rtt_min_ms'] < 135 else '~170ms' if m['rtt_min_ms'] < 220
                         else f"{m['rtt_min_ms']:.0f}ms") + (f"+{m['delay_ms']}" if m.get('delay_ms') else '')
    agg = collections.defaultdict(list)
    for f in sorted(glob.glob(str(B / 'results' / 'cmp_*.json'))):
        m = json.load(open(f))
        if not m.get('valid') or not latency(m):
            continue
        try:
            rows = analyse(m)
        except (OSError, ValueError) as e:
            print(f'SKIP invalid comparison: {e}', file=sys.stderr)
            continue
        if not rows:
            continue
        if m.get('start_rate_kbps'):
            rows = {(n + '+sr' if n.startswith('anl') else n): r for n, r in rows.items()}
        la, lv = latency(m)
        print(f"{m['sender']}>{m['receiver']} rtt {m['rtt_min_ms']:.1f}{' +delay %d' % m['delay_ms'] if m.get('delay_ms') else ''} loss {m['loss_pct']}% buffer audio {la} / video {lv} ms")
        for name, r in rows.items():
            print(f"  {name:11} audio {r[1]['ontime']:6.2f} play {r[1]['play']:6.1f} | video {r[2]['ontime']:6.2f} dec {r[2]['dec']:6.2f} keys {r[2]['keys']:5.1f} "
                  f"play {r[2]['play']:6.1f} p99 {r[2]['play99']:6.1f} | need v99 {fn(name, r[2]['need99'])} v99.9 {fn(name, r[2]['need999'])} a99.9 {fn(name, r[1]['need999'])} ss v99 {fn(name, r[2]['ss99'])} v99.9 {fn(name, r[2]['ss999'])} | wire {r['wire']:6.0f}")
            agg[(path_of(m) + ('' if lv == 250 else ' rec'), m['loss_pct'], name)].append(r)
    print('\npath loss proto n | audio on | video on | dec | keys | play a / v (v p99) ms | need video 99% / 99.9%, audio 99.9% | ss video 99% / 99.9% ms | wire kbps')
    for k in sorted(agg, key=lambda k: (k[0], k[1], not k[2].startswith('anl'), k[2])):
        xs = agg[k]; mn = lambda g: statistics.mean(g(x) for x in xs)
        nd = lambda g: fn(k[2], max((g(x) for x in xs), key=lambda v: float('inf') if v is None else v))
        print(f"{k[0]:6} {k[1]:2}% {k[2]:11} {len(xs)} | {mn(lambda x: x[1]['ontime']):6.2f} | {mn(lambda x: x[2]['ontime']):6.2f} | {mn(lambda x: x[2]['dec']):6.2f} | "
              f"{mn(lambda x: x[2]['keys']):5.1f} | {mn(lambda x: x[1]['play']):5.0f} / {mn(lambda x: x[2]['play']):5.0f} ({max(x[2]['play99'] for x in xs):5.0f}) | "
              f"{nd(lambda x: x[2]['need99'])} / {nd(lambda x: x[2]['need999'])} / {nd(lambda x: x[1]['need999'])} | {nd(lambda x: x[2]['ss99'])} / {nd(lambda x: x[2]['ss999'])} | {mn(lambda x: x['wire']):6.0f}")
