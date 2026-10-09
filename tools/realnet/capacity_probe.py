#!/usr/bin/env python3
"""Egress capacity of a sender toward a receiver: paced UDP (1200-byte datagrams,
2 ms ticks) at each rate for SECS seconds, the receiver counts what arrives.

Usage: capacity_probe.py SENDER RECEIVER PORT RATES [SECS]
  RATES  Mbit/s, comma separated, e.g. 2,4,8,12,16
Prints one line per rate: sent, received, loss %. Run it before a batch with
nothing else on the hosts; the cap_kbps in the host table can be out of date
(2026-10-08: one host lost 8..87% above ~10 Mbit/s, the table said 30).
A cloud provider may drop everything for a while after a step far above the limit,
so go up in steps and stop at the first step with loss. Hosts come from
ANL_REALNET_HOSTS; the receiver must accept UDP on PORT from the sender."""
import sys, time, subprocess
import hosts as H
import rnlib as R

AGENT = r'''
import socket, sys, time, struct, collections
if sys.argv[1] == 'recv':
    port, secs = int(sys.argv[2]), float(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    s.bind(('0.0.0.0', port)); s.settimeout(1.0); print('READY', flush=True)
    cnt = collections.Counter(); end = time.time() + secs
    while time.time() < end:
        try: d, _ = s.recvfrom(2048)
        except socket.timeout: continue
        cnt[struct.unpack('!II', d[:8])[0]] += 1
    for k in sorted(cnt): print('STEP', k, cnt[k], flush=True)
else:
    host, port, mbit, secs, step = sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), int(sys.argv[6])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
    pps = mbit * 1e6 / 8 / 1228; t0 = time.time(); n = 0; pad = b'x' * 1192
    while time.time() - t0 < secs:
        while n < int((time.time() - t0) * pps):
            s.sendto(struct.pack('!II', step, n) + pad, (host, port)); n += 1
        time.sleep(0.002)
    print('SENT', step, n, flush=True)
'''


def main():
    if len(sys.argv) < 5: raise SystemExit(__doc__)
    hs = H.load(); S, C = hs[sys.argv[1]], hs[sys.argv[2]]
    port = int(sys.argv[3]); rates = [float(x) for x in sys.argv[4].split(',')]
    secs = float(sys.argv[5]) if len(sys.argv) > 5 else 8
    path = lambda h: f"{h['base']}/{H.REMOTE_DIR}/capacity_probe_agent.py"
    for h in (S, C): R.ssh(h, f"mkdir -p {h['base']}/{H.REMOTE_DIR} && printf %s {R.q(AGENT)} > {path(h)}")
    total = len(rates) * (secs + 31) + 6     # each step's sender login may be retried
    for attempt in range(4):        # a public sshd drops some logins (MaxStartups): retry like rnlib.ssh
        rp = subprocess.Popen(R.SSH + [C['ssh'], f'python3 {path(C)} recv {port} {total}'],
                              stdout=subprocess.PIPE, text=True)
        if rp.stdout.readline().strip() == 'READY': break
        rp.wait(); time.sleep(3 + 5 * attempt)
    else: raise SystemExit('receiver did not start')
    time.sleep(0.5); sent = {}
    for i, r in enumerate(rates):
        out = R.ssh(S, f"python3 {path(S)} send {C['ip']} {port} {r} {secs} {i}", timeout=secs + 60).stdout.decode().split()
        sent[i] = int(out[2]); time.sleep(1)
    got = {int(l.split()[1]): int(l.split()[2]) for l in rp.communicate()[0].splitlines() if l.startswith('STEP')}
    for i, r in enumerate(rates):
        g = got.get(i, 0)
        print(f"{S['name']}>{C['name']} {r:6.1f} Mbit/s sent {sent[i]:6d} received {g:6d} loss {100 * (1 - g / max(1, sent[i])):6.2f}%")


if __name__ == '__main__':
    main()
