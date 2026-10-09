#!/usr/bin/env python3
"""Token bucket of a sender's egress policer: after an idle gap, a burst of
SIZE KB sent back to back (line rate); the receiver counts what arrives.
A policer passes about its bucket at line rate and drops the rest, so the
received KB level off at the bucket (plus the rate times the burst's
duration, small at 1 Gbit/s).

Usage: burst_probe.py SENDER RECEIVER PORT SIZES_KB [GAP_S]
  SIZES_KB  comma separated, e.g. 32,64,128,256,512,1024,2048
  GAP_S     idle time before each burst so the bucket refills (default 4)
One line per burst: sent, received (datagrams and KB), loss %. All bursts
run in one ssh session (a slow ssh login does not stretch the gaps). Run it
with nothing else on the hosts. Hosts come from ANL_REALNET_HOSTS; the
receiver must accept UDP on PORT from the sender."""
import sys, time, subprocess
import hosts as H
import rnlib as R

AGENT = r'''
import socket, sys, time, struct, collections
if sys.argv[1] == 'recv':
    port, secs = int(sys.argv[2]), float(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
    s.bind(('0.0.0.0', port)); s.settimeout(1.0); print('READY', flush=True)
    cnt = collections.Counter(); end = time.time() + secs
    while time.time() < end:
        try: d, _ = s.recvfrom(2048)
        except socket.timeout: continue
        cnt[struct.unpack('!II', d[:8])[0]] += 1
    for k in sorted(cnt): print('STEP', k, cnt[k], flush=True)
else:
    host, port, gap, sizes = sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), [int(x) for x in sys.argv[5].split(',')]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 << 20)
    pad = b'x' * 1192
    for step, kb in enumerate(sizes):
        time.sleep(gap)
        n = max(1, kb * 1024 // 1200); t0 = time.time()
        for i in range(n): s.sendto(struct.pack('!II', step, i) + pad, (host, port))
        print('SENT', step, n, round((time.time() - t0) * 1000, 2), flush=True)
'''


def main():
    if len(sys.argv) < 5: raise SystemExit(__doc__)
    hs = H.load(); S, C = hs[sys.argv[1]], hs[sys.argv[2]]
    port = int(sys.argv[3]); sizes = [int(x) for x in sys.argv[4].split(',')]
    gap = float(sys.argv[5]) if len(sys.argv) > 5 else 4
    path = lambda h: f"{h['base']}/{H.REMOTE_DIR}/burst_probe_agent.py"
    for h in (S, C): R.ssh(h, f"mkdir -p {h['base']}/{H.REMOTE_DIR} && printf %s {R.q(AGENT)} > {path(h)}")
    total = len(sizes) * (gap + 1) + 90       # the sender's ssh login can take tens of seconds
    for attempt in range(4):        # a public sshd drops some logins (MaxStartups): retry like rnlib.ssh
        rp = subprocess.Popen(R.SSH + [C['ssh'], f'python3 {path(C)} recv {port} {total}'],
                              stdout=subprocess.PIPE, text=True)
        if rp.stdout.readline().strip() == 'READY': break
        rp.wait(); time.sleep(3 + 5 * attempt)
    else: raise SystemExit('receiver did not start')
    out = R.ssh(S, f"python3 {path(S)} send {C['ip']} {port} {gap} {','.join(map(str, sizes))}", timeout=total + 60).stdout.decode()
    sent = {int(l.split()[1]): (int(l.split()[2]), float(l.split()[3])) for l in out.splitlines() if l.startswith('SENT')}
    got = {int(l.split()[1]): int(l.split()[2]) for l in rp.communicate()[0].splitlines() if l.startswith('STEP')}
    for i, kb in enumerate(sizes):
        n, ms = sent.get(i, (0, 0)); g = got.get(i, 0)
        print(f"{S['name']}>{C['name']} burst {kb:5d} KB in {ms:7.2f} ms: sent {n:5d} received {g:5d} "
              f"({g * 1200 // 1024:5d} KB) loss {100 * (1 - g / max(1, n)):6.2f}%")


if __name__ == '__main__':
    main()
