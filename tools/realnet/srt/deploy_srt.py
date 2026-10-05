#!/usr/bin/env python3
"""Copy a locally built srtnet to the test hosts: base/ANL_REALNET_REMOTE_DIR/srt/srtnet.

Usage: deploy_srt.py SRTNET_BINARY [HOST ...]
Build it statically so it runs on hosts without libsrt (see ../README.md)."""
import sys, hashlib, pathlib, concurrent.futures as cf
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import hosts as H
import rnlib as R

binary = pathlib.Path(sys.argv[1]); digest = hashlib.sha256(binary.read_bytes()).hexdigest()
hosts = H.load(); names = sys.argv[2:] or list(hosts)


def one(n):
    h = hosts[n]; d = H.remote(h, 'srt')
    R.ssh(h, f'mkdir -p {d}/logs'); R.upload(h, binary, f'{d}/srtnet')
    got = R.ssh(h, f'chmod +x {d}/srtnet && sha256sum {d}/srtnet').stdout.decode().split()[0]
    return f"{n}: {'ok' if got == digest else 'HASH MISMATCH'} {digest[:12]}"


with cf.ThreadPoolExecutor(len(names)) as ex:
    for line in ex.map(one, names): print(line)
