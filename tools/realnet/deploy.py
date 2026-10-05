#!/usr/bin/env python3
"""Package a variant and deploy it to the test hosts.

Usage: deploy.py VARIANT REV [HOST ...]

The library (anliu.c, anliu.h) is taken from git revision REV ("WORKTREE":
the working tree); the test tool (bench/realnet.c, ikcp, the diagnostics
headers) from the working tree. The variant goes to ANL_REALNET_WORK/VARIANT
(src/, deployment-manifest.json, src.tgz) and to every host (or those named)
under base/ANL_REALNET_REMOTE_DIR/VARIANT, where realnet_trace is built
(-DREALNET_INTERNAL: TRACE lines show BBR internals) and the sources are
checked against the manifest."""
import sys, json, hashlib, datetime, tarfile, subprocess as sp, concurrent.futures as cf
import hosts as H
import rnlib as R

REPO = H.Path(__file__).resolve().parents[2]
TOOL = ['bench/realnet.c', 'bench/ikcp.c', 'bench/ikcp.h', 'bench/fec_diag.h', 'bench/tx_diag.h']


def git_file(rev, path):
    if rev == 'WORKTREE': return (REPO / path).read_bytes()
    return sp.run(['git', '-C', str(REPO), 'show', f'{rev}:{path}'], capture_output=True, check=True).stdout


def package(variant, rev):
    d = H.WORK / variant; src = d / 'src'
    (src / 'bench').mkdir(parents=True, exist_ok=True)
    for p in ('anliu.c', 'anliu.h'): (src / p).write_bytes(git_file(rev, p))
    for p in TOOL: (src / p).write_bytes((REPO / p).read_bytes())
    files = {p: hashlib.sha256((src / p).read_bytes()).hexdigest() for p in ['anliu.c', 'anliu.h'] + TOOL}
    desc = 'working tree' if rev == 'WORKTREE' else sp.run(['git', '-C', str(REPO), 'log', '-1', '--format=%h %s', rev],
                                                            capture_output=True, text=True, check=True).stdout.strip()
    (d / 'deployment-manifest.json').write_text(json.dumps(dict(revision=desc, time=datetime.datetime.now().astimezone().isoformat(),
                                                                files=files), indent=2))
    with tarfile.open(d / 'src.tgz', 'w:gz') as t: t.add(src, arcname='.')
    return files


def deploy(h, variant, files):
    rd = H.remote(h, variant)
    R.ssh(h, f'mkdir -p {rd}/src {rd}/logs')
    R.upload(h, H.WORK / variant / 'src.tgz', f'{rd}/src.tgz')
    out = R.ssh(h, f'cd {rd} && tar xzf src.tgz -C src && cd src/bench && '
                   'gcc -std=gnu99 -O2 -DREALNET_INTERNAL -I. -I.. realnet.c ikcp.c -lm -o realnet_trace && '
                   'sha256sum ../anliu.c realnet.c', timeout=300).stdout.decode().split()
    ok = out[0] == files['anliu.c'] and out[2] == files['bench/realnet.c']
    return f"{h['name']}: {'ok' if ok else 'HASH MISMATCH'} {files['anliu.c'][:12]}"


if __name__ == '__main__':
    variant, rev = sys.argv[1], sys.argv[2]
    hosts = H.load()
    names = sys.argv[3:] or list(hosts)
    files = package(variant, rev)
    with cf.ThreadPoolExecutor(len(names)) as ex:
        for line in ex.map(lambda n: deploy(hosts[n], variant, files), names): print(line)
