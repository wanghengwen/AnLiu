#!/usr/bin/env python3
"""Package a variant and deploy it to the test hosts.

Usage: deploy.py VARIANT REV [--tools-from-rev] [HOST ...]

The library (anliu.c, anliu.h) is taken from git revision REV ("WORKTREE":
the working tree); the test tool (bench/realnet.c, ikcp, the diagnostics
headers) from the working tree, or with --tools-from-rev from REV as well
(realnet.c reaches into the library's internals, so an older library may
not build with the current tool; a header the revision lacks is left out). The variant goes to ANL_REALNET_WORK/VARIANT
(src/, deployment-manifest.json, src.tgz) and to every host (or those named)
under base/ANL_REALNET_REMOTE_DIR/VARIANT, where realnet_trace is built
(-DREALNET_INTERNAL: TRACE lines show BBR internals) and the sources are
checked against the manifest."""
import sys, json, hashlib, datetime, tarfile, subprocess as sp, concurrent.futures as cf
import hosts as H
import rnlib as R

REPO = H.Path(__file__).resolve().parents[2]
TOOL = ['bench/realnet.c', 'bench/ikcp.c', 'bench/ikcp.h', 'bench/fec_diag.h', 'bench/tx_diag.h', 'bench/anl_trace.h']


def git_file(rev, path):
    """the file at REV, None when the revision has no such file"""
    if rev == 'WORKTREE':
        f = REPO / path
        return f.read_bytes() if f.exists() else None
    r = sp.run(['git', '-C', str(REPO), 'show', f'{rev}:{path}'], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def package(variant, rev, tool_rev='WORKTREE'):
    d = H.WORK / variant; src = d / 'src'
    (src / 'bench').mkdir(parents=True, exist_ok=True)
    have = []
    for p in ['anliu.c', 'anliu.h'] + TOOL:
        data = git_file(rev if p.startswith('anliu') else tool_rev, p)
        if data is None:
            if p in ('anliu.c', 'anliu.h', 'bench/realnet.c'): raise SystemExit(f'{p} missing')
            (src / p).unlink(missing_ok=True); continue
        (src / p).write_bytes(data); have.append(p)
    files = {p: hashlib.sha256((src / p).read_bytes()).hexdigest() for p in have}
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
    args = sys.argv[1:]
    tools_from_rev = '--tools-from-rev' in args
    if tools_from_rev: args.remove('--tools-from-rev')
    variant, rev = args[0], args[1]
    hosts = H.load()
    names = args[2:] or list(hosts)
    files = package(variant, rev, rev if tools_from_rev else 'WORKTREE')
    with cf.ThreadPoolExecutor(len(names)) as ex:
        for line in ex.map(lambda n: deploy(hosts[n], variant, files), names): print(line)
