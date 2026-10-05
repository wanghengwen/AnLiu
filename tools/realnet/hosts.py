#!/usr/bin/env python3
"""Test host table, from the JSON file that ANL_REALNET_HOSTS names (nothing
about the hosts lives in the repository). One object per host name:

  ssh    ssh destination, user@host
  ip     the address its peers send to
  base   directory under the remote home that holds the test tree
  dev    egress interface for tc ("" when the host cannot shape)
  shape  true: sudo -n tc works there, it can be a sender
  cap_kbps, slots, pool   scheduling (multi_sched_pair.py): bandwidth, at
         most this many concurrent processes, hosts sharing a machine share
         a pool name; defaults 30000 / 3 / the host's own name

ANL_REALNET_REMOTE_DIR names the test directory under base (default
anliu-realnet); ANL_REALNET_WORK the local directory with the variants and
results (default: the current directory). See hosts.example.json."""
import json, os
from pathlib import Path

WORK = Path(os.environ.get('ANL_REALNET_WORK', '.')).resolve()
REMOTE_DIR = os.environ.get('ANL_REALNET_REMOTE_DIR', 'anliu-realnet')


def load():
    path = os.environ.get('ANL_REALNET_HOSTS')
    if not path:
        raise SystemExit('set ANL_REALNET_HOSTS to the hosts JSON file (see hosts.example.json)')
    hosts = json.loads(Path(path).expanduser().read_text())
    for name, h in hosts.items():
        missing = [k for k in ('ssh', 'ip', 'base') if not h.get(k)]
        if missing:
            raise SystemExit(f'{path}: host {name} lacks {missing}')
        h.setdefault('dev', ''); h.setdefault('shape', False)
        h.setdefault('cap_kbps', 30000); h.setdefault('slots', 3); h.setdefault('pool', name)
        h['name'] = name
    return hosts


def remote(h, variant):
    """the variant's directory on host h, relative to its home"""
    return f"{h['base']}/{REMOTE_DIR}/{variant}"
