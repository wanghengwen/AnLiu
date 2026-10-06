"""Offline validation shared by comparison rounds and their analysis."""
import math
import re


def recommended_latency(ping_ms, delay_ms):
    """The sender's one-way netem delay adds once to the measured RTT."""
    if not math.isfinite(ping_ms) or ping_ms < 0 or delay_ms < 0:
        raise ValueError('invalid path delay')
    return max(120, math.ceil(4 * (ping_ms + delay_ms)))


def validate_lane(name, duration, sender, receiver, require_exit=True):
    """Return reasons to exclude incomplete/unhealthy runs, not quality losses.

    Historical logs lack CMP_EXIT; analysis still checks their health and
    complete source sequence. New rounds must also have successful exits.
    SRT send failures and AnLiu's intentional frame drops remain quality data.
    """
    errors = []
    if duration <= 0:
        return ['non-positive duration']
    anl = name.startswith('anl')
    for role, log in (('sender', sender), ('receiver', receiver)):
        health = re.findall(r'^HEALTH (.*)$', log, re.M)
        fields = dict(re.findall(r'(\w+)=([^\s]+)', health[-1])) if health else {}
        if fields.get('state') != '0':
            errors.append(f'{role}: missing/unhealthy completion')
        if anl:
            for key in ('input_errors', 'output_errors', 'payload_errors'):
                if fields.get(key) != '0':
                    errors.append(f'{role}: {key} missing/nonzero')
            if not re.search(r'^TIMEBASE event=traffic_start event_mono_us=\d+ .*wall_us=\d+', log, re.M):
                errors.append(f'{role}: missing timebase')
            if re.search(r'^TIMEOUT ', log, re.M):
                errors.append(f'{role}: timed out')
        end = re.findall(r'^CMP_EXIT rc=(\d+) elapsed_s=(\d+)$', log, re.M)
        if require_exit and not end:
            errors.append(f'{role}: missing process exit')
        if end and (int(end[-1][0]) != 0 or int(end[-1][1]) < duration - 1):
            errors.append(f'{role}: failed/early process exit')

    prefix = 'MDIAG_S' if anl else 'SRTS'
    seqs = {1: [], 2: []}
    for line in sender.splitlines():
        if not line.startswith(prefix + ' '):
            continue
        try:
            values = list(map(int, line.split()[1:]))
            if len(values) != (7 if anl else 6) or values[0] not in seqs or values[3] <= 0:
                raise ValueError()
            seqs[values[0]].append(values[1])
        except ValueError:
            errors.append('malformed source record')
    for fid, fps in ((1, 50), (2, 30)):
        if sorted(seqs[fid]) != list(range(duration * fps)):
            errors.append(f'flow {fid}: incomplete/duplicate source sequence')
    rprefix = 'MDIAG_R' if anl else 'SRTR'
    if not re.search(r'^' + rprefix + r' [12] ', receiver, re.M):
        errors.append('receiver: no traffic records')
    return errors
