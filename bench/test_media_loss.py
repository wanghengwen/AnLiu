#!/usr/bin/env python3
"""End-to-end auto-FEC regression; pass an ASan-built media_loss executable.

Checks delivery and wire cost, not the estimator's formula. All configured
random loss is at most 20%. Three seeds cover each scenario independently.
"""
import argparse
import os
import pathlib
import subprocess


def fields(line):
    return dict(item.split("=", 1) for item in line.split()[1:])


def run(binary, output, rtt, loss, seed, stop=0):
    args = [str(binary), "5000", str(rtt), str(loss), str(seed), "120", str(stop)]
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    name = f"rtt{rtt}-loss{loss}-seed{seed}-stop{stop}"
    if output:
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
    lines = result.stdout.splitlines()
    flow = [fields(line) for line in lines if line.startswith("FLOW ")]
    total = fields(next(line for line in lines if line.startswith("TOTAL ")))
    samples = [fields(line) for line in lines if line.startswith("SAMPLE ")]
    assert int(total["errors"]) == 0 and int(total["queue_drop"]) == 0, name
    for f in flow:
        assert int(f["received"]) <= int(f["sent"]), name
    audio, video = flow
    assert int(audio["ontime"]) / int(audio["sent"]) >= .995, (name, audio)
    if loss and rtt == 100:
        assert int(video["ontime"]) / int(video["sent"]) >= .98, (name, video)
        assert int(video["key_ontime"]) / int(video["keys"]) >= .98, (name, video)
        assert int(video["parity"]) <= .55 * int(video["first"]), (name, video)
        assert int(total["wire"]) * 8 / 120 <= 2200000, (name, total)
    if not loss:
        assert int(video["ontime"]) == int(video["sent"]), (name, video)
        assert all(int(s["gate"]) == 0 for s in samples), (name, samples)
        assert len({s["parity_video"] for s in samples}) == 1, (name, samples)
        assert int(video["parity"]) < 20000, (name, video)
    if rtt == 2:
        assert int(video["ontime"]) == int(video["sent"]), (name, video)
        assert int(video["parity"]) == 0, (name, video)
    if stop:
        settled = [s for s in samples if int(s["ms"]) >= (stop + 40) * 1000]
        assert settled and all(int(s["gate"]) == 0 for s in settled), name
        assert len({s["parity_video"] for s in settled}) == 1, (name, settled)
    print(f"PASS {name}: video={int(video['ontime'])/int(video['sent']):.4%} "
          f"keys={video['key_ontime']}/{video['keys']}", flush=True)


# Video fixed at the encoder level the closed loop averaged on main (01aff48)
# in the same case, key and P frames scaled alike: the transport is judged at
# an equal source rate, not through the rate controller's response to it.
LOW_FIXED_SCALE = {800: 195, 2000: 500}


def run_low(binary, output, bw, seed):
    # Six hundred seconds amortize startup and cover many key-frame bursts.
    env = dict(os.environ, MEDIA_LOSS_FIXED_SCALE=str(LOW_FIXED_SCALE[bw]))
    result = subprocess.run([str(binary), str(bw), "100", "20", str(seed), "600"],
                            capture_output=True, text=True, check=True, env=env)
    name = f"low{bw}-seed{seed}"
    if output:
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
    lines = result.stdout.splitlines()
    audio, video = [fields(line) for line in lines if line.startswith("FLOW ")]
    total = fields(next(line for line in lines if line.startswith("TOTAL ")))
    # Guard audio, useful video bytes and queue cost together. A better video
    # frame percentage obtained only by shrinking the encoder is insufficient.
    audio_min, video_min, key_min = (.955, .94, .90) if bw == 800 else (.98, .97, .975)
    generated_min, useful_min = (175000, 165000) if bw == 800 else (440000, 430000)
    wire_max = 640000 if bw == 800 else 1250000
    assert int(total["errors"]) == 0, name
    assert int(audio["ontime"]) / int(audio["sent"]) >= audio_min, (name, audio)
    assert int(video["ontime"]) / int(video["sent"]) >= video_min, (name, video)
    assert int(video["key_ontime"]) / int(video["keys"]) >= key_min, (name, video)
    assert int(video["generated_bytes"]) * 8 / 600 >= generated_min, (name, video)
    assert int(video["ontime_bytes"]) * 8 / 600 >= useful_min, (name, video)
    assert int(total["wire"]) * 8 / 600 <= wire_max, (name, total)
    assert int(total["queue_drop"]) < 1500, (name, total)
    print(f"PASS {name}: audio={int(audio['ontime'])/int(audio['sent']):.4%} "
          f"video_useful={int(video['ontime_bytes'])*8/600/1000:.1f} kbps "
          f"keys={video['key_ontime']}/{video['keys']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
    for rtt, loss, stop in [(100, 20, 0), (100, 15, 0), (2, 20, 0),
                            (100, 0, 0), (180, 0, 0), (100, 20, 30)]:
        for seed in (1, 2, 3):
            run(args.binary.resolve(), args.output, rtt, loss, seed, stop)
    for bw in (800, 2000):
        for seed in (1, 2, 3):
            run_low(args.binary.resolve(), args.output, bw, seed)


if __name__ == "__main__":
    main()
