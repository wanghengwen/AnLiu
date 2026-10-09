#!/usr/bin/env python3
"""Collect paired media regressions without conflating percentage and payload.

Use --baseline and --candidate together for a before/after comparison. Steady
cases run 600 virtual seconds by default; --quick uses 120. Event cases always
run 120 seconds, including a 20-second delivery pause or delay change. Random
loss never exceeds 15%; a pause retains datagrams instead of discarding them.
The original test_media_loss.py assertions remain a separate acceptance gate.
"""
import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import subprocess


def fields(line):
    return dict(part.split("=", 1) for part in line.split()[1:])


def cases(quick):
    duration = 120 if quick else 600
    for seed in (1, 2, 3):
        for bw in (800, 2000):
            for rtt in (2, 100, 180):
                yield (bw, rtt, 15, seed, duration, 0, 10, "none", 30, 20, 200)
        for rtt, loss, stop in ((100, 15, 0), (180, 15, 0), (100, 0, 0),
                                (180, 0, 0), (2, 15, 0), (100, 15, 30)):
            yield (5000, rtt, loss, seed, duration, stop, 10, "none", 30, 20, 200)
        for event in ("pause", "delay"):
            yield (5000, 180, 15, seed, 120, 0, 10, event, 30, 20, 200)


def collect(binary, output, case):
    label = "-".join(map(str, case))
    result = subprocess.run([str(binary), *map(str, case)], capture_output=True,
                            text=True, timeout=180)
    log = result.stdout + result.stderr
    (output / (label + ".log")).write_text(log)
    assert result.returncode == 0, (label, result.returncode, result.stderr)
    lines = result.stdout.splitlines()
    config = fields(next(line for line in lines if line.startswith("CONFIG ")))
    flow = [fields(line) for line in lines if line.startswith("FLOW ")]
    total = fields(next(line for line in lines if line.startswith("TOTAL ")))
    assert int(total["errors"]) == 0 and len(flow) == 2, label
    assert int(config["interval"]) == case[6], (label, config)
    row = {"case": list(case), "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
           "wire_kbps": int(total["wire"]) * 8 / case[4] / 1000,
           "queue_drops": int(total["queue_drop"]), "flows": []}
    for f in flow:
        generated = int(f["sent"])
        assert int(f["received"]) <= generated, (label, f)
        row["flows"].append({
            "ontime_pct": int(f["ontime"]) * 100 / generated,
            "key_ontime": int(f["key_ontime"]), "keys": int(f["keys"]),
            "generated_kbps": int(f["generated_bytes"]) * 8 / case[4] / 1000,
            "timely_kbps": int(f["ontime_bytes"]) * 8 / case[4] / 1000,
            "first_bytes": int(f["first"]), "retry_bytes": int(f["retry"]),
            "parity_bytes": int(f["parity"]),
        })
    row["recovery"] = [fields(line) for line in lines if line.startswith("RECOVERY ")]
    windows = [fields(line) for line in lines if line.startswith("WINDOW ")]
    if case[7] != "none":
        row["settled"] = []
        for fid in range(2):
            selected = [w for w in windows if int(w["id"]) == fid and 60 <= int(w["sec"]) < 110]
            sent = sum(int(w["sent"]) for w in selected)
            row["settled"].append({
                "ontime_pct": sum(int(w["ontime"]) for w in selected) * 100 / sent,
                "timely_kbps": sum(int(w["ontime_bytes"]) for w in selected) * 8 / 50 / 1000,
                "key_ontime": sum(int(w["key_ontime"]) for w in selected),
            })
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--candidate", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--check-recovery", action="store_true", help="require bounded recovery and useful media after the pause")
    parser.add_argument("--jobs", type=int, default=3)
    args = parser.parse_args()
    if not args.baseline and not args.candidate:
        parser.error("provide a baseline or candidate executable")
    if args.jobs < 1 or args.jobs > 6:
        parser.error("jobs must be between 1 and 6")
    matrix = list(cases(args.quick))
    results = {}
    args.output.mkdir(parents=True, exist_ok=True)
    for name, binary in (("baseline", args.baseline), ("candidate", args.candidate)):
        if not binary:
            continue
        destination = args.output / name
        destination.mkdir(parents=True, exist_ok=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(lambda c: collect(binary.resolve(), destination, c), matrix))
        results[name] = rows
        (args.output / (name + ".json")).write_text(json.dumps(rows, indent=2) + "\n")
        print(f"{name}: {len(rows)} cases collected", flush=True)
        if name == "candidate" and args.check_recovery:
            for row in rows:
                if row["case"][7] != "pause":
                    continue
                recovery = row["recovery"]
                assert 0 <= int(recovery[0]["ontime_ms"]) <= 3000, row
                assert 0 <= int(recovery[1]["key_ms"]) <= 2000, row
                assert row["settled"][0]["ontime_pct"] >= 95, row
                assert row["settled"][1]["timely_kbps"] >= 800, row
                assert row["settled"][1]["key_ontime"] >= 47, row
            print("PASS recovery: bounded first audio/key frame and sustained payload", flush=True)
    if len(results) == 2:
        comparisons = []
        for old, new in zip(results["baseline"], results["candidate"]):
            assert old["case"] == new["case"]
            comparisons.append({"case": old["case"],
                "audio_delta_pp": new["flows"][0]["ontime_pct"] - old["flows"][0]["ontime_pct"],
                "video_delta_pp": new["flows"][1]["ontime_pct"] - old["flows"][1]["ontime_pct"],
                "useful_video_delta_kbps": new["flows"][1]["timely_kbps"] - old["flows"][1]["timely_kbps"],
                "key_delta": new["flows"][1]["key_ontime"] - old["flows"][1]["key_ontime"],
                "wire_delta_kbps": new["wire_kbps"] - old["wire_kbps"]})
        (args.output / "comparison.json").write_text(json.dumps(comparisons, indent=2) + "\n")
        print("paired differences recorded; run original assertions separately", flush=True)


if __name__ == "__main__":
    main()
