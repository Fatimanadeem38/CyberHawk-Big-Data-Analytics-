"""
Builds the LABELLED, SIMULATED training dataset used by Spark MLlib.

It replays the same TrafficSimulator used for the live stream over
24 "virtual hours" (one 10-minute slice per hour of the day), so the
models see every hour of the day and every attack type.

    python scripts/generate_training_data.py                 # default ~150k events
    python scripts/generate_training_data.py --target 60000  # smaller / faster
Output: data/training/training_events.jsonl  (one JSON event per line)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kafka" / "producers"))
from event_factory import TrafficSimulator  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=int(os.getenv("TRAINING_EVENTS_TARGET", "150000")))
    ap.add_argument("--out", default=str(ROOT / "data" / "training" / "training_events.jsonl"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rate = 8
    # About 73% normal + 27% attack per simulated second (see stats below)
    seconds_per_hour = max(60, int(args.target / 24 / (rate * 1.45)))
    sim = TrafficSimulator(seed=args.seed, attack_probability=0.05, benign_burst_probability=0.02)
    base = datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    labels: Counter = Counter()
    total = 0
    with out.open("w", encoding="utf-8") as f:
        for hour in range(24):
            start = base + hour * 3600 + sim.rng.randint(0, 3000)
            for s in range(seconds_per_hour):
                for ev in sim.tick(start + s, rate):
                    f.write(json.dumps(ev, separators=(",", ":")) + "\n")
                    labels[ev["true_label"]] += 1
                    total += 1
            # let the remaining burst events of this slice finish
            t = start + seconds_per_hour
            while sim.pending_count:
                for ev in sim.tick(t, 0):
                    f.write(json.dumps(ev, separators=(",", ":")) + "\n")
                    labels[ev["true_label"]] += 1
                    total += 1
                t += 1

    print(f"Wrote {total} SIMULATED labelled events to {out}")
    for label, n in labels.most_common():
        print(f"  {label:22s} {n:8d}  ({100 * n / total:.1f}%)")


if __name__ == "__main__":
    main()
