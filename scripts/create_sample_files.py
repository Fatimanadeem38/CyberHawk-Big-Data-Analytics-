"""
Creates small SIMULATED sample files for testing the "Upload logs" feature:
    data/raw/sample_logs.csv   and   data/raw/sample_logs.json
Each file has ~2,000 events: normal traffic plus one burst of every
simulated attack type. The true_label column is kept for reference.

    python scripts/create_sample_files.py
"""
from __future__ import annotations
import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kafka" / "producers"))
from event_factory import ATTACK_SCENARIOS, TrafficSimulator  # noqa: E402


def build(seed: int) -> list[dict]:
    sim = TrafficSimulator(seed=seed, attack_probability=0.0, benign_burst_probability=0.01)
    start = time.time() - 600
    events = []
    for s in range(150):
        forced = [ATTACK_SCENARIOS[s // 25]] if s % 25 == 5 else []
        events += sim.tick(start + s, 8, forced)
    t = start + 150
    while sim.pending_count:
        events += sim.tick(t, 0)
        t += 1
    return events


def main():
    out = ROOT / "data" / "raw"
    out.mkdir(parents=True, exist_ok=True)
    events = build(7)
    with (out / "sample_logs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(events[0].keys()))
        w.writeheader()
        w.writerows(events)
    (out / "sample_logs.json").write_text(json.dumps(build(11), indent=1), encoding="utf-8")
    print(f"Wrote {len(events)} events to {out / 'sample_logs.csv'} and sample_logs.json")


if __name__ == "__main__":
    main()
