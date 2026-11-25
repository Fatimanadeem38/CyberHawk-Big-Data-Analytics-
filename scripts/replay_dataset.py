"""
Replay REAL UNSW-NB15 flows into Kafka from the command line
(same as the "Replay real dataset" button on the Log Ingestion page).

    docker compose run --rm generator python /app/scripts/replay_dataset.py --rows 5000 --rate 100
    docker compose run --rm generator python /app/scripts/replay_dataset.py --mode attack_enriched --rows 3000
    docker compose run --rm generator python /app/scripts/replay_dataset.py --file /app/data/datasets/unsw-nb15/UNSW-NB15_2.csv --start-row 100000
"""
from __future__ import annotations
import argparse
import logging
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kafka" / "producers"))
from producer import SecurityLogProducer  # noqa: E402
from unsw_replay import DatasetReplayer  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [replay] %(message)s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"))
    ap.add_argument("--file", default=None, help="full-format UNSW-NB15_N.csv (default: first one found)")
    ap.add_argument("--rows", type=int, default=5000)
    ap.add_argument("--rate", type=int, default=100, help="flows per second")
    ap.add_argument("--start-row", type=int, default=0)
    ap.add_argument("--mode", choices=["sequential", "attack_enriched"], default="sequential")
    ap.add_argument("--normal-fraction", type=float, default=0.05)
    a = ap.parse_args()
    r = DatasetReplayer(lambda: SecurityLogProducer(a.bootstrap, client_id="unsw-replay"), file=a.file,
                        rows=a.rows, rate=a.rate, start_row=a.start_row, mode=a.mode,
                        normal_fraction=a.normal_fraction)
    r.start()
    try:
        while r.is_alive():
            time.sleep(5)
            s = r.status()
            print(f"sent {s['rows_sent']}/{s['rows_target']} (read {s['rows_read']}) labels={s['by_label']}")
    except KeyboardInterrupt:
        r.stop()
        r.join()
    s = r.status()
    print(f"Finished: {s['status']} {s['error']}")
    sys.exit(0 if s["status"] in ("completed", "stopped") else 1)


if __name__ == "__main__":
    main()
