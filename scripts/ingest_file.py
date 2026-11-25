"""
Publish a real or sample log file (CSV, JSON array, or JSON lines) to Kafka.

    # inside Docker (recommended)
    docker compose run --rm generator python /app/scripts/ingest_file.py /app/data/raw/sample_logs.csv --replay-now

    # from WSL with Python installed
    python scripts/ingest_file.py data/raw/sample_logs.json --bootstrap localhost:29092

Rows are validated first; invalid rows are counted and skipped.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "kafka" / "producers"))
from normalizer import normalize_record, read_records, replay_as_now  # noqa: E402
from producer import SecurityLogProducer  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"))
    ap.add_argument("--source", default="network", help="default log_source if the file has none")
    ap.add_argument("--replay-now", action="store_true", help="shift timestamps so the newest = now")
    args = ap.parse_args()

    path = Path(args.file)
    records = read_records(path.read_bytes(), path.name)
    events, errors = [], {}
    for rec in records:
        ev, err = normalize_record(rec, args.source)
        if ev:
            events.append(ev)
        else:
            errors[err] = errors.get(err, 0) + 1
    if args.replay_now:
        replay_as_now(events)

    print(f"Read {len(records)} rows: {len(events)} valid, {len(records) - len(events)} rejected")
    for reason, n in errors.items():
        print(f"  rejected {n:6d}: {reason}")
    if not events:
        return
    producer = SecurityLogProducer(args.bootstrap, client_id="file-ingest")
    producer.send_many(events)
    producer.flush(60)
    print(f"Published {producer.sent} events to Kafka ({producer.failed} failed)")


if __name__ == "__main__":
    main()
