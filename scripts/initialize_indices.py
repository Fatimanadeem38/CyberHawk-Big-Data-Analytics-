"""
Creates the Elasticsearch indices from elasticsearch/mappings/*.json
(safe to run many times; existing indices are left alone).

    docker compose run --rm init python /app/scripts/initialize_indices.py
    docker compose run --rm init python /app/scripts/initialize_indices.py --recreate   # deletes data!
"""
from __future__ import annotations
import argparse
import json
import os
import time
from pathlib import Path

from elasticsearch import Elasticsearch

MAPPINGS = Path(__file__).resolve().parents[1] / "elasticsearch" / "mappings"
INDICES = ["security-events", "threat-detections", "security-alerts", "model-metrics", "pipeline-metrics"]


def main(recreate: bool = False) -> None:
    es = Elasticsearch(os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"), request_timeout=30)
    for _ in range(40):
        try:
            if es.ping():
                break
        except Exception:
            pass
        print("[indices] waiting for Elasticsearch...")
        time.sleep(3)
    else:
        raise SystemExit("Elasticsearch not reachable")

    for name in INDICES:
        body = json.loads((MAPPINGS / f"{name}.json").read_text())
        if es.indices.exists(index=name):
            if not recreate:
                print(f"[indices] exists  {name}")
                continue
            es.indices.delete(index=name)
            print(f"[indices] deleted {name}")
        es.indices.create(index=name, settings=body["settings"], mappings=body["mappings"])
        print(f"[indices] created {name}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--recreate", action="store_true")
    main(ap.parse_args().recreate)
