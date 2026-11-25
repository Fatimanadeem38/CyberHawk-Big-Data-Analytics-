"""
Free disk space: delete events older than N days from Elasticsearch and
date folders older than N days from HDFS. Alerts are kept.

    docker compose run --rm init python /app/scripts/purge_old_data.py --days 3
    docker compose run --rm init python /app/scripts/purge_old_data.py --days 3 --dry-run
"""
from __future__ import annotations
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hadoop" / "storage"))
import webhdfs  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    cutoff = datetime.now(timezone.utc) - timedelta(days=a.days)
    es = Elasticsearch(os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"), request_timeout=120)

    for idx, field in [("security-events", "processed_at"), ("threat-detections", "processed_at"),
                       ("pipeline-metrics", "timestamp")]:
        q = {"range": {field: {"lt": f"now-{a.days}d"}}}
        n = es.count(index=idx, query=q)["count"]
        print(f"[es] {idx}: {n} documents older than {a.days} days")
        if n and not a.dry_run:
            es.delete_by_query(index=idx, query=q, conflicts="proceed", wait_for_completion=True)

    for folder in ["processed-logs", "detection-results", "historical-alerts", "processing-metadata"]:
        for st in webhdfs.list_status(f"/cybersecurity/{folder}"):
            name = st["pathSuffix"]
            if name.startswith("date="):
                day = datetime.strptime(name[5:], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if day < cutoff:
                    print(f"[hdfs] delete /cybersecurity/{folder}/{name}")
                    if not a.dry_run:
                        webhdfs.delete(f"/cybersecurity/{folder}/{name}")
    # raw logs: year=YYYY/month=MM/day=DD
    for y in webhdfs.list_status("/cybersecurity/raw-logs"):
        if not y["pathSuffix"].startswith("year="):
            continue
        for m in webhdfs.list_status(f"/cybersecurity/raw-logs/{y['pathSuffix']}"):
            for d in webhdfs.list_status(f"/cybersecurity/raw-logs/{y['pathSuffix']}/{m['pathSuffix']}"):
                try:
                    day = datetime(int(y["pathSuffix"][5:]), int(m["pathSuffix"][6:]), int(d["pathSuffix"][4:]),
                                   tzinfo=timezone.utc)
                except ValueError:
                    continue
                if day < cutoff:
                    path = f"/cybersecurity/raw-logs/{y['pathSuffix']}/{m['pathSuffix']}/{d['pathSuffix']}"
                    print(f"[hdfs] delete {path}")
                    if not a.dry_run:
                        webhdfs.delete(path)
    print("done" + (" (dry run, nothing deleted)" if a.dry_run else ""))


if __name__ == "__main__":
    main()
