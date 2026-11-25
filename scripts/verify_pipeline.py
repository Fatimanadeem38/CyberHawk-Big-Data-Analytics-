"""
End-to-end check: is data really flowing through every component?

    docker compose run --rm init python /app/scripts/verify_pipeline.py

Checks
  1. Kafka      - messages exist in the input topics and in security-alerts
  2. HDFS       - files exist in raw-logs, processed-logs, detection-results, historical-alerts
  3. Elasticsearch - documents exist in every index; newest event age
  4. Models     - trained models exist in HDFS and metrics in Elasticsearch
Prints PASS / WARN / FAIL for each line.
"""
from __future__ import annotations
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from confluent_kafka import Consumer, TopicPartition
from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hadoop" / "storage"))
import webhdfs  # noqa: E402

results = []


def report(status, check, detail):
    results.append(status)
    color = {"PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m"}[status]
    print(f"{color}{status:4s}\033[0m  {check:45s} {detail}")


def kafka_checks():
    try:
        c = Consumer({"bootstrap.servers": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"),
                      "group.id": "verify-pipeline"})
        md = c.list_topics(timeout=5)
        for topic in ["network-logs", "firewall-logs", "authentication-logs", "dataset-flows", "security-alerts"]:
            t = md.topics.get(topic)
            if not t:
                report("FAIL", f"Kafka topic {topic}", "missing")
                continue
            total = sum(c.get_watermark_offsets(TopicPartition(topic, p), timeout=5)[1] for p in t.partitions)
            report("PASS" if total else "WARN", f"Kafka topic {topic}", f"{len(t.partitions)} partitions, {total} messages produced")
        c.close()
    except Exception as exc:
        report("FAIL", "Kafka reachable", str(exc))


def hdfs_checks():
    if not webhdfs.namenode_ready():
        report("FAIL", "HDFS NameNode + DataNode", "not ready")
        return
    for folder in ["raw-logs", "processed-logs", "detection-results", "historical-alerts", "models", "checkpoints"]:
        cs = webhdfs.content_summary(f"/cybersecurity/{folder}")
        files, size = cs.get("fileCount", 0), cs.get("length", 0)
        report("PASS" if files else "WARN", f"HDFS /cybersecurity/{folder}", f"{files} files, {size / 1e6:.2f} MB")
    days = [s["pathSuffix"] for s in webhdfs.list_status("/cybersecurity/processed-logs")]
    if days:
        print(f"      processed-logs date folders: {', '.join(days[-5:])}")


def es_checks():
    try:
        es = Elasticsearch(os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"), request_timeout=10)
        for idx in ["security-events", "threat-detections", "security-alerts", "model-metrics", "pipeline-metrics"]:
            n = es.count(index=idx)["count"] if es.indices.exists(index=idx) else -1
            report("PASS" if n > 0 else ("FAIL" if n < 0 else "WARN"), f"Elasticsearch index {idx}",
                   "missing" if n < 0 else f"{n} documents")
        r = es.search(index="security-events", size=1, sort=[{"processed_at": "desc"}])
        if r["hits"]["hits"]:
            last = r["hits"]["hits"][0]["_source"]["processed_at"]
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds()
            report("PASS" if age < 120 else "WARN", "Newest processed event", f"{last} ({int(age)} s ago)")
        a = es.search(index="security-alerts", size=3, sort=[{"last_seen": "desc"}])
        for h in a["hits"]["hits"]:
            s = h["_source"]
            print(f"      alert {s['alert_id']}: {s['severity']:8s} {s['threat_category']:20s} src={s['src_ip']} "
                  f"events={s['event_count']} status={s['status']}")
    except Exception as exc:
        report("FAIL", "Elasticsearch reachable", str(exc))


if __name__ == "__main__":
    print("== Kafka ==")
    kafka_checks()
    print("== HDFS ==")
    hdfs_checks()
    print("== Elasticsearch ==")
    es_checks()
    fails, warns = results.count("FAIL"), results.count("WARN")
    print(f"\nSummary: {results.count('PASS')} pass, {warns} warn, {fails} fail")
    print("WARN usually means 'no data yet' - start ingestion and wait 1-2 minutes.")
    sys.exit(1 if fails else 0)
