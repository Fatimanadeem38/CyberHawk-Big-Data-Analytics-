"""
Creates the Kafka topics (safe to run many times).

    docker compose run --rm init python /app/scripts/initialize_topics.py
"""
from __future__ import annotations
import os
import time

from confluent_kafka.admin import AdminClient, NewTopic

TOPICS = {
    "network-logs": 3,
    "firewall-logs": 3,
    "authentication-logs": 3,
    "security-alerts": 1,
    "dataset-flows": 3,      # real UNSW-NB15 flows replayed from the dataset files
}
RETENTION_MS = str(24 * 3600 * 1000)  # keep 24 h in Kafka (HDFS keeps the history)


def main(bootstrap: str | None = None) -> None:
    bootstrap = bootstrap or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
    admin = AdminClient({"bootstrap.servers": bootstrap})
    for attempt in range(30):
        try:
            existing = set(admin.list_topics(timeout=5).topics)
            break
        except Exception as exc:
            print(f"[topics] waiting for Kafka ({exc})")
            time.sleep(3)
    else:
        raise SystemExit("Kafka not reachable")

    partitions_default = int(os.getenv("KAFKA_TOPIC_PARTITIONS", "3"))
    new = [
        NewTopic(name, num_partitions=(p if name == "security-alerts" else partitions_default),
                 replication_factor=1, config={"retention.ms": RETENTION_MS})
        for name, p in TOPICS.items() if name not in existing
    ]
    if new:
        for name, fut in admin.create_topics(new).items():
            try:
                fut.result()
                print(f"[topics] created {name}")
            except Exception as exc:
                print(f"[topics] {name}: {exc}")
    for name in TOPICS:
        if name in existing:
            print(f"[topics] exists  {name}")
    md = admin.list_topics(timeout=5)
    for name in TOPICS:
        t = md.topics.get(name)
        print(f"[topics] {name}: {len(t.partitions) if t else 0} partition(s)")


if __name__ == "__main__":
    main()
