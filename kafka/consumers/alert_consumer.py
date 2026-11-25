"""
Example Kafka consumer (consumer group "soc-alert-console").

Spark publishes every new/updated alert to the "security-alerts" topic.
This script reads them and prints a one-line summary. Run several copies
with the same --group to see Kafka spread the partitions between them.

    docker compose run --rm generator python /app/kafka/consumers/alert_consumer.py
"""
from __future__ import annotations
import argparse
import json
import os
import signal

from confluent_kafka import Consumer, KafkaError

running = True


def stop(*_):
    global running
    running = False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092"))
    ap.add_argument("--group", default="soc-alert-console")
    ap.add_argument("--from-beginning", action="store_true")
    args = ap.parse_args()

    consumer = Consumer({
        "bootstrap.servers": args.bootstrap,
        "group.id": args.group,
        "auto.offset.reset": "earliest" if args.from_beginning else "latest",
        "enable.auto.commit": False,      # commit only after the message is handled
    })
    consumer.subscribe(["security-alerts"])
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"Listening on security-alerts (group={args.group}) ... Ctrl+C to stop")
    try:
        while running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print("Kafka error:", msg.error())
                continue
            try:
                a = json.loads(msg.value())
                print(f"[{a.get('severity', '?').upper():13s}] {a.get('threat_category')} "
                      f"src={a.get('src_ip')} events={a.get('event_count')} id={a.get('alert_id')}")
            except (ValueError, TypeError):
                print("Unreadable message at offset", msg.offset())
            consumer.commit(message=msg, asynchronous=False)
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
