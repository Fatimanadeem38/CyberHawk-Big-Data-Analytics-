"""
Reliable JSON producer for the security log topics.

* JSON serialisation (UTF-8)
* idempotent producer (acks=all + enable.idempotence) -> no duplicates
  caused by producer retries
* automatic retries with back-off on temporary broker failures
* message key = source IP, so all events of one source stay in order
  inside the same partition
"""
from __future__ import annotations

import json
import logging
import time

from confluent_kafka import KafkaException, Producer

try:
    from event_factory import TOPIC_BY_SOURCE
except ImportError:  # imported as kafka.producers.producer
    from .event_factory import TOPIC_BY_SOURCE  # type: ignore

log = logging.getLogger("producer")


def topic_for(event: dict) -> str:
    return TOPIC_BY_SOURCE.get(str(event.get("log_source", "network")), "network-logs")


class SecurityLogProducer:
    def __init__(self, bootstrap_servers: str, client_id: str = "log-generator", connect_attempts: int = 30):
        self.config = {
            "bootstrap.servers": bootstrap_servers,
            "client.id": client_id,
            "acks": "all",
            "enable.idempotence": True,
            "retries": 10,
            "retry.backoff.ms": 500,
            "linger.ms": 50,
            "message.timeout.ms": 60000,
            "socket.keepalive.enable": True,
        }
        self.sent = 0
        self.failed = 0
        self.last_error = ""
        self._producer = self._connect(connect_attempts)

    def _connect(self, attempts: int = 30) -> Producer:
        for i in range(1, attempts + 1):
            try:
                p = Producer(self.config)
                p.list_topics(timeout=5)  # raises if the broker is unreachable
                log.info("Connected to Kafka at %s", self.config["bootstrap.servers"])
                return p
            except KafkaException as exc:
                log.warning("Kafka not reachable (attempt %d/%d): %s", i, attempts, exc)
                time.sleep(min(2 * i, 15))
        raise RuntimeError("Could not connect to Kafka")

    def _on_delivery(self, err, msg):
        if err is not None:
            self.failed += 1
            self.last_error = str(err)
            log.error("Delivery failed for %s: %s", msg.key(), err)
        else:
            self.sent += 1

    def send(self, event: dict, topic: str | None = None) -> None:
        topic = topic or topic_for(event)
        payload = json.dumps(event, separators=(",", ":")).encode("utf-8")
        key = str(event.get("src_ip", "")).encode("utf-8")
        while True:
            try:
                self._producer.produce(topic, value=payload, key=key, on_delivery=self._on_delivery)
                break
            except BufferError:
                # local queue full -> wait for deliveries, then try again
                self._producer.poll(0.5)
        self._producer.poll(0)

    def send_many(self, events: list[dict]) -> None:
        for ev in events:
            self.send(ev)

    def flush(self, timeout: float = 15) -> int:
        return self._producer.flush(timeout)
