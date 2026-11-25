# Kafka topics

| Topic | Partitions | Producer | Consumer(s) | Content |
|---|---|---|---|---|
| `network-logs` | 3 | log generator / file upload | Spark Structured Streaming | network, server access and IDS events |
| `firewall-logs` | 3 | log generator / file upload | Spark Structured Streaming | firewall allow/deny events |
| `authentication-logs` | 3 | log generator / file upload | Spark Structured Streaming | login events |
| `security-alerts` | 1 | Spark (alert engine) | `kafka/consumers/alert_consumer.py` (group `soc-alert-console`) | grouped alerts |

* Serialization: JSON (UTF-8). Message key = source IP, so one source's events stay in order inside one partition.
* Producer: `acks=all` + `enable.idempotence=true` + retries, so a retry after a network problem does not write the same message twice.
* Retention: 24 hours (HDFS keeps the long-term history). This keeps disk use low.
* Spark does not use a Kafka consumer group. It stores its Kafka offsets in its **checkpoint folder in HDFS** (`/cybersecurity/checkpoints/...`). That is how it continues from the right place after a restart.
* Created by `scripts/initialize_topics.py` (auto-created when the `init` container runs).
