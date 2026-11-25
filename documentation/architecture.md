# Architecture

## 1. Big picture

```
 ┌────────────────────┐   JSON    ┌──────────────────────────────┐
 │ Log generator      │──────────►│ Apache Kafka 3.7 (KRaft)     │
 │ (simulated, 5 log  │           │ network-logs     (3 parts)   │
 │  sources) / file   │           │ firewall-logs    (3 parts)   │
 │  upload (CSV/JSON) │           │ authentication-logs (3 parts)│
 └────────────────────┘           └──────────────┬───────────────┘
                                                 │ readStream
                                ┌────────────────▼─────────────────────────────┐
                                │ Spark 3.5 Structured Streaming               │
                                │  Q1 raw-archive ───────────────► HDFS raw    │
                                │  Q2 threat-detection (every 15 s):           │
                                │   parse → dedupe → clean → features          │
                                │   → Model A (Random Forest)                  │
                                │   → Model B (KMeans anomaly)                 │
                                │   → rules → severity → alert grouping        │
                                └───┬───────────────┬───────────────┬──────────┘
                                    │               │               │
                   ┌────────────────▼──┐  ┌─────────▼────────┐  ┌───▼──────────────┐
                   │ Hadoop HDFS 3.3.6 │  │ Elasticsearch 8  │  │ Kafka topic      │
                   │ Parquet + JSON    │  │ events, threats, │  │ security-alerts  │
                   │ history, models,  │  │ alerts, metrics  │  │ (alert consumer) │
                   │ checkpoints       │  └─────────┬────────┘  └──────────────────┘
                   └───────────────────┘            │ queries + aggregations
                                         ┌──────────▼───────────┐   ┌──────────────┐
                                         │ Django 5 + DRF        │◄─►│ MongoDB 7    │
                                         │ + Channels (Daphne)   │   │ users, roles,│
                                         └──────────┬───────────┘   │ workflow,    │
                                       REST + WebSocket             │ notes, audit │
                                         ┌──────────▼───────────┐   └──────────────┘
                                         │ SOC dashboard        │
                                         │ Bootstrap 5, Chart.js│
                                         └──────────────────────┘
```

## 2. Data flow, step by step

| # | From → To | What moves | How |
|---|---|---|---|
| 1 | Generator → Kafka | one JSON event per message, key = source IP | `confluent-kafka` idempotent producer (`acks=all`, retries) |
| 2 | Kafka → Spark | micro-batches of up to 20,000 messages | Structured Streaming Kafka source; offsets kept in the HDFS checkpoint |
| 3 | Spark → HDFS (raw) | original messages, unchanged | query `raw-archive`, text files, `year=/month=/day=` folders, 1 file per minute |
| 4 | Spark (inside the batch) | parsing, de-duplication, cleaning, features, 2 models, rules, severity | `foreachBatch` |
| 5 | Spark → HDFS | processed events, detections (Parquet), alerts (JSON), metadata | one folder per batch: `date=YYYY-MM-DD/batch_id=N` |
| 6 | Spark → Elasticsearch | every processed event; detections; alerts (upsert) | bulk API from the Spark executors (`foreachPartition`) |
| 7 | Spark → Kafka | alerts | `security-alerts` topic |
| 8 | Elasticsearch → Django | search results, counts, aggregations | `elasticsearch-py` 8 |
| 9 | Django → browser | page data | REST (`/api/...`) |
| 10 | Django → browser (live) | new events, new/updated alerts, KPIs every ~2–6 s | WebSocket `/ws/stream/` (Django Channels) |
| 11 | Browser → Django → MongoDB + ES | alert status, notes, assignee | REST PATCH/POST, also written back to the ES alert |
| 12 | Django → generator | ON/OFF switch, rate, "simulate attack", "replay real dataset" | generator polls `/api/ingestion/service/control/` with a service token |
| 13 | UNSW-NB15 file → Kafka `dataset-flows` → Spark query `dataset-detection` | real flows scored by the UNSW-NB15 models | same storage and dashboard path as steps 5–10 (see real_dataset.md) |

## 3. Software versions

| Component | Version | Docker image | Notes |
|---|---|---|---|
| Apache Kafka | 3.7.0 | `apache/kafka:3.7.0` | KRaft mode (no ZooKeeper) |
| Apache Spark + MLlib | 3.5.1 (Scala 2.12) | `apache/spark:3.5.1-python3` + Kafka connector jars | `dropDuplicatesWithinWatermark` needs Spark ≥ 3.5 |
| Spark–Kafka connector | spark-sql-kafka-0-10_2.12:3.5.1, kafka-clients 3.4.1 | downloaded at image build | must match the Spark version |
| Apache Hadoop HDFS | 3.3.6 | `apache/hadoop:3.3.6` | Spark 3.5 ships the Hadoop 3.3 client |
| Elasticsearch | 8.13.4 | `docker.elastic.co/elasticsearch/elasticsearch:8.13.4` | security off for local use |
| MongoDB | 7.0 | `mongo:7.0` | Django connects with `django-mongodb-backend` (official MongoDB backend for Django 5.2) |
| Python (web) | 3.11 | `python:3.11-slim` | |
| Django / DRF / Channels / Daphne | 5.0 / 3.15 / 4.1 / 4.1 | pip | |
| elasticsearch-py | 8.13 | pip | client major version = server major version |
| Bootstrap / Chart.js / Bootstrap Icons | 5.3.3 / 4.4.1 / 1.11.3 | CDN | |

**Compatibility rules:** the Spark Kafka connector must match Spark (3.5.1). The Elasticsearch Python client must have the same major version as the server (8). Spark 3.5 needs Java 8/11/17 (included in the image).

## 4. Ports

| Port | Service |
|---|---|
| 8000 | Web dashboard (Django/Daphne) |
| 9870 | HDFS NameNode web UI + WebHDFS |
| 4040 | Spark UI (Structured Streaming tab) |
| 9200 | Elasticsearch (bound to 127.0.0.1 only) |
| 29092 | Kafka for tools running on the host |

## 5. Memory plan (12 GB laptop, WSL limited to 8 GB)

| Service | Limit |
|---|---|
| Kafka | 900 MB (heap 512 MB) |
| NameNode / DataNode | 640 MB each (heap 384 MB) |
| Elasticsearch | 1.3 GB (heap 512 MB) |
| MongoDB | 512 MB (WiredTiger cache 0.25 GB) |
| Spark streaming | 2.2 GB (driver 1.2 GB, `local[2]`) |
| Spark training (runs once, before streaming) | 3 GB |
| Django | 450 MB |
| Generator | 192 MB |
| **Steady state total** | **≈ 6.5 GB** |

## 6. Why "distributed" on one laptop?

Every component is a real distributed system, running here with the smallest size (1 broker, 1 NameNode + 1 DataNode, Spark `local[2]` with 2 parallel tasks, 1 ES node). The design is the same as on a cluster:

* Kafka topics are **partitioned** (3 partitions), and events of one source IP stay in one partition.
* Spark processes partitions **in parallel tasks**, and Elasticsearch indexing happens on the executors (`foreachPartition`).
* HDFS stores blocks on DataNodes. With more DataNodes you raise `dfs.replication`.
* To use a real cluster, change `SPARK_MASTER` (e.g. `spark://master:7077`) and the service addresses in `.env`. The code stays the same.

## 7. Responsibilities of the stores

| Store | Holds | Why there |
|---|---|---|
| **HDFS** | raw messages, processed events, detections, alerts history, models, checkpoints, metadata | cheap, append-only, long-term history and recovery |
| **Elasticsearch** | searchable events, detections, alerts, model + pipeline metrics | fast search, filters, aggregations for the dashboard |
| **MongoDB** | users, roles, alert workflow (status/assignee/resolution), notes, audit log, ingestion settings, upload history | application data (one collection per Django model, ObjectId keys) |
| **Kafka** | the last 24 h of messages | buffer between producers and Spark; replay after failure |

MongoDB is **not** used to search events. All event search goes to Elasticsearch.
