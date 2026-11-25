# Distributed Cyber Threat Detection Using Hadoop

A web-based Security Operations Center (SOC) platform. It collects security logs, processes them as a stream with Big Data tools, finds suspicious activity with machine learning, and shows alerts on a live dashboard.

```
Log generator / file upload ──► Kafka ──► Spark Structured Streaming ──► cleaning + features
        ──► Spark MLlib (Random Forest + KMeans anomaly) ──► severity + alert grouping
        ──► HDFS (history, Parquet/JSON)  +  Elasticsearch (search)  +  Kafka "security-alerts"
        ──► Django REST API + WebSocket ──► SOC web dashboard (Bootstrap 5 + Chart.js)
```

> **Important:** the built-in generator creates **simulated** events for testing. They are marked `is_simulated = true` and shown with a purple **SIM** tag. They use reserved documentation IP ranges, so they never name real hosts. This project **detects and alerts**. It does **not** block traffic.

---

## 1. Quick start (Windows 11 + WSL2)

Full step-by-step guide: **[documentation/setup.md](documentation/setup.md)**

```bash
# in the Ubuntu (WSL) terminal, inside the project folder
cp .env.example .env          # then change the passwords in .env
docker compose up -d --build  # first run: 10–20 minutes (downloads ~5 GB of images)
docker compose ps             # wait until init + spark-train show "exited (0)"
```

Open **http://localhost:8000** and sign in:

| Role | Username | Password (change in `.env`) |
|---|---|---|
| Administrator | `admin` | `Admin@12345` |
| Security Analyst | `analyst` | `Analyst@12345` |

Then go to **Log Ingestion → Start ingestion**, or click a **Simulate attack** button.

Other web UIs: HDFS http://localhost:9870 · Spark http://localhost:4040 · Elasticsearch http://localhost:9200

## 2. Real dataset (UNSW-NB15)

The models are also trained and tested on **UNSW-NB15**, a public dataset of real captured network flows (real normal traffic plus attacks generated in a lab testbed), using the dataset's **official train/test split**. Real flows can also be replayed live through Kafka → Spark → Elasticsearch → dashboard.

```bash
# 1. download the CSVs into data/datasets/unsw-nb15/  (see documentation/real_dataset.md)
# 2. train + evaluate on the official test set (prints the results, shows them on the ML Models page)
python3 scripts/train_models.py --dataset unsw
# 3. Log Ingestion page -> "Replay real flows"
```

Full guide: **[documentation/real_dataset.md](documentation/real_dataset.md)**

## 3. What is implemented

| Stage | Status | Where |
|---|---|---|
| 1. Log collection: simulated generator (5 log sources, 6 attack types + benign look-alikes) and CSV/JSON upload | ✅ Implemented | `kafka/producers/`, `scripts/generate_logs.py`, Log Ingestion page |
| 2. Kafka: 4 topics, idempotent JSON producers, retries, consumer group example | ✅ | `scripts/initialize_topics.py`, `kafka/` |
| 3. Spark Structured Streaming: parse, validate, de-duplicate (event_id + watermark), micro-batches, HDFS checkpoints | ✅ | `spark/streaming/`, `spark/preprocessing/` |
| 4. Feature engineering, shared by training and inference | ✅ | `spark/feature_engineering/features.py` |
| 5. MLlib: **Model A** Random Forest, **Model B** KMeans distance anomaly detector (MLlib has no Isolation Forest) | ✅ | `spark/models/`, `spark/training/`, `spark/inference/` |
| Real dataset UNSW-NB15: training on the official split, TTL ablation, live replay (`dataset-flows` topic, `dataset-detection` query) | ✅ code ready, you run it after downloading the data | `spark/datasets/`, `spark/training/train_unsw_nb15.py`, `spark/streaming/dataset_job.py`, `kafka/producers/unsw_replay.py` |
| 6. Severity levels, configurable rules, alert grouping / de-duplication | ✅ | `spark/inference/threat_classifier.py`, `spark/config/detection_rules.json` |
| 7. HDFS: raw JSON, processed Parquet, detections, alerts, metadata, models, checkpoints, compaction | ✅ | `spark/storage/`, `hadoop/` |
| 8. Elasticsearch: 3 main indices + model and pipeline metrics, search and aggregations | ✅ | `elasticsearch/mappings/` |
| 9. Django + DRF: 9 apps, roles, REST APIs, MongoDB for users/workflow/notes/audit | ✅ | `backend/` |
| 10. Frontend: 11 pages, dark SOC theme | ✅ | `frontend/` |
| Real-time: Django Channels WebSocket with auto-reconnect | ✅ | `backend/dashboard/consumers.py`, `frontend/static/js/realtime.js` |
| Mobile app / PWA | ❌ Not planned (web only, as agreed) | – |
| Automatic blocking / intrusion prevention | ❌ Out of scope by design | – |
| Multi-node Hadoop / Spark cluster | ⚠️ Single-node on one laptop (see architecture notes) | `docker-compose.yml` |

## 4. Folder structure

```
distributed-cyber-threat-detection/
├── docker-compose.yml            all services (memory-limited for a 12 GB laptop)
├── .env.example                  settings and passwords (copy to .env)
├── backend/                      Django project
│   ├── config/                   settings, URLs, ASGI (HTTP + WebSocket)
│   ├── core/                     Elasticsearch helper, permissions, audit helper
│   ├── accounts/                 login, roles, audit log, bootstrap_roles command
│   ├── dashboard/                KPIs + WebSocket consumer
│   ├── security_events/          live + historical event search, CSV export, IP profile
│   ├── threat_detection/         detections + ML model metrics
│   ├── alerts/                   alert workflow (status, assignee, notes)
│   ├── analytics/                network analytics aggregations
│   ├── system_monitoring/        real health checks of every service
│   └── ingestion/                generator control, attack simulation, file upload
├── frontend/templates + static/  HTML pages, CSS theme, one JS file per page
├── kafka/producers               event factory, normaliser, reliable producer
├── kafka/consumers               example consumer group for security-alerts
├── spark/                        config, preprocessing, features, models, training, inference, streaming, storage
├── hadoop/                       HDFS config + WebHDFS helper
├── elasticsearch/                index mappings + example queries
├── scripts/                      init, generate, ingest, train, verify, purge
├── data/raw                      sample upload files (simulated)
├── docker/                       Dockerfiles
└── documentation/                setup, architecture, methodology, testing, API
```

## 5. Documentation

* [Setup guide (Windows 11, PowerShell + WSL2)](documentation/setup.md)
* [Real dataset: UNSW-NB15 (download, train, replay, what to report)](documentation/real_dataset.md)
* [Architecture and data flow](documentation/architecture.md)
* [Methodology: features, models, severity](documentation/methodology.md)
* [Testing procedure (Tests 1–9)](documentation/testing.md)
* [REST API reference](documentation/api.md)

## 6. Honest notes

* The **simulated-data** model scores are close to 100% because the patterns are rule-generated. Report the **UNSW-NB15** results (official test set, with and without TTL features) instead.
* UNSW-NB15's normal traffic is real, but its attacks were generated in a lab testbed.
* Anomaly scores are **distance ÷ threshold**, not probabilities. The "model probability" is the Random Forest's tree-vote share.
* Behaviour features are counted per source IP inside 10-second windows *within each micro-batch*. A window that crosses two batches is counted in two parts.
* Everything runs on one machine (local Spark, 1 NameNode + 1 DataNode, 1 Kafka broker, 1 Elasticsearch node). The code works the same on a real cluster: you change the addresses in `.env` and `SPARK_MASTER`.
* Elasticsearch security (passwords/TLS) is turned off for local development. Turn it on before using this on a shared network.
