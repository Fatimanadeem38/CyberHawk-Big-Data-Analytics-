# Methodology

This explains how each stage works, in simple words, with an example for each one.

## Stage 1: Log collection

**Sources:** network, firewall, authentication, server access and intrusion-detection (IDS) logs.

Every event has these fields: `event_id, timestamp, log_source, src_ip, dst_ip, src_port, dst_port, protocol (TCP/UDP/ICMP), packet_size, duration, request_count, failed_logins, event_type, network_status, username, is_simulated, scenario, true_label`.

**The simulated generator** (`kafka/producers/event_factory.py`) uses clear rules:

| Label | How it is generated (per burst) |
|---|---|
| `normal` | web, DB, DNS, logins (sometimes 1–2 failures), firewall allow/deny, mail, ping, file share |
| `brute_force` | 40–90 failed logins in 10–20 s from one IP to SSH/RDP/FTP (25% "slow" version: 15–25) |
| `port_scan` | 60–250 different ports on one host in 8–20 s, tiny packets, rejected/blocked (25% "stealth": 20–40) |
| `dos` | 100–250 events from 1–3 IPs to one service in ~10 s, 150–900 requests each, small packets |
| `suspicious_frequency` | an internal host contacting 40–80 internal hosts (lateral movement), or regular "beacon" calls to one external IP |
| `unusual_volume` | 6–15 large transfers (1.3–1.5 KB × 1,500–8,000 requests) to an external IP |
| `abnormal_auth` | one external IP logging into 15–35 *different* accounts |
| benign look-alikes (labelled `normal`) | monitoring sweeps, nightly backup transfers, "forgot my password" retries |

The look-alikes make the problem harder. A backup transfer *looks like* exfiltration, but it goes to an internal backup server.

**File upload** (`kafka/producers/normalizer.py`) accepts CSV, JSON arrays or JSON lines. It accepts common column names (e.g. `srcip`, `dsport`, `proto`, `attack_cat`). It rejects rows with invalid IPv4 addresses and fixes bad numbers. If an event has no ID, it gets a stable one, so uploading the same file twice is de-duplicated.

## Stage 2: Kafka

* 3 input topics (3 partitions each) + `security-alerts`.
* Producer: `acks=all`, `enable.idempotence=true`, 10 retries with back-off, and it waits when the local queue is full. Because of this, temporary broker problems do not lose or duplicate messages.
* Key = source IP, so the order is kept per source.

## Stage 3: Spark Structured Streaming

1. Read the 3 topics (`startingOffsets=earliest`, at most 20,000 messages per batch).
2. `from_json` with a fixed schema. Bad JSON becomes null fields and is filtered out later.
3. **De-duplication:** `withWatermark(kafka_timestamp, 10 min).dropDuplicatesWithinWatermark(event_id)`. The same event sent twice within 10 minutes is processed once.
4. `foreachBatch` every 15 s does the rest. Checkpoints are in `hdfs:///cybersecurity/checkpoints/`, so after a restart Spark continues from the last committed Kafka offsets.
5. **Cleaning:** removes rows without a time or with invalid IPs. It upper-cases the protocol (unknown → `OTHER`), sets ports outside 0–65535 to 0, replaces negative or missing numbers with defaults, and lower-cases the categories.

## Stage 4: Features

The same function (`add_behavior_features`) is used for training and streaming.

| Group | Features |
|---|---|
| Per event | packet size, duration, request count, failed logins, destination port, log(bytes) |
| Per source IP in a 10 s window | connection frequency (`win_conn_count`), failed-login frequency, average packet size, traffic volume, unique destination ports, unique destination hosts, unique usernames, request frequency, average duration, protocol distribution (TCP/UDP/ICMP ratios), failure-status ratio |
| Time | hour of day, off-hours flag |
| Context | source internal?, destination internal? |
| Categorical (one-hot) | protocol, log source, network status |

Large, skewed values (bytes, counts) use `log(1 + x)`. All numeric features are scaled with `StandardScaler`.

**Example:** a brute-force IP in one 10-second window → `win_conn_count = 60`, `win_failed_logins = 150`, `win_unique_dst_ports = 1`, `win_unique_usernames = 2`.

**No data leakage:**
* Encoders and scalers are fitted on the training split only (they are inside the saved Pipeline).
* The split is **group-based**: all events of one (source IP, time window) go to the same side. If they did not, the window features would leak information from test rows into training.
* `event_type` is **not** used as a feature, because in the simulator it almost names the label. Using it would make the model memorise words instead of learning behaviour.

## Stage 5: Machine learning (Spark MLlib)

### Model A: Random Forest Classifier (built into MLlib)
* 50 trees, depth 12, class weights (attacks are rarer than normal traffic).
* Output: `predicted_class`. `ml_probability` = share of trees voting for that class (MLlib `probability` vector). `attack_probability` = 1 − P(normal).

### Model B: KMeans distance anomaly detector (our own method)
* **Spark MLlib 3.5 has no Isolation Forest.** We train MLlib's `KMeans` (k = 8) on **normal training traffic only**.
* For each event: `distance` = distance to the nearest cluster centre.
* Threshold = 99th percentile of that distance on normal training data.
* `anomaly_score = distance ÷ threshold`. A score above 1 means "further from normal behaviour than 99% of normal events".
* This score is **not a probability**. By design, about 1% of normal events score above 1.

### Training and evaluation
* Data: about 150,000 simulated labelled events covering all 24 hours of the day.
* 80 / 20 group split. Metrics: accuracy, weighted precision/recall/F1, per-class results, confusion matrix, ROC-AUC (attack vs normal, using `attack_probability` for Model A and `anomaly_score` for Model B).
* Saved to HDFS `/cybersecurity/models/`. Metrics are saved to Elasticsearch (`model-metrics`), HDFS and `data/processed/model_metrics.json`.
* The streaming job loads the models at start-up. Retrain with `python3 scripts/train_models.py --force`.

## Stage 6: Threat classification and alerts

Three detection methods are checked for each event:

| Method | Fires when |
|---|---|
| `ml_random_forest` | predicted class ≠ normal **and** probability ≥ 0.6 |
| `anomaly_kmeans` | anomaly score ≥ 1.0 |
| `rule:<name>` | a rule in `spark/config/detection_rules.json` matches, e.g. ≥ 15 failed logins in a window → brute force |

**Category:** the ML class if ML fired, else the rule category, else `unknown_anomaly`.

**Severity** (starts from the category's base: DoS / brute force / exfiltration = high, scan / frequency / auth = medium, unknown anomaly = low):

| Agreement | Result |
|---|---|
| all 3 methods | **critical** |
| 2 methods | base + 1 level |
| only anomaly, score < 1.5 | informational |
| only ML with probability < 0.75, or only a rule | base − 1 level |

**Alert grouping / de-duplication:** `alert_id = sha256(source IP | category | 10-minute bucket)`. All events of the same attack update **one** alert. Its event count, last-seen time and highest severity are updated by an Elasticsearch upsert script. You can change the bucket size with `ALERT_DEDUP_WINDOW_MINUTES`.

**Statuses:** New → Investigating → Resolved / False Positive. These are stored in MongoDB (`AlertState`, with notes and audit log) and copied to the ES alert so you can filter by status.

## Stage 7: HDFS layout

```
/cybersecurity/
  raw-logs/year=2026/month=11/day=16/part-*.txt        original JSON messages (1 file / minute)
  processed-logs/date=2026-11-16/batch_id=42/*.parquet  cleaned + scored events
  detection-results/date=…/batch_id=…/*.parquet         events flagged by ≥ 1 method
  historical-alerts/date=…/batch_id=…/*.json            alert records per batch
  processing-metadata/date=…/flush_*/                   batch statistics (every 10 min)
  processing-metadata/model_metrics/<time>/             training metrics
  models/                                               rf_pipeline, label_indexer, anomaly_kmeans_pipeline, anomaly_meta
  training/prepared_features/                           training dataset (Parquet)
  checkpoints/raw-archive, checkpoints/threat-detection Spark recovery state
```

* Folders use `key=value` names (Hive style), so Spark can read them back with automatic partition columns.
* **Small files:** each batch writes 1 file (`coalesce(1)`), raw logs are batched per minute, and `spark/storage/compact_hdfs.py` merges a whole day into one file.
* Each batch writes with mode `overwrite` into its own `batch_id` folder. If Spark replays a batch after a crash, the folder is replaced, not duplicated.

## Stage 8: Elasticsearch

| Index | Content | Main fields |
|---|---|---|
| `security-events` | every processed event | `src_ip`/`dst_ip` (type `ip`, so CIDR search works), times, predictions, scores, window features |
| `threat-detections` | events flagged as threats | same as above |
| `security-alerts` | grouped alerts (doc id = alert_id) | severity, category, counts, first/last seen, status |
| `model-metrics` | training results | metrics, confusion matrix |
| `pipeline-metrics` | Spark progress + per-batch stats | rates, lag, durations |

All dashboard numbers come from Elasticsearch queries and aggregations (terms, date_histogram, cardinality, sum, filter, top_hits).
