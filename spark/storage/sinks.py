"""
Output writers used by the streaming job.

* Elasticsearch: written from the Spark executors with foreachPartition
  (each partition opens its own client and sends a bulk request), so
  indexing work is distributed like the rest of the job.
* HDFS: Parquet (processed data) / JSON (alerts). Each micro-batch is
  written to its own folder  .../date=YYYY-MM-DD/batch_id=N  with mode
  "overwrite": if Spark re-runs a batch after a crash, the folder is
  replaced instead of duplicated. coalesce(1) keeps one file per batch,
  and storage/compact_hdfs.py merges a whole day into a few big files.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from config import settings

TS_FMT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"

EVENT_OUTPUT_COLUMNS = [
    "event_id", "event_time", "processed_at", "kafka_timestamp", "kafka_topic", "event_date",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_size", "duration",
    "request_count", "failed_logins", "event_type", "network_status", "log_source", "username",
    "is_simulated", "scenario", "true_label", "bytes_total",
    "win_conn_count", "win_failed_logins", "win_unique_dst_ports", "win_unique_dst_ips",
    "win_unique_usernames", "win_traffic_volume", "win_request_sum", "win_avg_packet_size",
    "predicted_class", "ml_probability", "attack_probability", "anomaly_score", "is_anomaly",
    "rule_category", "threat_category", "detection_methods", "severity", "severity_rank",
    "is_threat", "alert_id", "batch_id",
]

ALERT_SCRIPT = """
ctx._source.event_count += params.event_count;
if (params.last_seen.compareTo(ctx._source.last_seen) > 0) { ctx._source.last_seen = params.last_seen; }
if (params.first_seen.compareTo(ctx._source.first_seen) < 0) { ctx._source.first_seen = params.first_seen; }
if (params.severity_rank > ctx._source.severity_rank) {
  ctx._source.severity_rank = params.severity_rank; ctx._source.severity = params.severity;
}
if (params.max_anomaly_score != null && (ctx._source.max_anomaly_score == null || params.max_anomaly_score > ctx._source.max_anomaly_score)) {
  ctx._source.max_anomaly_score = params.max_anomaly_score;
}
if (params.max_ml_probability != null && (ctx._source.max_ml_probability == null || params.max_ml_probability > ctx._source.max_ml_probability)) {
  ctx._source.max_ml_probability = params.max_ml_probability;
}
for (m in params.detection_methods) { if (!ctx._source.detection_methods.contains(m)) { ctx._source.detection_methods.add(m); } }
for (x in params.sample_event_ids) { if (ctx._source.sample_event_ids.size() < 30 && !ctx._source.sample_event_ids.contains(x)) { ctx._source.sample_event_ids.add(x); } }
for (x in params.dst_ips) { if (ctx._source.dst_ips.size() < 20 && !ctx._source.dst_ips.contains(x)) { ctx._source.dst_ips.add(x); } }
for (x in params.dst_ports) { if (ctx._source.dst_ports.size() < 30 && !ctx._source.dst_ports.contains(x)) { ctx._source.dst_ports.add(x); } }
ctx._source.description = params.description;
ctx._source.updated_at = params.updated_at;
"""


def events_for_output(df: DataFrame) -> DataFrame:
    """Selects the output columns and turns timestamps into ISO strings (UTC)."""
    out = df
    for c in ("event_time", "processed_at", "kafka_timestamp"):
        out = out.withColumn(c, F.date_format(F.col(c), TS_FMT))
    for c in ("win_conn_count", "win_failed_logins", "win_unique_dst_ports", "win_unique_dst_ips",
              "win_unique_usernames", "win_traffic_volume", "win_request_sum"):
        out = out.withColumn(c, F.col(c).cast("long"))
    return out.select(*EVENT_OUTPUT_COLUMNS)


def _es_partition_writer(index: str, id_field: str):
    es_url = settings.ES_URL

    def write(rows):
        from elasticsearch import Elasticsearch, helpers  # imported on the executor

        es = Elasticsearch(es_url, request_timeout=60)

        def actions():
            for row in rows:
                doc = row.asDict(recursive=True)
                doc = {k: v for k, v in doc.items() if v is not None}
                yield {"_op_type": "index", "_index": index, "_id": doc[id_field], "_source": doc}

        for ok, info in helpers.streaming_bulk(es, actions(), chunk_size=500, max_retries=5,
                                               initial_backoff=1, raise_on_error=True):
            pass
        es.close()

    return write


def write_es(df: DataFrame, index: str, id_field: str = "event_id") -> None:
    df.foreachPartition(_es_partition_writer(index, id_field))


def write_alerts_es(alerts: DataFrame) -> None:
    """Upsert: a new alert is created with status 'new'; an existing one is updated."""
    from inference.threat_classifier import describe_alert
    es_url = settings.ES_URL
    index = settings.ES_ALERTS_INDEX

    def write(rows):
        from elasticsearch import Elasticsearch, helpers

        es = Elasticsearch(es_url, request_timeout=60)
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        def actions():
            for row in rows:
                a = row.asDict(recursive=True)
                a["description"] = describe_alert(a)
                doc = {
                    "alert_id": a["alert_id"], "dedup_key": f"{a['src_ip']}|{a['threat_category']}",
                    "src_ip": a["src_ip"], "dst_ip": a["dst_ip"], "dst_ips": a["dst_ips"] or [],
                    "dst_ports": a["dst_ports"] or [], "protocols": a["protocols"] or [],
                    "threat_category": a["threat_category"], "severity": a["severity"],
                    "severity_rank": a["severity_rank"], "detection_methods": a["detection_methods"] or [],
                    "max_anomaly_score": a["max_anomaly_score"], "max_ml_probability": a["max_ml_probability"],
                    "event_count": a["event_count"], "first_seen": a["first_seen"], "last_seen": a["last_seen"],
                    "sample_event_ids": a["sample_event_ids"] or [], "is_simulated": bool(a["is_simulated"]),
                    "description": a["description"], "status": "new", "created_at": now, "updated_at": now,
                }
                params = {k: doc[k] for k in ("event_count", "first_seen", "last_seen", "severity_rank",
                                              "severity", "max_anomaly_score", "max_ml_probability",
                                              "detection_methods", "sample_event_ids", "dst_ips",
                                              "dst_ports", "description", "updated_at")}
                yield {"_op_type": "update", "_index": index, "_id": doc["alert_id"],
                       "retry_on_conflict": 5,
                       "script": {"source": ALERT_SCRIPT, "lang": "painless", "params": params},
                       "upsert": doc}

        for _ in helpers.streaming_bulk(es, actions(), chunk_size=200, max_retries=5, initial_backoff=1):
            pass
        es.close()

    alerts.foreachPartition(write)


def write_alerts_kafka(alerts: DataFrame) -> None:
    (alerts.select(F.col("alert_id").alias("key"),
                   F.to_json(F.struct(*[c for c in alerts.columns])).alias("value"))
     .write.format("kafka")
     .option("kafka.bootstrap.servers", settings.KAFKA_BOOTSTRAP)
     .option("topic", settings.ALERT_TOPIC)
     .save())


def write_hdfs_batch(df: DataFrame, base: str, batch_id: int, fmt: str = "parquet", prefix: str = "") -> str:
    """prefix separates the batches of different streaming queries (e.g. 'unsw-')."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = f"{base}/date={day}/batch_id={prefix}{batch_id}"
    writer = df.coalesce(1).write.mode("overwrite")
    (writer.parquet(path) if fmt == "parquet" else writer.json(path))
    return path


def index_doc(index: str, doc: dict) -> None:
    """Single document write from the driver (metrics)."""
    from elasticsearch import Elasticsearch

    es = Elasticsearch(settings.ES_URL, request_timeout=20)
    try:
        es.index(index=index, document=doc)
    finally:
        es.close()
