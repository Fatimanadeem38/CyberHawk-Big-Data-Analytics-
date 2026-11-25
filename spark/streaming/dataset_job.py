"""
Streaming query #3 "dataset-detection": scores REAL UNSW-NB15 flows.

Kafka topic dataset-flows -> parse -> de-duplicate -> prepare (same function as
training) -> UNSW-NB15 Random Forest + KMeans anomaly -> severity + alert
grouping -> HDFS + Elasticsearch (same indices as the simulated pipeline,
with log_source = "unsw_nb15" and is_simulated = false) + Kafka security-alerts.

It only starts if the UNSW-NB15 models exist in HDFS
(python3 scripts/train_models.py --dataset unsw).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (BooleanType, DoubleType, LongType, StringType, StructField,
                               StructType)

from config import settings
from datasets import unsw_nb15 as unsw
from inference.detector import UNSW_MODELS, ThreatDetector, models_exist
from inference.threat_classifier import build_alerts, classify_threats
from preprocessing.parsing import IPV4_REGEX
from storage import sinks

SCHEMA = StructType(
    [StructField("event_id", StringType()), StructField("timestamp", StringType()),
     StructField("log_source", StringType()), StructField("is_simulated", BooleanType()),
     StructField("dataset_file", StringType()), StructField("dataset_row", LongType()),
     StructField("src_ip", StringType()), StructField("dst_ip", StringType()),
     StructField("src_port", LongType()), StructField("dst_port", LongType()),
     StructField("proto", StringType()), StructField("service", StringType()),
     StructField("state", StringType()), StructField("true_label", StringType()),
     StructField("orig_stime", DoubleType())]
    + [StructField(c, DoubleType()) for c in unsw.NUMERIC])

WIN_COLS = ["win_conn_count", "win_failed_logins", "win_unique_dst_ports", "win_unique_dst_ips",
            "win_unique_usernames", "win_traffic_volume", "win_request_sum", "win_avg_packet_size"]


def _to_event_schema(df: DataFrame) -> DataFrame:
    """Map UNSW flow fields onto the platform's event fields used by the dashboard."""
    proto = F.upper(F.col("proto"))
    df = (df.withColumn("protocol", F.when(proto.isin("TCP", "UDP", "ICMP"), proto).otherwise(F.lit("OTHER")))
            .withColumn("packet_size", F.round("smean").cast("long"))
            .withColumn("duration", F.col("dur"))
            .withColumn("request_count", (F.col("spkts") + F.col("dpkts")).cast("long"))
            .withColumn("failed_logins", F.lit(0).cast("long"))
            .withColumn("event_type", F.col("service"))
            .withColumn("network_status", F.col("state"))
            .withColumn("username", F.lit(""))
            .withColumn("scenario", F.concat(F.lit("unsw_nb15:"), F.coalesce(F.col("dataset_file"), F.lit(""))))
            .withColumn("bytes_total", (F.col("sbytes") + F.col("dbytes")).cast("long"))
            .withColumn("event_date", F.date_format("event_time", "yyyy-MM-dd"))
            .withColumn("src_port", F.col("src_port").cast("int"))
            .withColumn("dst_port", F.col("dst_port").cast("int")))
    for c in WIN_COLS:   # window features do not exist for dataset flows
        df = df.withColumn(c, F.lit(None).cast("double"))
    return df


def make_processor(spark: SparkSession, detector: ThreatDetector, rules: dict):
    def process(batch_df: DataFrame, batch_id: int) -> None:
        if batch_df.isEmpty():
            return
        started = time.time()
        batch_df = batch_df.persist()
        try:
            total_in = batch_df.count()
            # archive the original messages of this batch (JSON text) in HDFS
            batch_df.select(F.col("value_str").alias("value")).coalesce(1).write.mode("overwrite") \
                .text(f"{settings.HDFS_DATASETS}/replayed-raw/date={datetime.now(timezone.utc):%Y-%m-%d}/batch_id={batch_id}")
            valid = batch_df.filter(F.col("event_time").isNotNull() & F.col("src_ip").rlike(IPV4_REGEX)
                                    & F.col("dst_ip").rlike(IPV4_REGEX))
            scored = detector.score(unsw.prepare(valid))
            classified = (classify_threats(_to_event_schema(scored), rules)
                          .withColumn("processed_at", F.current_timestamp())
                          .withColumn("batch_id", F.lit(batch_id).cast("long")))
            out = sinks.events_for_output(classified).persist()
            n_events = out.count()
            sinks.write_hdfs_batch(out, settings.HDFS_PROCESSED, batch_id, prefix="unsw-")
            sinks.write_es(out, settings.ES_EVENTS_INDEX)
            threats = out.filter(F.col("is_threat")).persist()
            n_threats, n_alerts = threats.count(), 0
            if n_threats:
                sinks.write_hdfs_batch(threats, settings.HDFS_DETECTIONS, batch_id, prefix="unsw-")
                sinks.write_es(threats, settings.ES_DETECTIONS_INDEX)
                alerts = build_alerts(threats).persist()
                n_alerts = alerts.count()
                if n_alerts:
                    sinks.write_alerts_es(alerts)
                    sinks.write_alerts_kafka(alerts)
                    sinks.write_hdfs_batch(alerts, settings.HDFS_ALERTS, batch_id, fmt="json", prefix="unsw-")
                alerts.unpersist()
            threats.unpersist()
            out.unpersist()
            meta = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                    "query_name": "dataset-detection-batch", "batch_id": batch_id, "num_input_rows": total_in,
                    "invalid_rows": total_in - n_events, "threats_in_batch": n_threats, "alerts_in_batch": n_alerts,
                    "batch_duration_ms": int((time.time() - started) * 1000), "status": "ok",
                    "message": f"UNSW-NB15 model {detector.model_version}"}
            sinks.index_doc(settings.ES_PIPELINE_INDEX, meta)
            print(f"[unsw batch {batch_id}] in={total_in} valid={n_events} threats={n_threats} alerts={n_alerts} "
                  f"({meta['batch_duration_ms']} ms)")
        finally:
            batch_df.unpersist()

    return process


def start_dataset_query(spark: SparkSession):
    """Returns the started query, or None when the UNSW-NB15 models are not trained yet."""
    if not models_exist(spark, UNSW_MODELS):
        print("[dataset] UNSW-NB15 models not found in HDFS - real-dataset query NOT started. "
              "Run: python3 scripts/train_models.py --dataset unsw")
        return None
    detector = ThreatDetector(spark, wait=False, paths=UNSW_MODELS)
    rules = settings.load_dataset_rules("unsw_nb15")
    src = (spark.readStream.format("kafka")
           .option("kafka.bootstrap.servers", settings.KAFKA_BOOTSTRAP)
           .option("subscribe", settings.DATASET_TOPIC)
           .option("startingOffsets", "earliest")
           .option("failOnDataLoss", "false")
           .option("maxOffsetsPerTrigger", settings.MAX_OFFSETS_PER_TRIGGER)
           .load())
    parsed = (src.select(F.col("value").cast("string").alias("value_str"),
                         F.col("topic").alias("kafka_topic"), F.col("timestamp").alias("kafka_timestamp"))
              .withColumn("_e", F.from_json("value_str", SCHEMA))
              .select("value_str", "kafka_topic", "kafka_timestamp", "_e.*")
              .withColumn("event_id", F.coalesce(F.col("event_id"), F.sha2(F.col("value_str"), 256)))
              .withColumn("event_time", F.coalesce(F.to_timestamp("timestamp"), F.col("kafka_timestamp")))
              .withColumn("log_source", F.lit("unsw_nb15"))
              .withColumn("is_simulated", F.lit(False))
              .drop("timestamp")
              .withWatermark("kafka_timestamp", settings.DEDUP_WATERMARK)
              .dropDuplicatesWithinWatermark(["event_id"]))
    q = (parsed.writeStream.queryName("dataset-detection")
         .foreachBatch(make_processor(spark, detector, rules))
         .option("checkpointLocation", f"{settings.HDFS_CHECKPOINTS}/dataset-detection")
         .trigger(processingTime=f"{settings.TRIGGER_SECONDS} seconds")
         .start())
    print(f"[dataset] real-dataset query started (UNSW-NB15 model {detector.model_version})")
    return q
