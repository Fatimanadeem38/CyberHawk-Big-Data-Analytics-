"""
Spark Structured Streaming: Kafka -> clean -> features -> MLlib -> alerts
-> HDFS (history) + Elasticsearch (search) + Kafka (security-alerts).

Two streaming queries run in this application:

1. "raw-archive"       Kafka value strings -> HDFS raw-logs (JSON lines),
                       partitioned year=/month=/day=, one file per minute.
2. "threat-detection"  parse -> de-duplicate (event_id, 10 min watermark)
                       -> foreachBatch(process_batch) every N seconds.

Both queries keep their Kafka offsets and state in checkpoint folders in
HDFS, so after a crash/restart they continue exactly where they stopped.

Run (inside the spark container):  bash /opt/app/spark/run_streaming.sh
"""
from __future__ import annotations

import json
import threading
import time
import traceback
from datetime import datetime, timezone

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

from config import settings
from feature_engineering.features import add_behavior_features
from inference.detector import ThreatDetector
from inference.threat_classifier import build_alerts, classify_threats
from preprocessing.parsing import clean_events, parse_json
from storage import sinks

RULES = settings.load_rules()
STATE = {"metadata_buffer": [], "last_metadata_flush": time.time(), "batches": 0}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_spark() -> SparkSession:
    return (SparkSession.builder.appName("DistributedCyberThreatDetection-Streaming")
            .config("spark.sql.session.timeZone", "UTC")
            .config("spark.sql.shuffle.partitions", "4")
            .config("spark.sql.streaming.stateStore.stateSchemaCheck", "true")
            .config("spark.sql.streaming.minBatchesToRetain", "20")
            .getOrCreate())


def make_batch_processor(spark: SparkSession, detector: ThreatDetector):
    def process_batch(batch_df: DataFrame, batch_id: int) -> None:
        started = time.time()
        if batch_df.isEmpty():
            return
        batch_df = batch_df.persist()
        try:
            total_in = batch_df.count()
            cleaned = clean_events(batch_df)
            features = add_behavior_features(cleaned, settings.FEATURE_WINDOW_SECONDS)
            scored = detector.score(features)
            classified = (classify_threats(scored, RULES)
                          .withColumn("processed_at", F.current_timestamp())
                          .withColumn("batch_id", F.lit(batch_id).cast("long")))
            out = sinks.events_for_output(classified).persist()
            n_events = out.count()
            invalid = total_in - n_events

            # 1) HDFS: processed events (Parquet) + 2) Elasticsearch: all events
            sinks.write_hdfs_batch(out, settings.HDFS_PROCESSED, batch_id)
            sinks.write_es(out, settings.ES_EVENTS_INDEX)

            # 3) detections (events flagged by at least one method)
            threats = out.filter(F.col("is_threat")).persist()
            n_threats = threats.count()
            n_alerts = 0
            if n_threats:
                sinks.write_hdfs_batch(threats, settings.HDFS_DETECTIONS, batch_id)
                sinks.write_es(threats, settings.ES_DETECTIONS_INDEX)
                alerts = build_alerts(threats).persist()
                n_alerts = alerts.count()
                if n_alerts:
                    sinks.write_alerts_es(alerts)
                    sinks.write_alerts_kafka(alerts)
                    sinks.write_hdfs_batch(alerts, settings.HDFS_ALERTS, batch_id, fmt="json")
                alerts.unpersist()
            threats.unpersist()
            out.unpersist()

            meta = {
                "timestamp": utc_now_iso(), "query_name": "threat-detection-batch", "batch_id": batch_id,
                "num_input_rows": total_in, "invalid_rows": invalid, "threats_in_batch": n_threats,
                "alerts_in_batch": n_alerts, "batch_duration_ms": int((time.time() - started) * 1000),
                "status": "ok", "message": f"model {detector.model_version}",
            }
            sinks.index_doc(settings.ES_PIPELINE_INDEX, meta)
            STATE["metadata_buffer"].append(meta)
            STATE["batches"] += 1
            print(f"[batch {batch_id}] in={total_in} valid={n_events} invalid={invalid} "
                  f"threats={n_threats} alerts={n_alerts} ({meta['batch_duration_ms']} ms)")
            flush_metadata(spark)
        finally:
            batch_df.unpersist()

    return process_batch


def flush_metadata(spark: SparkSession, force: bool = False) -> None:
    """Every 10 minutes, archive batch metadata to HDFS processing-metadata (one small file)."""
    if not STATE["metadata_buffer"]:
        return
    if not force and time.time() - STATE["last_metadata_flush"] < 600:
        return
    rows = [json.dumps(m) for m in STATE["metadata_buffer"]]
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = f"{settings.HDFS_METADATA}/date={day}/flush_{int(time.time())}"
    spark.createDataFrame([(r,) for r in rows], ["value"]).coalesce(1).write.mode("overwrite").text(path)
    STATE["metadata_buffer"] = []
    STATE["last_metadata_flush"] = time.time()


def progress_reporter(spark: SparkSession, stop: threading.Event) -> None:
    """Every 10 s, copy Spark's streaming progress (rates, lag) to Elasticsearch."""
    while not stop.wait(10):
        for q in spark.streams.active:
            try:
                p = q.lastProgress
                if not p:
                    continue
                behind = 0
                for src in p.get("sources", []):
                    m = (src.get("metrics") or {}).get("maxOffsetsBehindLatest")
                    if m not in (None, ""):
                        behind = max(behind, int(float(m)))
                dups = sum(int((op.get("customMetrics") or {}).get("numDroppedDuplicateRows", 0) or 0)
                           for op in p.get("stateOperators", []))
                sinks.index_doc(settings.ES_PIPELINE_INDEX, {
                    "timestamp": utc_now_iso(), "query_name": q.name, "batch_id": p.get("batchId"),
                    "num_input_rows": p.get("numInputRows", 0),
                    "input_rows_per_second": float(p.get("inputRowsPerSecond") or 0.0),
                    "processed_rows_per_second": float(p.get("processedRowsPerSecond") or 0.0),
                    "batch_duration_ms": (p.get("durationMs") or {}).get("triggerExecution", 0),
                    "offsets_behind_latest": behind, "duplicates_removed": dups,
                    "status": "active" if q.isActive else "stopped",
                })
            except Exception as exc:  # metrics must never stop the pipeline
                print("[metrics] could not report progress:", exc)


def main() -> None:
    spark = build_spark()
    spark.sparkContext.setLogLevel("WARN")
    detector = ThreatDetector(spark, wait=True)

    kafka = (spark.readStream.format("kafka")
             .option("kafka.bootstrap.servers", settings.KAFKA_BOOTSTRAP)
             .option("subscribe", ",".join(settings.INPUT_TOPICS))
             .option("startingOffsets", "earliest")
             .option("failOnDataLoss", "false")
             .option("maxOffsetsPerTrigger", settings.MAX_OFFSETS_PER_TRIGGER)
             .load())
    base = kafka.select(F.col("value").cast("string").alias("value_str"),
                        F.col("topic").alias("kafka_topic"),
                        F.col("timestamp").alias("kafka_timestamp"))

    # Query 1: raw archive (original messages, unchanged) -> HDFS
    raw = (base.select(F.col("value_str").alias("value"),
                       F.date_format("kafka_timestamp", "yyyy").alias("year"),
                       F.date_format("kafka_timestamp", "MM").alias("month"),
                       F.date_format("kafka_timestamp", "dd").alias("day"))
           .repartition(1)
           .writeStream.queryName("raw-archive").format("text")
           .partitionBy("year", "month", "day")
           .option("path", settings.HDFS_RAW)
           .option("checkpointLocation", f"{settings.HDFS_CHECKPOINTS}/raw-archive")
           .trigger(processingTime=f"{settings.RAW_TRIGGER_SECONDS} seconds")
           .start())

    # Query 2: detection pipeline
    parsed = (parse_json(base)
              .withWatermark("kafka_timestamp", settings.DEDUP_WATERMARK)
              .dropDuplicatesWithinWatermark(["event_id"]))
    detection = (parsed.writeStream.queryName("threat-detection")
                 .foreachBatch(make_batch_processor(spark, detector))
                 .option("checkpointLocation", f"{settings.HDFS_CHECKPOINTS}/threat-detection")
                 .trigger(processingTime=f"{settings.TRIGGER_SECONDS} seconds")
                 .start())

    # Query 3: REAL dataset flows (UNSW-NB15) - only if its models were trained
    try:
        from streaming.dataset_job import start_dataset_query
        start_dataset_query(spark)
    except Exception as exc:  # the main pipeline must keep running
        print(f"[dataset] could not start the real-dataset query: {exc}")

    stop = threading.Event()
    threading.Thread(target=progress_reporter, args=(spark, stop), daemon=True).start()
    print(f"[streaming] running: {raw.name}, {detection.name}. Spark UI: http://localhost:4040")
    try:
        spark.streams.awaitAnyTermination()
    except Exception:
        traceback.print_exc()
        raise
    finally:
        stop.set()
        try:
            flush_metadata(spark, force=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
