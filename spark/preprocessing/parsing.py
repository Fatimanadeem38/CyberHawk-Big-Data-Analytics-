"""
Stage 3: parsing and cleaning of raw JSON events.

The SAME functions are used by the training job and the streaming job,
so training and live inference see exactly the same data preparation.
"""
from __future__ import annotations
from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (BooleanType, DoubleType, LongType, StringType, StructField,
                               StructType)

EVENT_SCHEMA = StructType([
    StructField("event_id", StringType()),
    StructField("timestamp", StringType()),
    StructField("log_source", StringType()),
    StructField("src_ip", StringType()),
    StructField("dst_ip", StringType()),
    StructField("src_port", LongType()),
    StructField("dst_port", LongType()),
    StructField("protocol", StringType()),
    StructField("packet_size", LongType()),
    StructField("duration", DoubleType()),
    StructField("request_count", LongType()),
    StructField("failed_logins", LongType()),
    StructField("event_type", StringType()),
    StructField("network_status", StringType()),
    StructField("username", StringType()),
    StructField("is_simulated", BooleanType()),
    StructField("scenario", StringType()),
    StructField("true_label", StringType()),
])

IPV4_REGEX = r"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
VALID_SOURCES = ["network", "firewall", "authentication", "server_access", "ids"]
VALID_PROTOCOLS = ["TCP", "UDP", "ICMP"]
FAILURE_STATUSES = ["failed", "rejected", "blocked", "reset", "timeout"]


def parse_json(df: DataFrame, value_col: str = "value_str") -> DataFrame:
    """JSON string column -> typed columns. Keeps kafka_* metadata columns if present."""
    extra = [c for c in ("kafka_topic", "kafka_timestamp") if c in df.columns]
    parsed = df.withColumn("_e", F.from_json(F.col(value_col), EVENT_SCHEMA))
    out = parsed.select(F.col(value_col), "_e.*", *extra)
    if "kafka_timestamp" not in out.columns:
        out = out.withColumn("kafka_timestamp", F.lit(None).cast("timestamp"))
        out = out.withColumn("kafka_topic", F.lit("file"))
    # missing event id -> deterministic hash of the raw message (still de-duplicable)
    out = out.withColumn("event_id", F.coalesce(F.col("event_id"), F.sha2(F.col(value_col), 256)))
    out = out.withColumn("event_time", F.coalesce(F.to_timestamp("timestamp"), F.col("kafka_timestamp")))
    return out.drop("timestamp")


def valid_condition():
    return (F.col("event_time").isNotNull()
            & F.col("src_ip").rlike(IPV4_REGEX)
            & F.col("dst_ip").rlike(IPV4_REGEX))


def clean_events(df: DataFrame) -> DataFrame:
    """Handles missing / invalid values and normalises categories.
    Rows without a time or with invalid IP addresses are removed."""
    def non_negative(c, default=0):
        return F.greatest(F.coalesce(F.col(c), F.lit(default)), F.lit(default))

    def port(c):
        return F.when(F.col(c).between(0, 65535), F.col(c)).otherwise(F.lit(0)).cast("int")

    proto = F.upper(F.trim(F.coalesce(F.col("protocol"), F.lit("TCP"))))
    source = F.lower(F.trim(F.coalesce(F.col("log_source"), F.lit("network"))))

    return (df.filter(valid_condition())
            .withColumn("src_ip", F.trim("src_ip"))
            .withColumn("dst_ip", F.trim("dst_ip"))
            .withColumn("protocol", F.when(proto.isin(VALID_PROTOCOLS), proto).otherwise(F.lit("OTHER")))
            .withColumn("log_source", F.when(source.isin(VALID_SOURCES), source).otherwise(F.lit("network")))
            .withColumn("src_port", port("src_port"))
            .withColumn("dst_port", port("dst_port"))
            .withColumn("packet_size", non_negative("packet_size").cast("long"))
            .withColumn("duration", non_negative("duration", 0.0).cast("double"))
            .withColumn("request_count", F.greatest(F.coalesce(F.col("request_count"), F.lit(1)), F.lit(1)).cast("long"))
            .withColumn("failed_logins", non_negative("failed_logins").cast("long"))
            .withColumn("event_type", F.lower(F.coalesce(F.col("event_type"), F.lit("unknown"))))
            .withColumn("network_status", F.lower(F.coalesce(F.col("network_status"), F.lit("unknown"))))
            .withColumn("username", F.coalesce(F.col("username"), F.lit("")))
            .withColumn("is_simulated", F.coalesce(F.col("is_simulated"), F.lit(False)))
            .withColumn("scenario", F.coalesce(F.col("scenario"), F.lit("")))
            .withColumn("true_label", F.lower(F.coalesce(F.col("true_label"), F.lit(""))))
            .withColumn("event_date", F.date_format("event_time", "yyyy-MM-dd")))
