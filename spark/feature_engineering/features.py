"""
Stage 4: feature engineering (shared by training and streaming inference).

Two kinds of features:
1. Per-event features   - packet size, duration, ports, protocol, ...
2. Behaviour features   - computed per SOURCE IP inside a short time
   window (FEATURE_WINDOW_SECONDS, default 10 s):
     connection frequency, failed-login frequency, average packet size,
     traffic volume, unique destination ports / hosts / usernames,
     request frequency, protocol distribution, failure ratio.
3. Time features        - hour of day, off-hours flag.

Example: a brute-force source sends 60 failed logins in 10 s ->
win_conn_count = 60, win_failed_logins = 150, win_unique_dst_ports = 1.

Note for streaming: windows are computed inside each micro-batch, so a
window that crosses two micro-batches is counted in two parts.
"""
from __future__ import annotations
from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from preprocessing.parsing import FAILURE_STATUSES

PRIVATE_IP_REGEX = r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)"

CATEGORICAL_FEATURES = ["protocol", "log_source", "network_status"]

NUMERIC_FEATURES = [
    "packet_size", "duration", "request_count", "failed_logins", "dst_port_num", "log_bytes_total",
    "win_conn_count", "win_failed_logins", "win_avg_packet_size", "log_win_traffic_volume",
    "win_unique_dst_ports", "win_unique_dst_ips", "win_unique_usernames", "log_win_request_sum",
    "win_avg_duration", "win_tcp_ratio", "win_udp_ratio", "win_icmp_ratio", "win_fail_status_ratio",
    "hour_of_day", "is_off_hours", "src_is_internal", "dst_is_internal",
]

# Smaller, scale-friendly set for the distance-based anomaly model
ANOMALY_FEATURES = [
    "log_bytes_total", "failed_logins", "log_win_conn_count", "log_win_failed_logins",
    "log_win_traffic_volume", "log_win_unique_dst_ports", "log_win_unique_dst_ips",
    "log_win_unique_usernames", "log_win_request_sum", "win_fail_status_ratio",
    "win_avg_packet_size", "src_is_internal", "dst_is_internal",
]


def add_behavior_features(df: DataFrame, window_seconds: int) -> DataFrame:
    df = (df.withColumn("time_bucket", F.floor(F.col("event_time").cast("long") / F.lit(window_seconds)))
            .withColumn("bytes_total", (F.col("packet_size") * F.col("request_count")).cast("long")))

    agg = df.groupBy("src_ip", "time_bucket").agg(
        F.count(F.lit(1)).alias("win_conn_count"),
        F.sum("failed_logins").alias("win_failed_logins"),
        F.avg("packet_size").alias("win_avg_packet_size"),
        F.sum("bytes_total").alias("win_traffic_volume"),
        F.countDistinct("dst_port").alias("win_unique_dst_ports"),
        F.countDistinct("dst_ip").alias("win_unique_dst_ips"),
        F.countDistinct(F.when(F.col("username") != "", F.col("username"))).alias("win_unique_usernames"),
        F.sum("request_count").alias("win_request_sum"),
        F.avg("duration").alias("win_avg_duration"),
        F.avg(F.when(F.col("protocol") == "TCP", 1.0).otherwise(0.0)).alias("win_tcp_ratio"),
        F.avg(F.when(F.col("protocol") == "UDP", 1.0).otherwise(0.0)).alias("win_udp_ratio"),
        F.avg(F.when(F.col("protocol") == "ICMP", 1.0).otherwise(0.0)).alias("win_icmp_ratio"),
        F.avg(F.when(F.col("network_status").isin(FAILURE_STATUSES), 1.0).otherwise(0.0))
         .alias("win_fail_status_ratio"),
    )
    df = df.join(agg, on=["src_ip", "time_bucket"], how="left")

    hour = F.hour("event_time")
    df = (df.withColumn("hour_of_day", hour.cast("double"))
            .withColumn("is_off_hours", F.when((hour < 6) | (hour >= 22), 1.0).otherwise(0.0))
            .withColumn("src_is_internal", F.when(F.col("src_ip").rlike(PRIVATE_IP_REGEX), 1.0).otherwise(0.0))
            .withColumn("dst_is_internal", F.when(F.col("dst_ip").rlike(PRIVATE_IP_REGEX), 1.0).otherwise(0.0))
            .withColumn("dst_port_num", F.col("dst_port").cast("double")))

    # log(1+x) tames very large, skewed values (bytes, counts)
    for c in ["bytes_total", "win_traffic_volume", "win_request_sum", "win_conn_count",
              "win_failed_logins", "win_unique_dst_ports", "win_unique_dst_ips", "win_unique_usernames"]:
        df = df.withColumn(f"log_{c}", F.log1p(F.col(c).cast("double")))

    base_cols = {"packet_size", "duration", "request_count", "failed_logins"}  # already clean
    for c in sorted(set(NUMERIC_FEATURES + ANOMALY_FEATURES) - base_cols):
        df = df.withColumn(c, F.coalesce(F.col(c).cast("double"), F.lit(0.0)))
    return df
