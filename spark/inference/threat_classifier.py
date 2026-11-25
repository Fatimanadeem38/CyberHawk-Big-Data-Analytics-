"""
Stage 6: threat classification, severity and alert grouping.

For each scored event three detection methods are checked:
  ml       RandomForest says "attack class" with probability >= ml_min_probability
  anomaly  KMeans anomaly_score >= anomaly_min_score
  rule     one of the configurable rules in config/detection_rules.json fires

Severity (informational < low < medium < high < critical):
  * start from the category's base severity (e.g. brute_force = high)
  * 3 methods agree                 -> critical
  * 2 methods agree                 -> base + 1 level
  * 1 method only:
        anomaly only, score < 1.5   -> informational
        ml only, probability < 0.75 -> base - 1 level
        rule only                   -> base - 1 level (minimum low)
        otherwise                   -> base

Alert grouping / de-duplication: threats are grouped by
(source IP, threat category, dedup time bucket of N minutes). The alert id
is a hash of these three values, so repeated events update ONE alert in
Elasticsearch (event_count goes up) instead of creating many alerts.
"""
from __future__ import annotations
from functools import reduce

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

SEVERITIES = ["informational", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

_OPS = {
    ">=": lambda c, v: c >= v, ">": lambda c, v: c > v, "<=": lambda c, v: c <= v,
    "<": lambda c, v: c < v, "==": lambda c, v: c == v, "!=": lambda c, v: c != v,
}


def _rule_condition(rule: dict):
    cond = _OPS[rule["op"]](F.col(rule["field"]), F.lit(rule["value"]))
    if "and" in rule:
        cond = cond & _rule_condition(rule["and"])
    return cond


def classify_threats(df: DataFrame, rules: dict) -> DataFrame:
    allow = rules.get("allowlist_src_ips", [])
    allowed = F.col("src_ip").isin(allow) if allow else F.lit(False)

    # first matching rule wins (rules are ordered in the JSON file)
    rule_cat = F.lit(None).cast("string")
    rule_name = F.lit(None).cast("string")
    for rule in reversed(rules["rules"]):
        cond = _rule_condition(rule) & ~allowed
        rule_cat = F.when(cond, F.lit(rule["category"])).otherwise(rule_cat)
        rule_name = F.when(cond, F.lit(rule["name"])).otherwise(rule_name)
    df = df.withColumn("rule_category", rule_cat).withColumn("rule_name", rule_name)

    ml_hit = (F.col("predicted_class") != "normal") & (F.col("ml_probability") >= rules["ml_min_probability"])
    anom_hit = (F.col("anomaly_score") >= rules["anomaly_min_score"]) & ~allowed
    rule_hit = F.col("rule_category").isNotNull()
    df = (df.withColumn("_ml", ml_hit).withColumn("_an", anom_hit).withColumn("_rule", rule_hit)
            .withColumn("_methods", F.col("_ml").cast("int") + F.col("_an").cast("int") + F.col("_rule").cast("int")))

    category = (F.when(F.col("_ml"), F.col("predicted_class"))
                 .when(F.col("_rule"), F.col("rule_category"))
                 .when(F.col("predicted_class") != "normal", F.col("predicted_class"))
                 .when(F.col("_an"), F.lit("unknown_anomaly")))
    df = df.withColumn("threat_category", F.when(F.col("_methods") > 0, category))

    base_map = F.create_map(*reduce(lambda acc, kv: acc + [F.lit(kv[0]), F.lit(RANK[kv[1]])],
                                    rules["base_severity"].items(), []))
    base = F.coalesce(base_map[F.col("threat_category")], F.lit(1))
    info_below = rules.get("anomaly_informational_below", 1.5)
    single = (F.when(F.col("_an") & ~F.col("_ml") & ~F.col("_rule") & (F.col("anomaly_score") < info_below), F.lit(0))
               .when(F.col("_ml") & (F.col("ml_probability") < 0.75), F.greatest(base - 1, F.lit(0)))
               .when(F.col("_rule") & ~F.col("_ml"), F.greatest(base - 1, F.lit(1)))
               .otherwise(base))
    rank = (F.when(F.col("_methods") >= 3, F.lit(4))
             .when(F.col("_methods") == 2, F.least(base + 1, F.lit(4)))
             .when(F.col("_methods") == 1, single))
    sev_arr = F.array(*[F.lit(s) for s in SEVERITIES])
    df = (df.withColumn("severity_rank", rank.cast("int"))
            .withColumn("severity", F.when(F.col("severity_rank").isNotNull(),
                                           F.element_at(sev_arr, F.col("severity_rank") + 1)).otherwise(F.lit("none")))
            .withColumn("is_threat", F.col("_methods") > 0)
            .withColumn("detection_methods", F.array_compact(F.array(
                F.when(F.col("_ml"), F.lit("ml_random_forest")),
                F.when(F.col("_an"), F.lit("anomaly_kmeans")),
                F.when(F.col("_rule"), F.concat(F.lit("rule:"), F.col("rule_name")))))))

    # alert id: same source + category + time bucket -> same alert
    bucket_seconds = int(rules.get("dedup_window_minutes", 10)) * 60
    min_rank = RANK.get(rules.get("min_alert_severity", "low"), 1)
    alert_id = F.substring(F.sha2(F.concat_ws("|", F.col("src_ip"), F.col("threat_category"),
                                              F.floor(F.col("event_time").cast("long") / bucket_seconds).cast("string")), 256), 1, 24)
    df = df.withColumn("alert_id", F.when(F.col("is_threat") & (F.col("severity_rank") >= min_rank), alert_id))
    return df.drop("_ml", "_an", "_rule", "_methods")


def build_alerts(threats: DataFrame) -> DataFrame:
    """Groups threat events into alert records (one row per alert_id in this batch)."""
    ts = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    return (threats.filter(F.col("alert_id").isNotNull())
            .groupBy("alert_id", "src_ip", "threat_category")
            .agg(F.count(F.lit(1)).alias("event_count"),
                 F.date_format(F.min("event_time"), ts).alias("first_seen"),
                 F.date_format(F.max("event_time"), ts).alias("last_seen"),
                 F.max("severity_rank").alias("severity_rank"),
                 F.round(F.max("anomaly_score"), 4).alias("max_anomaly_score"),
                 F.round(F.max(F.when(F.col("predicted_class") == F.col("threat_category"),
                                      F.col("ml_probability"))), 4).alias("max_ml_probability"),
                 F.mode("dst_ip").alias("dst_ip"),
                 F.slice(F.collect_set("dst_ip"), 1, 20).alias("dst_ips"),
                 F.slice(F.collect_set("dst_port"), 1, 30).alias("dst_ports"),
                 F.collect_set("protocol").alias("protocols"),
                 F.array_distinct(F.flatten(F.collect_list("detection_methods"))).alias("detection_methods"),
                 F.slice(F.collect_list("event_id"), 1, 20).alias("sample_event_ids"),
                 F.max(F.col("is_simulated").cast("int")).cast("boolean").alias("is_simulated"),
                 F.sum("failed_logins").alias("total_failed_logins"),
                 F.max("win_unique_dst_ports").cast("long").alias("max_unique_ports"),
                 F.max("win_unique_dst_ips").cast("long").alias("max_unique_hosts"),
                 F.max("win_unique_usernames").cast("long").alias("max_unique_users"),
                 F.sum("request_count").alias("total_requests"),
                 F.sum("bytes_total").alias("total_bytes"))
            .withColumn("severity", F.element_at(F.array(*[F.lit(s) for s in SEVERITIES]),
                                                 F.col("severity_rank") + 1)))


def describe_alert(a: dict) -> str:
    """Human readable one-line description (used by the ES writer)."""
    prefix = "[SIMULATED] " if a.get("is_simulated") else ""
    cat = a.get("threat_category")
    src, dst, n = a.get("src_ip"), a.get("dst_ip"), a.get("event_count")
    texts = {
        "brute_force": f"Potential brute-force activity: {a.get('total_failed_logins')} failed logins from {src} to {dst}.",
        "port_scan": f"Potential port scanning: {src} touched up to {a.get('max_unique_ports')} destination ports on {dst} within one window.",
        "dos": f"Potential DoS activity: {a.get('total_requests')} requests from {src} towards {dst}.",
        "suspicious_frequency": f"Suspicious connection frequency: {src} contacted up to {a.get('max_unique_hosts')} hosts ({n} connections).",
        "unusual_volume": f"Unusual traffic volume: about {round((a.get('total_bytes') or 0) / 1e6, 1)} MB from {src} to {dst}.",
        "abnormal_auth": f"Abnormal authentication behaviour: {src} tried up to {a.get('max_unique_users')} different accounts.",
        "unknown_anomaly": f"Unusual behaviour from {src} that differs from learned normal traffic (anomaly score {a.get('max_anomaly_score')}).",
    }
    if cat not in texts:  # real dataset (UNSW-NB15) categories
        from datasets.unsw_nb15 import DESCRIPTIONS
        if cat in DESCRIPTIONS:
            return (f"[UNSW-NB15 real flows] {DESCRIPTIONS[cat]}. {n} flow(s) from {src} to {dst} "
                    f"(model probability up to {a.get('max_ml_probability')}).")
    return prefix + texts.get(cat, f"Suspicious activity ({cat}) from {src}: {n} events.")
