"""Central configuration for the Spark jobs (read from environment variables)."""
from __future__ import annotations
import json
import os
from pathlib import Path

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
INPUT_TOPICS = ["network-logs", "firewall-logs", "authentication-logs"]
ALERT_TOPIC = "security-alerts"

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
ES_EVENTS_INDEX = "security-events"
ES_DETECTIONS_INDEX = "threat-detections"
ES_ALERTS_INDEX = "security-alerts"
ES_MODEL_METRICS_INDEX = "model-metrics"
ES_PIPELINE_INDEX = "pipeline-metrics"

HDFS_URI = os.getenv("HDFS_NAMENODE_URI", "hdfs://namenode:8020").rstrip("/")
HDFS_BASE = HDFS_URI + os.getenv("HDFS_BASE_PATH", "/cybersecurity")
HDFS_RAW = f"{HDFS_BASE}/raw-logs"
HDFS_PROCESSED = f"{HDFS_BASE}/processed-logs"
HDFS_DETECTIONS = f"{HDFS_BASE}/detection-results"
HDFS_ALERTS = f"{HDFS_BASE}/historical-alerts"
HDFS_METADATA = f"{HDFS_BASE}/processing-metadata"
HDFS_MODELS = f"{HDFS_BASE}/models"
HDFS_TRAINING = f"{HDFS_BASE}/training"
HDFS_CHECKPOINTS = f"{HDFS_BASE}/checkpoints"

MODEL_RF = f"{HDFS_MODELS}/rf_pipeline"
MODEL_LABELS = f"{HDFS_MODELS}/label_indexer"
MODEL_ANOMALY = f"{HDFS_MODELS}/anomaly_kmeans_pipeline"
MODEL_ANOMALY_META = f"{HDFS_MODELS}/anomaly_meta"

# ---- real dataset: UNSW-NB15 (see documentation/real_dataset.md) ----
DATASET_TOPIC = "dataset-flows"
UNSW_DIR_LOCAL = Path(__file__).resolve().parents[2] / "data" / "datasets" / "unsw-nb15"
HDFS_DATASETS = f"{HDFS_BASE}/datasets/unsw-nb15"
UNSW_MODELS_DIR = f"{HDFS_MODELS}/unsw_nb15"
UNSW_MODEL_RF = f"{UNSW_MODELS_DIR}/rf_pipeline"
UNSW_MODEL_LABELS = f"{UNSW_MODELS_DIR}/label_indexer"
UNSW_MODEL_ANOMALY = f"{UNSW_MODELS_DIR}/anomaly_kmeans_pipeline"
UNSW_MODEL_ANOMALY_META = f"{UNSW_MODELS_DIR}/anomaly_meta"
UNSW_LOCAL_METRICS_FILE = Path(__file__).resolve().parents[2] / "data" / "processed" / "model_metrics_unsw_nb15.json"

TRIGGER_SECONDS = int(os.getenv("SPARK_TRIGGER_SECONDS", "15"))
RAW_TRIGGER_SECONDS = int(os.getenv("SPARK_RAW_TRIGGER_SECONDS", "60"))
MAX_OFFSETS_PER_TRIGGER = int(os.getenv("SPARK_MAX_OFFSETS_PER_TRIGGER", "20000"))
FEATURE_WINDOW_SECONDS = int(os.getenv("FEATURE_WINDOW_SECONDS", "10"))
DEDUP_WATERMARK = "10 minutes"

ROOT = Path(__file__).resolve().parents[2]
TRAINING_FILE = ROOT / "data" / "training" / "training_events.jsonl"
LOCAL_METRICS_FILE = ROOT / "data" / "processed" / "model_metrics.json"
RULES_FILE = Path(__file__).resolve().parent / "detection_rules.json"


def load_rules() -> dict:
    rules = json.loads(RULES_FILE.read_text())
    if os.getenv("ALERT_DEDUP_WINDOW_MINUTES"):
        rules["dedup_window_minutes"] = int(os.environ["ALERT_DEDUP_WINDOW_MINUTES"])
    return rules


def load_dataset_rules(name: str = "unsw_nb15") -> dict:
    """Severity settings for a real dataset: no window rules, own base severities."""
    base = load_rules()
    ds = base.get("datasets", {}).get(name, {})
    return {**{k: v for k, v in base.items() if k not in ("rules", "datasets", "base_severity")},
            **{k: v for k, v in ds.items() if not k.startswith("_")},
            "rules": [], "allowlist_src_ips": []}
