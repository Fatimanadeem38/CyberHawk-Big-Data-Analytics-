"""
Real health checks for every component. Nothing here is hard-coded:
each function contacts the real service and reports "up", "degraded"
or "down" together with the measured numbers.
"""
from __future__ import annotations

import platform
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import django
import requests
from django.conf import settings
from django.core.cache import cache

from core import es

STARTED = time.time()
TOPICS = ["network-logs", "firewall-logs", "authentication-logs", "dataset-flows", "security-alerts"]


def _result(name, status, message="", **details):
    return {"name": name, "status": status, "message": message, "details": details,
            "checked_at": es.utc_now_iso()}


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return round((datetime.now(timezone.utc) - dt).total_seconds(), 1)
    except ValueError:
        return None


# ---------------------------------------------------------------- Kafka
def kafka_offsets() -> dict:
    """Total messages currently stored per topic (high - low watermark)."""
    from confluent_kafka import Consumer, TopicPartition
    c = Consumer({"bootstrap.servers": settings.KAFKA_BOOTSTRAP_SERVERS, "group.id": "dashboard-health",
                  "enable.auto.commit": False, "socket.timeout.ms": 3000, "session.timeout.ms": 6000})
    try:
        md = c.list_topics(timeout=3)
        out = {}
        for t in TOPICS:
            tmeta = md.topics.get(t)
            if not tmeta or tmeta.error:
                out[t] = {"exists": False}
                continue
            high_total = low_total = 0
            for p in tmeta.partitions:
                low, high = c.get_watermark_offsets(TopicPartition(t, p), timeout=3, cached=False)
                high_total += high
                low_total += low
            out[t] = {"exists": True, "partitions": len(tmeta.partitions),
                      "end_offset_total": high_total, "messages_retained": high_total - low_total}
        return {"brokers": len(md.brokers), "topics": out}
    finally:
        c.close()


def check_kafka():
    try:
        data = kafka_offsets()
    except Exception as exc:
        return _result("Kafka", "down", f"Cannot reach broker: {exc}")
    now = time.time()
    total_end = sum(t.get("end_offset_total", 0) for n, t in data["topics"].items() if n != "security-alerts")
    prev = cache.get("kafka-prev")
    rate = None
    if prev and now - prev["t"] > 0.5:
        rate = round((total_end - prev["end"]) / (now - prev["t"]), 2)
    cache.set("kafka-prev", {"t": now, "end": total_end}, 600)
    missing = [n for n, t in data["topics"].items() if not t.get("exists")]
    status = "degraded" if missing else "up"
    msg = f"Missing topics: {', '.join(missing)}" if missing else f"{data['brokers']} broker(s), {len(TOPICS)} topics"
    return _result("Kafka", status, msg, brokers=data["brokers"], topics=data["topics"],
                   ingestion_rate_msgs_per_sec=rate, total_messages_produced=total_end)


# ---------------------------------------------------------------- Spark
def check_spark():
    try:
        resp = es.search(es.PIPELINE, size=0, query={"range": {"timestamp": {"gte": "now-1h"}}}, aggs={
            "q": {"terms": {"field": "query_name", "size": 5},
                  "aggs": {"last": {"top_hits": {"size": 1, "sort": [{"timestamp": "desc"}]}}}}})
    except es.ESUnavailable as exc:
        return _result("Spark Streaming", "degraded", f"Cannot read metrics from Elasticsearch: {exc}")
    latest = {b["key"]: b["last"]["hits"]["hits"][0]["_source"] for b in es.buckets(resp, "q")}
    ui = None
    try:
        r = requests.get(f"{settings.SPARK_UI_URL}/api/v1/applications", timeout=2)
        if r.ok and r.json():
            app = r.json()[0]
            ui = {"app_name": app.get("name"), "app_id": app.get("id")}
    except Exception:
        pass
    det = latest.get("threat-detection", {})
    batch = latest.get("threat-detection-batch", {})
    age = _age_seconds(det.get("timestamp"))
    if age is not None and age < 60:
        status, msg = "up", "Streaming queries are reporting progress"
    elif ui:
        status, msg = "degraded", "Spark application is running but has not reported progress recently"
    elif age is not None and age < 300:
        status, msg = "degraded", f"Last progress report {int(age)} s ago"
    else:
        status, msg = "down", "No streaming progress reported (is the spark-streaming container running?)"
    return _result("Spark Streaming", status, msg, application=ui,
                   input_rows_per_second=det.get("input_rows_per_second"),
                   processed_rows_per_second=det.get("processed_rows_per_second"),
                   consumer_lag_offsets=det.get("offsets_behind_latest"),
                   duplicates_removed=det.get("duplicates_removed"),
                   last_progress_at=det.get("timestamp"),
                   last_successful_batch_at=batch.get("timestamp"),
                   last_batch=batch, raw_archive=latest.get("raw-archive"))


# ---------------------------------------------------------------- HDFS
def check_hdfs():
    base = settings.HDFS_WEBHDFS_URL.rstrip("/")
    try:
        fs = requests.get(f"{base}/jmx", params={"qry": "Hadoop:service=NameNode,name=FSNamesystemState"},
                          timeout=3).json()["beans"][0]
        info = requests.get(f"{base}/jmx", params={"qry": "Hadoop:service=NameNode,name=NameNodeInfo"},
                            timeout=3).json()["beans"][0]
    except Exception as exc:
        return _result("Hadoop HDFS", "down", f"NameNode not reachable: {exc}")
    folders = {}
    for name in ("raw-logs", "processed-logs", "detection-results", "historical-alerts", "models"):
        try:
            r = requests.get(f"{base}/webhdfs/v1{settings.HDFS_BASE_PATH}/{name}",
                             params={"op": "GETCONTENTSUMMARY", "user.name": settings.HDFS_USER}, timeout=3)
            cs = r.json().get("ContentSummary", {}) if r.ok else {}
            folders[name] = {"bytes": cs.get("length", 0), "files": cs.get("fileCount", 0),
                             "directories": cs.get("directoryCount", 0)}
        except Exception:
            folders[name] = {"error": "unavailable"}
    live = fs.get("NumLiveDataNodes", 0)
    safemode = bool(info.get("Safemode"))
    status = "up" if live >= 1 and not safemode else ("degraded" if live >= 1 else "down")
    msg = f"{live} live DataNode(s)" + (" - SAFE MODE" if safemode else "")
    return _result("Hadoop HDFS", status, msg, live_datanodes=live, dead_datanodes=fs.get("NumDeadDataNodes", 0),
                   capacity_total=fs.get("CapacityTotal"), capacity_used=fs.get("CapacityUsed"),
                   capacity_remaining=fs.get("CapacityRemaining"), files_total=fs.get("FilesTotal"),
                   blocks_total=fs.get("BlocksTotal"), safemode=safemode, folders=folders,
                   version=info.get("Version", "").split(",")[0])


# ---------------------------------------------------------------- Elasticsearch
def check_elasticsearch():
    try:
        c = es.client()
        health = c.cluster.health(timeout="3s").body
        idx = c.cat.indices(index="security-*,threat-*,model-*,pipeline-*", format="json",
                            bytes="b").body
        info = c.info().body
    except Exception as exc:
        return _result("Elasticsearch", "down", f"Not reachable: {exc}")
    indices = {i["index"]: {"docs": int(i.get("docs.count") or 0), "size_bytes": int(i.get("store.size") or 0),
                            "health": i.get("health")} for i in idx}
    last = es.search(es.EVENTS, size=1, sort=[{"processed_at": "desc"}], source=["processed_at"])
    last_doc = es.hits(last)[0]["processed_at"] if es.hits(last) else None
    color = health.get("status")
    status = "up" if color in ("green", "yellow") else "down"
    return _result("Elasticsearch", status, f"Cluster status {color}", cluster=health.get("cluster_name"),
                   cluster_status=color, version=info.get("version", {}).get("number"),
                   nodes=health.get("number_of_nodes"), indices=indices, last_indexed_event_at=last_doc,
                   seconds_since_last_event=_age_seconds(last_doc))


# ---------------------------------------------------------------- MongoDB / Django
def check_mongodb():
    """Ping MongoDB and read its version and data size (pymongo comes with django-mongodb-backend)."""
    from pymongo import MongoClient
    try:
        with MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000) as client:
            info = client.admin.command("buildInfo")
            stats = client[settings.MONGO_DB].command("dbStats")
        return _result("MongoDB", "up", "Connected", version=info.get("version"),
                       database_size_bytes=int(stats.get("dataSize", 0)),
                       collections=stats.get("collections"), documents=stats.get("objects"))
    except Exception as exc:
        return _result("MongoDB", "down", f"Database error: {exc}")


def check_django():
    from dashboard.consumers import CONNECTED
    return _result("Django Backend", "up", "Serving HTTP and WebSocket",
                   django_version=django.get_version(), python_version=platform.python_version(),
                   uptime_seconds=int(time.time() - STARTED), websocket_clients=CONNECTED["count"])


def check_generator():
    from ingestion.models import GeneratorHeartbeat
    hb = GeneratorHeartbeat.current()
    if not hb or not hb.last_seen:
        return _result("Log Generator", "down", "No heartbeat received yet")
    age = (datetime.now(timezone.utc) - hb.last_seen).total_seconds()
    status = "up" if age < 20 else ("degraded" if age < 120 else "down")
    msg = ("Producing events" if hb.running else "Connected, ingestion paused") if status == "up" else \
        f"Last heartbeat {int(age)} s ago"
    return _result("Log Generator", status, msg, running=hb.running, rate=hb.rate,
                   events_sent=hb.events_sent, events_failed=hb.events_failed, last_error=hb.last_error,
                   last_heartbeat_at=hb.last_seen.isoformat(), by_topic=hb.by_topic)


# network checks run in parallel threads; database checks stay on the request thread
CHECKS = [check_kafka, check_spark, check_hdfs, check_elasticsearch, check_django]


def all_health() -> list[dict]:
    cached = cache.get("health-all")
    if cached:
        return cached
    with ThreadPoolExecutor(max_workers=len(CHECKS)) as pool:
        results = list(pool.map(lambda f: f(), CHECKS))
    results.insert(4, check_mongodb())
    results.append(check_generator())
    for r in results:
        r["details"] = {k: v for k, v in r["details"].items() if v is not None}
    cache.set("health-all", results, 3)
    return results
