"""Dashboard statistics, computed with Elasticsearch queries and aggregations."""
from django.core.cache import cache

from core import es

OPEN_STATUSES = ["new", "investigating"]


def dashboard_stats(range_key: str = "24h", use_cache: bool = False) -> dict:
    key = f"dash-stats-{range_key}"
    if use_cache:
        cached = cache.get(key)
        if cached:
            return cached

    rf = es.range_filter("processed_at", range_key)
    ev = es.search(es.EVENTS, size=0, track_total_hits=True, query={"bool": {"filter": rf}}, aggs={
        "normal": {"filter": {"term": {"predicted_class": "normal"}}},
        "threats": {"filter": {"term": {"is_threat": True}}},
        "anomalies": {"filter": {"term": {"is_anomaly": True}}},
        "bytes": {"sum": {"field": "bytes_total"}},
        "recent": {
            "filter": {"range": {"processed_at": {"gte": "now-60m"}}},
            "aggs": {"per_minute": {
                "date_histogram": {"field": "processed_at", "fixed_interval": "1m", "min_doc_count": 0,
                                   "extended_bounds": {"min": "now-60m", "max": "now"}},
                "aggs": {"threats": {"filter": {"term": {"is_threat": True}}},
                         "bytes": {"sum": {"field": "bytes_total"}}}}},
        },
    })
    aggs = ev.get("aggregations", {})
    in_range = es.total(ev)
    timeline = [{
        "t": b["key_as_string"], "events": b["doc_count"], "threats": b["threats"]["doc_count"],
        "bytes": int(b["bytes"]["value"] or 0),
    } for b in aggs.get("recent", {}).get("per_minute", {}).get("buckets", [])]

    det = es.search(es.DETECTIONS, size=0, query={"bool": {"filter": rf}}, aggs={
        "categories": {"terms": {"field": "threat_category", "size": 10}}})

    arf = es.range_filter("last_seen", range_key)
    al = es.search(es.ALERTS, size=8, sort=[{"last_seen": "desc"}], query={"bool": {"filter": arf}},
                   track_total_hits=True, aggs={
                       "severity": {"terms": {"field": "severity", "size": 5}},
                       "open_critical": {"filter": {"bool": {"filter": [
                           {"term": {"severity": "critical"}}, {"terms": {"status": OPEN_STATUSES}}]}}},
                       "open_high": {"filter": {"bool": {"filter": [
                           {"term": {"severity": "high"}}, {"terms": {"status": OPEN_STATUSES}}]}}},
                       "open_all": {"filter": {"terms": {"status": OPEN_STATUSES}}},
                   })
    a_aggs = al.get("aggregations", {})
    threats = aggs.get("threats", {}).get("doc_count", 0)
    anomalies = aggs.get("anomalies", {}).get("doc_count", 0)
    result = {
        "range": range_key,
        "total_events_all_time": es.count(es.EVENTS),
        "events_in_range": in_range,
        "threat_events": threats,
        "normal_events": aggs.get("normal", {}).get("doc_count", 0),
        "anomaly_events": anomalies,
        "anomaly_rate": round(100.0 * anomalies / in_range, 2) if in_range else 0.0,
        "threat_rate": round(100.0 * threats / in_range, 2) if in_range else 0.0,
        "traffic_bytes": int(aggs.get("bytes", {}).get("value") or 0),
        "alerts_in_range": es.total(al),
        "open_alerts": a_aggs.get("open_all", {}).get("doc_count", 0),
        "critical_alerts": a_aggs.get("open_critical", {}).get("doc_count", 0),
        "high_alerts": a_aggs.get("open_high", {}).get("doc_count", 0),
        "timeline": timeline,
        "threat_distribution": [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(det, "categories")],
        "severity_distribution": [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(al, "severity")],
        "recent_alerts": es.hits(al),
        "generated_at": es.utc_now_iso(),
    }
    cache.set(key, result, 3)
    return result
