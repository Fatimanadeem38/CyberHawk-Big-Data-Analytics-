"""
Network analytics from Elasticsearch aggregations.

GET /api/analytics/overview/?range=24h
"""
from rest_framework.decorators import api_view
from rest_framework.response import Response

from core import es
from core.views import Page


class AnalyticsPage(Page):
    template_name = "analytics.html"
    page_id = "analytics"
    page_title = "Network Analytics"


def _terms(resp, name):
    return [{"key": b.get("key_as_string", b["key"]), "count": b["doc_count"]} for b in es.buckets(resp, name)]


@api_view(["GET"])
def overview(request):
    rng = request.query_params.get("range", "24h")
    if rng not in es.RANGES:
        rng = "24h"
    interval = es.INTERVALS[rng]
    query = {"bool": {"filter": es.range_filter("event_time", rng)}}
    resp = es.search(es.EVENTS, size=0, track_total_hits=True, query=query, aggs={
        "over_time": {"date_histogram": {"field": "event_time", "fixed_interval": interval, "min_doc_count": 0},
                      "aggs": {"bytes": {"sum": {"field": "bytes_total"}},
                               "requests": {"sum": {"field": "request_count"}},
                               "threats": {"filter": {"term": {"is_threat": True}}},
                               "anomalies": {"filter": {"term": {"is_anomaly": True}}}}},
        "protocols": {"terms": {"field": "protocol", "size": 6}},
        "log_sources": {"terms": {"field": "log_source", "size": 6}},
        "top_src": {"terms": {"field": "src_ip", "size": 10},
                    "aggs": {"threats": {"filter": {"term": {"is_threat": True}}},
                             "bytes": {"sum": {"field": "bytes_total"}}}},
        "top_dst": {"terms": {"field": "dst_ip", "size": 10},
                    "aggs": {"bytes": {"sum": {"field": "bytes_total"}}}},
        "top_ports": {"terms": {"field": "dst_port", "size": 12}},
        "status": {"terms": {"field": "network_status", "size": 8}},
        "total_bytes": {"sum": {"field": "bytes_total"}},
        "unique_src": {"cardinality": {"field": "src_ip"}},
        "unique_dst": {"cardinality": {"field": "dst_ip"}},
    })
    aggs = resp.get("aggregations", {})
    det = es.search(es.DETECTIONS, size=0, query=query, aggs={
        "trend": {"date_histogram": {"field": "event_time", "fixed_interval": interval, "min_doc_count": 0},
                  "aggs": {"cat": {"terms": {"field": "threat_category", "size": 8}}}}})
    categories = sorted({c["key"] for b in es.buckets(det, "trend") for c in b["cat"]["buckets"]})
    trend = {
        "labels": [b["key_as_string"] for b in es.buckets(det, "trend")],
        "series": {cat: [next((c["doc_count"] for c in b["cat"]["buckets"] if c["key"] == cat), 0)
                         for b in es.buckets(det, "trend")] for cat in categories},
    }
    return Response({
        "range": rng, "interval": interval, "total_events": es.total(resp),
        "total_bytes": int(aggs.get("total_bytes", {}).get("value") or 0),
        "unique_sources": aggs.get("unique_src", {}).get("value", 0),
        "unique_destinations": aggs.get("unique_dst", {}).get("value", 0),
        "traffic_over_time": [{"t": b["key_as_string"], "events": b["doc_count"],
                               "bytes": int(b["bytes"]["value"] or 0), "requests": int(b["requests"]["value"] or 0),
                               "threats": b["threats"]["doc_count"], "anomalies": b["anomalies"]["doc_count"]}
                              for b in es.buckets(resp, "over_time")],
        "protocols": _terms(resp, "protocols"),
        "log_sources": _terms(resp, "log_sources"),
        "top_sources": [{"key": b["key"], "count": b["doc_count"], "threats": b["threats"]["doc_count"],
                         "bytes": int(b["bytes"]["value"] or 0)} for b in es.buckets(resp, "top_src")],
        "top_destinations": [{"key": b["key"], "count": b["doc_count"], "bytes": int(b["bytes"]["value"] or 0)}
                             for b in es.buckets(resp, "top_dst")],
        "top_ports": [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(resp, "top_ports")],
        "network_status": _terms(resp, "status"),
        "suspicious_trend": trend,
    })
