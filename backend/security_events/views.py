"""
Security event APIs (all data comes from the Elasticsearch index security-events).

GET /api/events/recent/            newest processed events (live monitoring)
GET /api/events/search/            historical search with filters + paging
GET /api/events/export/            same filters, CSV download (max 10,000 rows)
GET /api/events/by-ip/<ip>/        everything about one IP address
GET /api/events/<event_id>/        one event
"""
import csv
import ipaddress

from django.http import StreamingHttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

from core import es
from core.audit import log_action
from core.views import Page, int_param

from .queries import build_event_query

EXPORT_COLUMNS = ["event_time", "event_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                  "log_source", "event_type", "network_status", "username", "packet_size", "duration",
                  "request_count", "failed_logins", "predicted_class", "ml_probability", "anomaly_score",
                  "threat_category", "severity", "detection_methods", "is_simulated", "true_label",
                  "processed_at"]
SORTABLE = {"event_time", "processed_at", "src_ip", "dst_ip", "dst_port", "anomaly_score", "severity_rank",
            "bytes_total", "ml_probability"}


class LivePage(Page):
    template_name = "live.html"
    page_id = "live"
    page_title = "Live Monitoring"


class HistoryPage(Page):
    template_name = "history.html"
    page_id = "history"
    page_title = "Historical Logs"


@api_view(["GET"])
def recent_events(request):
    size = int_param(request, "size", 100, 1, 500)
    query = build_event_query(request.query_params, time_field="processed_at", default_range="all")
    resp = es.search(es.EVENTS, size=size, sort=[{"processed_at": "desc"}, {"event_time": "desc"}],
                     query=query, track_total_hits=True)
    return Response({"total": es.total(resp), "results": es.hits(resp)})


def _sort(request):
    field = request.query_params.get("sort", "event_time")
    order = "asc" if request.query_params.get("order") == "asc" else "desc"
    return [{field if field in SORTABLE else "event_time": order}]


@api_view(["GET"])
def search_events(request):
    size = int_param(request, "size", 50, 1, 200)
    page = int_param(request, "page", 1, 1, 10000)
    if page * size > 10000:
        return Response({"detail": "Results are limited to the first 10,000 hits. Narrow your filters."},
                        status=400)
    query = build_event_query(request.query_params, time_field="event_time")
    resp = es.search(es.EVENTS, size=size, from_=(page - 1) * size, sort=_sort(request), query=query,
                     track_total_hits=True, aggs={
                         "protocols": {"terms": {"field": "protocol", "size": 5}},
                         "classes": {"terms": {"field": "predicted_class", "size": 10}},
                     })
    return Response({
        "total": es.total(resp), "page": page, "size": size, "results": es.hits(resp),
        "facets": {k: [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(resp, k)]
                   for k in ("protocols", "classes")},
    })


class _Echo:
    def write(self, value):
        return value


@api_view(["GET"])
def export_events(request):
    limit = int_param(request, "limit", 10000, 1, 10000)
    query = build_event_query(request.query_params, time_field="event_time")
    resp = es.search(es.EVENTS, size=limit, sort=_sort(request), query=query, source=EXPORT_COLUMNS)
    rows = es.hits(resp)
    log_action(request, "export_events", "security-events", "", rows=len(rows),
               filters={k: v for k, v in request.query_params.items()})
    writer = csv.writer(_Echo())

    def stream():
        yield writer.writerow(EXPORT_COLUMNS)
        for r in rows:
            yield writer.writerow([
                "|".join(r.get(c)) if isinstance(r.get(c), list) else r.get(c, "") for c in EXPORT_COLUMNS])

    response = StreamingHttpResponse(stream(), content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="security_events_export.csv"'
    return response


@api_view(["GET"])
def event_detail(request, event_id):
    doc = es.get(es.EVENTS, event_id)
    if not doc:
        return Response({"detail": "Event not found"}, status=404)
    return Response(doc)


@api_view(["GET"])
def events_by_ip(request, ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return Response({"detail": "Invalid IP address"}, status=400)
    either = {"bool": {"should": [{"term": {"src_ip": ip}}, {"term": {"dst_ip": ip}}], "minimum_should_match": 1}}
    resp = es.search(es.EVENTS, size=50, sort=[{"event_time": "desc"}], query=either, track_total_hits=True,
                     aggs={
                         "as_source": {"filter": {"term": {"src_ip": ip}}, "aggs": {
                             "dst": {"terms": {"field": "dst_ip", "size": 10}},
                             "ports": {"terms": {"field": "dst_port", "size": 10}}}},
                         "as_destination": {"filter": {"term": {"dst_ip": ip}}, "aggs": {
                             "src": {"terms": {"field": "src_ip", "size": 10}}}},
                         "categories": {"terms": {"field": "threat_category", "size": 10}},
                         "first": {"min": {"field": "event_time"}},
                         "last": {"max": {"field": "event_time"}},
                     })
    aggs = resp.get("aggregations", {})
    alerts = es.search(es.ALERTS, size=20, sort=[{"last_seen": "desc"}],
                       query={"bool": {"should": [{"term": {"src_ip": ip}}, {"term": {"dst_ip": ip}}],
                                       "minimum_should_match": 1}})
    simple = lambda bs: [{"key": b["key"], "count": b["doc_count"]} for b in bs]  # noqa: E731
    return Response({
        "ip": ip, "total_events": es.total(resp),
        "as_source": aggs.get("as_source", {}).get("doc_count", 0),
        "as_destination": aggs.get("as_destination", {}).get("doc_count", 0),
        "top_destinations": simple(aggs.get("as_source", {}).get("dst", {}).get("buckets", [])),
        "top_ports": simple(aggs.get("as_source", {}).get("ports", {}).get("buckets", [])),
        "top_sources": simple(aggs.get("as_destination", {}).get("src", {}).get("buckets", [])),
        "threat_categories": simple(aggs.get("categories", {}).get("buckets", [])),
        "first_seen": aggs.get("first", {}).get("value_as_string"),
        "last_seen": aggs.get("last", {}).get("value_as_string"),
        "recent_events": es.hits(resp), "alerts": es.hits(alerts),
    })
