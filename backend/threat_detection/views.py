"""
Threat detection APIs.

GET /api/detections/                 detections (index threat-detections) with filters
GET /api/detections/<event_id>/      one detection + the alert it belongs to
GET /api/models/metrics/             OFFLINE evaluation metrics of both models
                                     + LIVE detection statistics (kept separate)
"""
import json

from django.conf import settings
from rest_framework.decorators import api_view
from rest_framework.response import Response

from core import es
from core.views import Page, int_param
from security_events.queries import build_event_query


class ThreatsPage(Page):
    template_name = "threats.html"
    page_id = "threats"
    page_title = "Threat Detection"


class ModelsPage(Page):
    template_name = "models.html"
    page_id = "models"
    page_title = "ML Model Performance"


@api_view(["GET"])
def detections(request):
    size = int_param(request, "size", 50, 1, 200)
    page = int_param(request, "page", 1, 1, 200)
    query = build_event_query(request.query_params, time_field="processed_at", default_range="24h")
    method = (request.query_params.get("method") or "").strip()
    if method:
        query["bool"]["filter"].append({"prefix": {"detection_methods": method}})
    resp = es.search(es.DETECTIONS, size=size, from_=(page - 1) * size, query=query, track_total_hits=True,
                     sort=[{"processed_at": "desc"}, {"severity_rank": "desc"}],
                     aggs={"categories": {"terms": {"field": "threat_category", "size": 10}},
                           "severity": {"terms": {"field": "severity", "size": 5}},
                           "methods": {"terms": {"field": "detection_methods", "size": 12}}})
    facets = {k: [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(resp, k)]
              for k in ("categories", "severity", "methods")}
    return Response({"total": es.total(resp), "page": page, "size": size, "results": es.hits(resp),
                     "facets": facets})


@api_view(["GET"])
def detection_detail(request, event_id):
    doc = es.get(es.DETECTIONS, event_id)
    if not doc:
        return Response({"detail": "Detection not found"}, status=404)
    alert = es.get(es.ALERTS, doc["alert_id"]) if doc.get("alert_id") else None
    return Response({"detection": doc, "alert": alert})


def _offline_metrics():
    resp = es.search(es.MODEL_METRICS, size=20, sort=[{"trained_at": "desc"}],
                     query={"term": {"is_current": True}})
    docs = es.hits(resp)
    if docs:
        return docs, "elasticsearch"
    docs = []  # fallback: files written by the training jobs
    for f in (settings.MODEL_METRICS_FILE, settings.MODEL_METRICS_FILE.with_name("model_metrics_unsw_nb15.json")):
        try:
            docs += json.loads(f.read_text())
        except (OSError, ValueError):
            pass
    return docs, ("file" if docs else "none")


@api_view(["GET"])
def model_metrics(request):
    offline, source = _offline_metrics()
    history = es.hits(es.search(es.MODEL_METRICS, size=20, sort=[{"trained_at": "desc"}],
                                source=["model_name", "dataset", "trained_at", "metrics.f1", "metrics.accuracy",
                                        "metrics.roc_auc", "is_current"]))
    # ---- live statistics (NOT accuracy measurements on new data) ----
    live = es.search(es.EVENTS, size=0, track_total_hits=True,
                     query={"range": {"processed_at": {"gte": "now-24h"}}}, aggs={
                         "classes": {"terms": {"field": "predicted_class", "size": 10}},
                         "avg_prob": {"avg": {"field": "ml_probability"}},
                         "avg_anom": {"avg": {"field": "anomaly_score"}},
                         "anomalies": {"filter": {"term": {"is_anomaly": True}}},
                         "methods": {"terms": {"field": "detection_methods", "size": 12}},
                         "labelled": {"filter": {"bool": {"filter": [{"exists": {"field": "true_label"}}],
                                                          "must_not": [{"term": {"true_label": ""}}]}},
                                      "aggs": {"agree": {"filter": {"script": {"script": {
                                          "source": "doc['true_label'].size()>0 && doc['predicted_class'].size()>0 && doc['true_label'].value == doc['predicted_class'].value"}}}},
                                               "by_source": {"terms": {"field": "is_simulated", "size": 2},
                                                             "aggs": {"agree": {"filter": {"script": {"script": {
                                                                 "source": "doc['true_label'].size()>0 && doc['predicted_class'].size()>0 && doc['true_label'].value == doc['predicted_class'].value"}}}}}}}},
                     })
    a = live.get("aggregations", {})
    n = es.total(live)
    labelled = a.get("labelled", {}).get("doc_count", 0)
    agree = a.get("labelled", {}).get("agree", {}).get("doc_count", 0)
    return Response({
        "offline": offline, "offline_source": source, "training_history": history,
        "live": {
            "window": "last 24 hours", "events_scored": n,
            "class_distribution": [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(live, "classes")],
            "avg_ml_probability": a.get("avg_prob", {}).get("value"),
            "avg_anomaly_score": a.get("avg_anom", {}).get("value"),
            "anomaly_rate": round(100 * a.get("anomalies", {}).get("doc_count", 0) / n, 2) if n else 0,
            "detection_methods": [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(live, "methods")],
            "simulated_labelled_events": labelled,
            "agreement_with_simulation_labels": round(100 * agree / labelled, 2) if labelled else None,
            "agreement_by_source": [{
                "source": "simulated" if b.get("key_as_string") == "true" or b.get("key") in (1, True) else "real dataset (UNSW-NB15)",
                "events": b["doc_count"],
                "agreement": round(100 * b["agree"]["doc_count"] / b["doc_count"], 2) if b["doc_count"] else None}
                for b in a.get("labelled", {}).get("by_source", {}).get("buckets", [])],
        },
    })
