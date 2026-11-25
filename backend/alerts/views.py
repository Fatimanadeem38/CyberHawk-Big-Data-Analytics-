"""
Alert management.

GET   /api/alerts/                       list + filters (severity, status, category, q=IP, range)
GET   /api/alerts/<id>/                  alert + workflow state + notes + related events + history
PATCH /api/alerts/<id>/status/           change status / assign to me / add a note
GET   /api/alerts/<id>/notes/            list investigation notes
POST  /api/alerts/<id>/notes/            add an investigation note
"""
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

from accounts.models import AuditLog
from core import es
from core.audit import log_action
from core.views import Page, int_param
from security_events.queries import ip_clause

from .models import AlertState, AlertStatus, InvestigationNote
from .serializers import NoteSerializer, StatusUpdateSerializer


class AlertsPage(Page):
    template_name = "alerts.html"
    page_id = "alerts"
    page_title = "Security Alerts"


class AlertDetailPage(Page):
    template_name = "alert_detail.html"
    page_id = "alerts"
    page_title = "Alert Investigation"


def _state_info(states):
    return {s.alert_id: {"assigned_to": s.assigned_to.username if s.assigned_to else None,
                         "updated_by": s.updated_by.username if s.updated_by else None,
                         "workflow_updated_at": s.updated_at} for s in states}


@api_view(["GET"])
def alert_list(request):
    p = request.query_params
    size = int_param(request, "size", 25, 1, 100)
    page = int_param(request, "page", 1, 1, 400)
    filters = es.range_filter("last_seen", p.get("range", "7d"))
    for field in ("severity", "status", "threat_category"):
        if p.get(field):
            filters.append({"terms": {field: p.get(field).split(",")}})
    if p.get("q"):
        clause = ip_clause(p["q"])
        filters.append(clause if clause else {"prefix": {"alert_id": p["q"].strip()}})
    if p.get("simulated") in ("0", "1"):
        filters.append({"term": {"is_simulated": p.get("simulated") == "1"}})
    sort_field = p.get("sort", "last_seen")
    if sort_field not in ("last_seen", "severity_rank", "event_count", "first_seen"):
        sort_field = "last_seen"
    resp = es.search(es.ALERTS, size=size, from_=(page - 1) * size, track_total_hits=True,
                     query={"bool": {"filter": filters}},
                     sort=[{sort_field: "desc"}, {"last_seen": "desc"}],
                     aggs={"status": {"terms": {"field": "status", "size": 4}},
                           "severity": {"terms": {"field": "severity", "size": 5}}})
    results = es.hits(resp)
    info = _state_info(AlertState.objects.filter(alert_id__in=[r["_id"] for r in results])
                       .select_related("assigned_to", "updated_by"))
    for r in results:
        r.update(info.get(r["_id"], {"assigned_to": None}))
    return Response({
        "total": es.total(resp), "page": page, "size": size, "results": results,
        "facets": {k: [{"key": b["key"], "count": b["doc_count"]} for b in es.buckets(resp, k)]
                   for k in ("status", "severity")},
    })


@api_view(["GET"])
def alert_detail(request, alert_id):
    alert = es.get(es.ALERTS, alert_id)
    if not alert:
        return Response({"detail": "Alert not found"}, status=404)
    state = AlertState.objects.filter(alert_id=alert_id).select_related("assigned_to", "updated_by").first()
    related = es.search(es.EVENTS, size=100, sort=[{"event_time": "desc"}],
                        query={"term": {"alert_id": alert_id}}, track_total_hits=True)
    notes = NoteSerializer(InvestigationNote.objects.filter(alert_id=alert_id).select_related("author"),
                           many=True).data
    history = list(AuditLog.objects.filter(target_type="alert", target_id=alert_id)
                   .values("created_at", "username", "action", "details")[:50])
    other_alerts = es.hits(es.search(es.ALERTS, size=10, sort=[{"last_seen": "desc"}], query={"bool": {
        "filter": [{"term": {"src_ip": alert["src_ip"]}}], "must_not": [{"ids": {"values": [alert_id]}}]}}))
    return Response({
        "alert": alert,
        "workflow": {
            "status": alert.get("status", "new"),
            "assigned_to": state.assigned_to.username if state and state.assigned_to else None,
            "updated_by": state.updated_by.username if state and state.updated_by else None,
            "resolution_summary": state.resolution_summary if state else "",
            "resolved_at": state.resolved_at if state else None,
        },
        "notes": notes, "history": history,
        "related_events": es.hits(related), "related_total": es.total(related),
        "other_alerts_from_source": other_alerts,
    })


@api_view(["PATCH", "POST"])
def update_status(request, alert_id):
    alert = es.get(es.ALERTS, alert_id)
    if not alert:
        return Response({"detail": "Alert not found"}, status=404)
    ser = StatusUpdateSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    data = ser.validated_data
    old_status = alert.get("status", "new")

    # MongoDB note: select_for_update() and Django transactions are not supported,
    # so the alert state is updated directly (one analyst action = one document write).
    state, _ = AlertState.objects.get_or_create(
        alert_id=alert_id, defaults={"src_ip": alert.get("src_ip"), "status": old_status,
                                     "threat_category": alert.get("threat_category", ""),
                                     "severity": alert.get("severity", "")})
    if data.get("assign_to_me"):
        state.assigned_to = request.user
        if state.status == AlertStatus.NEW and not data.get("status"):
            data["status"] = AlertStatus.INVESTIGATING
    new_status = data.get("status") or state.status
    state.status = new_status
    state.updated_by = request.user
    state.severity = alert.get("severity", state.severity)
    if data.get("resolution_summary"):
        state.resolution_summary = data["resolution_summary"]
    state.resolved_at = timezone.now() if new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE) else None
    state.save()
    if data.get("note"):
        InvestigationNote.objects.create(alert_id=alert_id, author=request.user, text=data["note"].strip())

    # keep Elasticsearch in sync so filters/search by status work
    es.update(es.ALERTS, alert_id, {"status": new_status, "updated_at": es.utc_now_iso()})
    log_action(request, "alert_status_change" if new_status != old_status else "alert_update",
               "alert", alert_id, old_status=old_status, new_status=new_status,
               assigned_to=state.assigned_to.username if state.assigned_to else None,
               note_added=bool(data.get("note")))
    return Response({"alert_id": alert_id, "status": new_status,
                     "assigned_to": state.assigned_to.username if state.assigned_to else None})


@api_view(["GET", "POST"])
def notes(request, alert_id):
    if request.method == "GET":
        qs = InvestigationNote.objects.filter(alert_id=alert_id).select_related("author")
        return Response(NoteSerializer(qs, many=True).data)
    if not es.get(es.ALERTS, alert_id):
        return Response({"detail": "Alert not found"}, status=404)
    ser = NoteSerializer(data=request.data)
    ser.is_valid(raise_exception=True)
    note = ser.save(alert_id=alert_id, author=request.user)
    log_action(request, "alert_note_added", "alert", alert_id, note_id=note.id)
    return Response(NoteSerializer(note).data, status=201)
