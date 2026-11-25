"""
Log ingestion APIs.

For the dashboard (session login):
  GET  /api/ingestion/status/      switch, generator heartbeat, Kafka topic counters, history
  POST /api/ingestion/control/     start / pause / change rate          (Administrator)
  POST /api/ingestion/scenario/    inject one simulated attack          (Administrator)
  POST /api/ingestion/upload/      upload a CSV / JSON log file         (Administrator)

For the log generator service (X-Service-Token header):
  GET  /api/ingestion/service/control/
  POST /api/ingestion/service/heartbeat/
"""
import logging

from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, parser_classes, permission_classes
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from core.audit import log_action
from core.permissions import HasServiceToken, IsAdminRole
from core.views import Page

from .dataset import dataset_status
from .models import DATASET_REPLAY, SCENARIOS, GeneratorHeartbeat, IngestionControl, ScenarioRequest, UploadJob

log = logging.getLogger(__name__)
SCENARIO_KEYS = {k for k, _ in SCENARIOS}
MAX_UPLOAD = 20 * 1024 * 1024


class IngestionPage(Page):
    template_name = "ingestion.html"
    page_id = "ingestion"
    page_title = "Log Ingestion"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["scenarios"] = SCENARIOS
        return ctx


def _control_dict(c: IngestionControl) -> dict:
    return {"enabled": c.enabled, "rate": c.rate, "attack_probability": c.attack_probability,
            "updated_by": c.updated_by.username if c.updated_by else None, "updated_at": c.updated_at}


@api_view(["GET"])
def status(request):
    from system_monitoring.health import check_generator
    topics = None
    try:
        from system_monitoring.health import kafka_offsets
        topics = kafka_offsets()["topics"]
    except Exception as exc:
        topics = {"error": str(exc)[:200]}
    hb = GeneratorHeartbeat.current()
    return Response({
        "control": _control_dict(IngestionControl.get()),
        "generator": check_generator(),
        "heartbeat": {"events_sent": hb.events_sent, "events_failed": hb.events_failed,
                      "pending_burst_events": hb.pending_burst_events, "by_topic": hb.by_topic,
                      "by_label": hb.by_label, "last_seen": hb.last_seen} if hb else None,
        "kafka_topics": topics,
        "recent_scenarios": list(ScenarioRequest.objects.exclude(scenario=DATASET_REPLAY).values(
            "scenario", "requested_by__username", "created_at", "consumed_at")[:10]),
        "recent_uploads": list(UploadJob.objects.values(
            "filename", "status", "rows_total", "rows_valid", "rows_rejected", "rows_published",
            "message", "uploaded_by__username", "created_at")[:10]),
        "scenarios": [{"key": k, "label": v} for k, v in SCENARIOS],
        "dataset": dataset_status(),
        "replay": hb.replay if hb else {},
    })


@api_view(["POST"])
@permission_classes([IsAdminRole])
def control(request):
    c = IngestionControl.get()
    changes = {}
    if "enabled" in request.data:
        c.enabled = str(request.data["enabled"]).lower() in ("1", "true", "yes", "on")
        changes["enabled"] = c.enabled
    if "rate" in request.data:
        try:
            rate = int(request.data["rate"])
        except (TypeError, ValueError):
            return Response({"detail": "rate must be a number"}, status=400)
        if not 1 <= rate <= 200:
            return Response({"detail": "rate must be between 1 and 200 events per second"}, status=400)
        c.rate = rate
        changes["rate"] = rate
    if "attack_probability" in request.data:
        try:
            p = float(request.data["attack_probability"])
        except (TypeError, ValueError):
            return Response({"detail": "attack_probability must be a number"}, status=400)
        if not 0 <= p <= 0.5:
            return Response({"detail": "attack_probability must be between 0 and 0.5"}, status=400)
        c.attack_probability = p
        changes["attack_probability"] = p
    c.updated_by = request.user
    c.save()
    log_action(request, "ingestion_control", "ingestion", "generator", **changes)
    return Response(_control_dict(c))


@api_view(["POST"])
@permission_classes([IsAdminRole])
def scenario(request):
    key = request.data.get("scenario")
    if key not in SCENARIO_KEYS:
        return Response({"detail": f"Unknown scenario. Choose one of: {', '.join(sorted(SCENARIO_KEYS))}"},
                        status=400)
    req = ScenarioRequest.objects.create(scenario=key, requested_by=request.user)
    log_action(request, "simulate_scenario", "ingestion", key)
    return Response({"id": str(req.id), "scenario": key, "message":
                     "Queued. The generator will publish this SIMULATED attack within a few seconds."}, status=201)


@api_view(["POST"])
@permission_classes([IsAdminRole])
@parser_classes([MultiPartParser, FormParser])
def upload(request):
    """Validate a CSV / JSON file and publish its rows to Kafka (same path as live logs)."""
    from normalizer import normalize_record, read_records, replay_as_now
    from producer import SecurityLogProducer

    f = request.FILES.get("file")
    if not f:
        return Response({"detail": "Choose a file to upload."}, status=400)
    name = f.name.lower()
    if not name.endswith((".csv", ".json", ".jsonl", ".ndjson")):
        return Response({"detail": "Only .csv, .json, .jsonl files are accepted."}, status=400)
    if f.size > MAX_UPLOAD:
        return Response({"detail": "File is larger than 20 MB."}, status=400)

    job = UploadJob.objects.create(filename=f.name[:255], size_bytes=f.size, uploaded_by=request.user)
    try:
        records = read_records(f.read(), f.name)
        default_source = request.data.get("default_source", "network")
        events, reasons = [], {}
        for rec in records:
            ev, err = normalize_record(rec, default_source)
            if ev:
                events.append(ev)
            else:
                reasons[err] = reasons.get(err, 0) + 1
        if str(request.data.get("replay_now", "")).lower() in ("1", "true", "on", "yes"):
            replay_as_now(events)
        job.rows_total, job.rows_valid = len(records), len(events)
        job.rows_rejected = len(records) - len(events)
        if events:
            producer = SecurityLogProducer(settings.KAFKA_BOOTSTRAP_SERVERS, client_id="django-upload",
                                           connect_attempts=2)
            producer.send_many(events)
            producer.flush(60)
            job.rows_published = producer.sent
        job.status = "completed" if events else "rejected"
        job.message = "; ".join(f"{n} rows: {r}" for r, n in reasons.items())[:2000]
        job.save()
    except Exception as exc:
        log.exception("upload failed")
        job.status, job.message = "failed", str(exc)[:2000]
        job.save()
        return Response({"detail": f"Upload failed: {exc}"}, status=500)
    log_action(request, "upload_logs", "ingestion", job.filename, rows=job.rows_total,
               published=job.rows_published, rejected=job.rows_rejected)
    return Response({"filename": job.filename, "rows_total": job.rows_total, "rows_valid": job.rows_valid,
                     "rows_rejected": job.rows_rejected, "rows_published": job.rows_published,
                     "rejection_reasons": reasons, "status": job.status}, status=201)


@api_view(["POST"])
@permission_classes([IsAdminRole])
def dataset_replay(request):
    """Start (or stop) a replay of REAL UNSW-NB15 flows into Kafka topic dataset-flows."""
    d = request.data
    if d.get("action") == "stop":
        ScenarioRequest.objects.create(scenario=DATASET_REPLAY, params={"action": "stop"}, requested_by=request.user)
        log_action(request, "dataset_replay_stop", "ingestion", "unsw_nb15")
        return Response({"message": "Stop request sent to the generator."}, status=201)
    try:
        params = {"action": "start", "rows": int(d.get("rows", 20000)), "rate": int(d.get("rate", 50)),
                  "start_row": int(d.get("start_row", 0)), "mode": str(d.get("mode", "sequential")),
                  "normal_fraction": float(d.get("normal_fraction", 0.05))}
    except (TypeError, ValueError):
        return Response({"detail": "rows, rate and start_row must be numbers"}, status=400)
    if not 1 <= params["rows"] <= 700000:
        return Response({"detail": "rows must be between 1 and 700,000"}, status=400)
    if not 1 <= params["rate"] <= 1000:
        return Response({"detail": "rate must be between 1 and 1000 flows per second"}, status=400)
    if params["mode"] not in ("sequential", "attack_enriched"):
        return Response({"detail": "mode must be 'sequential' or 'attack_enriched'"}, status=400)
    if params["start_row"] < 0 or not 0 <= params["normal_fraction"] <= 1:
        return Response({"detail": "start_row must be >= 0 and normal_fraction between 0 and 1"}, status=400)
    if not dataset_status()["replay_files"]:
        return Response({"detail": "No UNSW-NB15 replay file found. Put UNSW-NB15_1.csv in "
                                   "data/datasets/unsw-nb15/ (see documentation/real_dataset.md)."}, status=400)
    ScenarioRequest.objects.create(scenario=DATASET_REPLAY, params=params, requested_by=request.user)
    log_action(request, "dataset_replay_start", "ingestion", "unsw_nb15", **params)
    return Response({"message": "Queued. The generator starts replaying real flows within a few seconds.",
                     "params": params}, status=201)


# ------------------------------------------------------------------ service endpoints
@api_view(["GET"])
@authentication_classes([])
@permission_classes([HasServiceToken])
def service_control(request):
    c = IngestionControl.get()
    pending = list(ScenarioRequest.objects.filter(consumed_at__isnull=True).order_by("created_at")[:10])
    ScenarioRequest.objects.filter(id__in=[p.id for p in pending]).update(consumed_at=timezone.now())
    return Response({"enabled": c.enabled, "rate": c.rate, "attack_probability": c.attack_probability,
                     "scenarios": [p.scenario for p in pending if p.scenario != DATASET_REPLAY],
                     "dataset_replays": [p.params for p in pending if p.scenario == DATASET_REPLAY]})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([HasServiceToken])
@parser_classes([JSONParser])
def service_heartbeat(request):
    d = request.data
    hb = GeneratorHeartbeat.get()
    hb.last_seen = timezone.now()
    hb.running = bool(d.get("running"))
    hb.rate = int(d.get("rate") or 0)
    hb.attack_probability = float(d.get("attack_probability") or 0)
    hb.events_sent = int(d.get("events_sent") or 0)
    hb.events_failed = int(d.get("events_failed") or 0)
    hb.pending_burst_events = int(d.get("pending_burst_events") or 0)
    hb.last_error = str(d.get("last_error") or "")[:2000]
    hb.by_topic = d.get("by_topic") or {}
    hb.by_label = d.get("by_label") or {}
    hb.replay = d.get("replay") or {}
    hb.save()
    return Response({"ok": True})
