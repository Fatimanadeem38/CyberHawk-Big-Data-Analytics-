"""
GET /api/system/health/       real status of Kafka, Spark, HDFS, Elasticsearch, MongoDB, Django
GET /api/system/pipeline/     recent Spark micro-batch metrics (for the rate chart)
GET /api/system/audit/        recent audit records (Administrators only)
"""
from django.db import close_old_connections
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from accounts.models import AuditLog
from core import es
from core.permissions import IsAdminRole
from core.views import Page, int_param

from .health import all_health


class SystemPage(Page):
    template_name = "system.html"
    page_id = "system"
    page_title = "System Monitoring"


@api_view(["GET"])
def health(request):
    results = all_health()
    close_old_connections()
    order = {"down": 0, "degraded": 1, "up": 2}
    overall = min((r["status"] for r in results), key=lambda s: order.get(s, 0))
    return Response({"overall": overall, "components": results, "checked_at": es.utc_now_iso()})


@api_view(["GET"])
def pipeline(request):
    size = int_param(request, "size", 60, 1, 500)
    resp = es.search(es.PIPELINE, size=size, sort=[{"timestamp": "desc"}],
                     query={"bool": {"filter": [{"term": {"query_name": "threat-detection-batch"}},
                                                {"range": {"timestamp": {"gte": "now-2h"}}}]}})
    progress = es.search(es.PIPELINE, size=size, sort=[{"timestamp": "desc"}],
                         query={"bool": {"filter": [{"term": {"query_name": "threat-detection"}},
                                                    {"range": {"timestamp": {"gte": "now-2h"}}}]}})
    return Response({"batches": list(reversed(es.hits(resp))), "progress": list(reversed(es.hits(progress)))})


@api_view(["GET"])
@permission_classes([IsAdminRole])
def audit(request):
    size = int_param(request, "size", 50, 1, 500)
    rows = AuditLog.objects.all().values("created_at", "username", "action", "target_type", "target_id",
                                         "ip_address", "details")[:size]
    return Response(list(rows))
