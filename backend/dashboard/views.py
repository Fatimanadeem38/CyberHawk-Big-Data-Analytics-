from rest_framework.decorators import api_view
from rest_framework.response import Response

from core.es import RANGES
from core.views import Page

from .services import dashboard_stats


class DashboardPage(Page):
    template_name = "dashboard.html"
    page_id = "dashboard"
    page_title = "Security Overview"


@api_view(["GET"])
def stats(request):
    """GET /api/dashboard/stats/?range=24h  -> KPIs, charts and recent alerts."""
    rng = request.query_params.get("range", "24h")
    if rng not in RANGES:
        rng = "24h"
    return Response(dashboard_stats(rng))
