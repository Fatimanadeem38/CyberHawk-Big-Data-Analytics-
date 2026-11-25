from django.contrib import admin
from django.urls import include, path

admin.site.site_header = "CyberHawk Administration"
admin.site.site_title = "CyberHawk Admin"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("accounts.urls")),
    path("", include("dashboard.urls")),
    path("", include("security_events.urls")),
    path("", include("threat_detection.urls")),
    path("", include("alerts.urls")),
    path("", include("analytics.urls")),
    path("", include("system_monitoring.urls")),
    path("", include("ingestion.urls")),
]
