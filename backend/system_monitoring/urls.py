from django.urls import path

from . import views

urlpatterns = [
    path("system/", views.SystemPage.as_view(), name="system"),
    path("api/system/health/", views.health, name="api-system-health"),
    path("api/system/pipeline/", views.pipeline, name="api-system-pipeline"),
    path("api/system/audit/", views.audit, name="api-system-audit"),
]
