from django.urls import path

from . import views

urlpatterns = [
    path("threats/", views.ThreatsPage.as_view(), name="threats"),
    path("models/", views.ModelsPage.as_view(), name="models"),
    path("api/detections/", views.detections, name="api-detections"),
    path("api/detections/<str:event_id>/", views.detection_detail, name="api-detection-detail"),
    path("api/models/metrics/", views.model_metrics, name="api-model-metrics"),
]
