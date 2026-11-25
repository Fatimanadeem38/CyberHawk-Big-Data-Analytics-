from django.urls import path

from . import views

urlpatterns = [
    path("ingestion/", views.IngestionPage.as_view(), name="ingestion"),
    path("api/ingestion/status/", views.status, name="api-ingestion-status"),
    path("api/ingestion/control/", views.control, name="api-ingestion-control"),
    path("api/ingestion/scenario/", views.scenario, name="api-ingestion-scenario"),
    path("api/ingestion/upload/", views.upload, name="api-ingestion-upload"),
    path("api/ingestion/dataset-replay/", views.dataset_replay, name="api-ingestion-dataset-replay"),
    path("api/ingestion/service/control/", views.service_control, name="api-service-control"),
    path("api/ingestion/service/heartbeat/", views.service_heartbeat, name="api-service-heartbeat"),
]
