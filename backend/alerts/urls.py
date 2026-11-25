from django.urls import path

from . import views

urlpatterns = [
    path("alerts/", views.AlertsPage.as_view(), name="alerts"),
    path("alerts/<str:alert_id>/", views.AlertDetailPage.as_view(), name="alert-detail"),
    path("api/alerts/", views.alert_list, name="api-alerts"),
    path("api/alerts/<str:alert_id>/", views.alert_detail, name="api-alert-detail"),
    path("api/alerts/<str:alert_id>/status/", views.update_status, name="api-alert-status"),
    path("api/alerts/<str:alert_id>/notes/", views.notes, name="api-alert-notes"),
]
