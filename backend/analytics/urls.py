from django.urls import path

from . import views

urlpatterns = [
    path("analytics/", views.AnalyticsPage.as_view(), name="analytics"),
    path("api/analytics/overview/", views.overview, name="api-analytics-overview"),
]
