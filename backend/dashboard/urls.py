from django.urls import path

from . import views

urlpatterns = [
    path("", views.DashboardPage.as_view(), name="dashboard"),
    path("api/dashboard/stats/", views.stats, name="api-dashboard-stats"),
]
