from django.urls import path

from . import views

urlpatterns = [
    path("live/", views.LivePage.as_view(), name="live"),
    path("history/", views.HistoryPage.as_view(), name="history"),
    path("api/events/recent/", views.recent_events, name="api-events-recent"),
    path("api/events/search/", views.search_events, name="api-events-search"),
    path("api/events/export/", views.export_events, name="api-events-export"),
    path("api/events/by-ip/<str:ip>/", views.events_by_ip, name="api-events-by-ip"),
    path("api/events/<str:event_id>/", views.event_detail, name="api-event-detail"),
]
