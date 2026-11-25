from django.contrib import admin

from .models import AlertState, InvestigationNote


@admin.register(AlertState)
class AlertStateAdmin(admin.ModelAdmin):
    list_display = ("alert_id", "status", "severity", "threat_category", "src_ip", "assigned_to", "updated_at")
    list_filter = ("status", "severity", "threat_category")
    search_fields = ("alert_id", "src_ip")


@admin.register(InvestigationNote)
class InvestigationNoteAdmin(admin.ModelAdmin):
    list_display = ("alert_id", "author", "created_at")
    search_fields = ("alert_id", "text")
