"""
Alert management metadata (MongoDB).

The alert itself (what was detected) lives in Elasticsearch, index
"security-alerts", written by Spark. MongoDB stores the analyst
workflow around it: status, assignee, investigation notes, history.
"""
from django.conf import settings
from django.db import models


class AlertStatus(models.TextChoices):
    NEW = "new", "New"
    INVESTIGATING = "investigating", "Investigating"
    RESOLVED = "resolved", "Resolved"
    FALSE_POSITIVE = "false_positive", "False Positive"


class AlertState(models.Model):
    alert_id = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=20, choices=AlertStatus.choices, default=AlertStatus.NEW, db_index=True)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name="assigned_alerts")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                   on_delete=models.SET_NULL, related_name="+")
    # copied from ES so the admin list is readable without a lookup
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    threat_category = models.CharField(max_length=40, blank=True)
    severity = models.CharField(max_length=20, blank=True)
    resolution_summary = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.alert_id} [{self.status}]"


class InvestigationNote(models.Model):
    alert_id = models.CharField(max_length=64, db_index=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"note on {self.alert_id} by {self.author}"
