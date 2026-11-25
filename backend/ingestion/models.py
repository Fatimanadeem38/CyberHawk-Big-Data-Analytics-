"""
Log ingestion control (application settings stored in MongoDB).

IngestionControl    the ON/OFF switch, rate and attack frequency of the generator
ScenarioRequest     "simulate a brute-force now" button clicks, picked up by the generator
GeneratorHeartbeat  last status report sent by the generator
UploadJob           history of uploaded CSV/JSON log files
"""
from django.conf import settings
from django.db import models

SCENARIOS = [
    ("brute_force", "Brute-force login attempts"),
    ("port_scan", "Port scanning"),
    ("dos", "Denial-of-Service-like traffic"),
    ("suspicious_frequency", "Suspicious connection frequency"),
    ("unusual_volume", "Unusual traffic volume"),
    ("abnormal_auth", "Abnormal authentication behaviour"),
]


class IngestionControl(models.Model):
    enabled = models.BooleanField(default=False)
    rate = models.PositiveIntegerField(default=8, help_text="normal events per second")
    attack_probability = models.FloatField(default=0.02, help_text="chance per second of a random simulated attack")
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def get(cls):
        # one settings document only (MongoDB ids are ObjectIds, so no "pk=1")
        return cls.objects.order_by("pk").first() or cls.objects.create()

    def __str__(self):
        return f"Ingestion {'ON' if self.enabled else 'OFF'} @ {self.rate}/s"


DATASET_REPLAY = "replay_unsw_nb15"


class ScenarioRequest(models.Model):
    """A button click picked up by the generator: a simulated attack, or a real-dataset replay."""
    scenario = models.CharField(max_length=40, choices=SCENARIOS + [(DATASET_REPLAY, "Replay UNSW-NB15 (real dataset)")])
    params = models.JSONField(default=dict, blank=True)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


class GeneratorHeartbeat(models.Model):
    last_seen = models.DateTimeField(null=True)
    running = models.BooleanField(default=False)
    rate = models.PositiveIntegerField(default=0)
    attack_probability = models.FloatField(default=0)
    events_sent = models.BigIntegerField(default=0)
    events_failed = models.BigIntegerField(default=0)
    pending_burst_events = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)
    by_topic = models.JSONField(default=dict, blank=True)
    by_label = models.JSONField(default=dict, blank=True)
    replay = models.JSONField(default=dict, blank=True)

    @classmethod
    def current(cls):
        """The single heartbeat document, or None if the generator never reported."""
        return cls.objects.order_by("pk").first()

    @classmethod
    def get(cls):
        return cls.current() or cls.objects.create()


class UploadJob(models.Model):
    filename = models.CharField(max_length=255)
    size_bytes = models.BigIntegerField(default=0)
    rows_total = models.IntegerField(default=0)
    rows_valid = models.IntegerField(default=0)
    rows_rejected = models.IntegerField(default=0)
    rows_published = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default="processing")
    message = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
