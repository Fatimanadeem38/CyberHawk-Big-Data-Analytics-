from django.apps import AppConfig


class ThreatDetectionConfig(AppConfig):
    default_auto_field = "django_mongodb_backend.fields.ObjectIdAutoField"
    name = "threat_detection"
