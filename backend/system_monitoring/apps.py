from django.apps import AppConfig


class SystemMonitoringConfig(AppConfig):
    default_auto_field = "django_mongodb_backend.fields.ObjectIdAutoField"
    name = "system_monitoring"
