from django.apps import AppConfig


class SecurityEventsConfig(AppConfig):
    default_auto_field = "django_mongodb_backend.fields.ObjectIdAutoField"
    name = "security_events"
