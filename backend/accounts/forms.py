from datetime import timedelta

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils import timezone

MAX_FAILED = 5
LOCK_MINUTES = 15


class ThrottledAuthenticationForm(AuthenticationForm):
    """Blocks a username for 15 minutes after 5 failed logins (stops password guessing)."""

    def clean(self):
        from .models import AuditLog
        username = (self.cleaned_data.get("username") or "")[:150]
        since = timezone.now() - timedelta(minutes=LOCK_MINUTES)
        recent_failures = AuditLog.objects.filter(action="login_failed", username=username,
                                                  created_at__gte=since).count()
        if username and recent_failures >= MAX_FAILED:
            raise forms.ValidationError(
                f"Too many failed attempts. This account is locked for {LOCK_MINUTES} minutes.",
                code="locked")
        return super().clean()
