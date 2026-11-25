from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from core.audit import client_ip


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    from .models import AuditLog
    AuditLog.objects.create(user=user, username=user.username, action="login",
                            ip_address=client_ip(request) or None)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    from .models import AuditLog
    if user:
        AuditLog.objects.create(user=user, username=user.username, action="logout",
                                ip_address=client_ip(request) or None)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    from .models import AuditLog
    AuditLog.objects.create(username=str(credentials.get("username", ""))[:150], action="login_failed",
                            ip_address=(client_ip(request) if request else None) or None)
