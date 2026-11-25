"""Role-based permissions: Administrator and Security Analyst."""
import hmac

from django.conf import settings
from rest_framework.permissions import SAFE_METHODS, BasePermission

ADMIN_GROUP = "Administrator"
ANALYST_GROUP = "Security Analyst"


def user_role(user) -> str:
    if not user or not user.is_authenticated:
        return "anonymous"
    if user.is_superuser or user.groups.filter(name=ADMIN_GROUP).exists():
        return "admin"
    if user.groups.filter(name=ANALYST_GROUP).exists():
        return "analyst"
    return "none"


class IsAnalystOrAdmin(BasePermission):
    """Default for all APIs: logged-in Analyst or Administrator."""
    message = "You need the Security Analyst or Administrator role."

    def has_permission(self, request, view):
        return user_role(request.user) in ("admin", "analyst")


class IsAdminRole(BasePermission):
    message = "Only Administrators can do this."

    def has_permission(self, request, view):
        return user_role(request.user) == "admin"


class AdminWriteAnalystRead(BasePermission):
    """Analysts can read; only Administrators can change."""

    def has_permission(self, request, view):
        role = user_role(request.user)
        if request.method in SAFE_METHODS:
            return role in ("admin", "analyst")
        return role == "admin"


class HasServiceToken(BasePermission):
    """For internal services (log generator) using the X-Service-Token header."""

    def has_permission(self, request, view):
        expected = settings.SERVICE_API_TOKEN
        given = request.headers.get("X-Service-Token", "")
        return bool(expected) and hmac.compare_digest(expected, given)
