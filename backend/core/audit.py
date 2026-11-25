"""Helper to write audit records (stored in MongoDB)."""
import logging

log = logging.getLogger("audit")


def client_ip(request) -> str:
    fwd = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return fwd.split(",")[0].strip() if fwd else request.META.get("REMOTE_ADDR", "")


def log_action(request, action: str, target_type: str = "", target_id: str = "", **details) -> None:
    from accounts.models import AuditLog
    user = getattr(request, "user", None)
    try:
        AuditLog.objects.create(
            user=user if user is not None and user.is_authenticated else None,
            username=getattr(user, "username", "") or "",
            action=action, target_type=target_type, target_id=str(target_id)[:128],
            details=details, ip_address=client_ip(request) or None,
        )
    except Exception:  # auditing must never break the request
        log.exception("could not write audit record")
