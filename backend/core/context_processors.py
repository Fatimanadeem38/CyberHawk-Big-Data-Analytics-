from .permissions import user_role as _role


def user_role(request):
    role = _role(getattr(request, "user", None))
    return {"user_role": role, "is_admin_role": role == "admin"}
