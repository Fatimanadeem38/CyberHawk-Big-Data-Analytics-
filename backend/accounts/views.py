from django.contrib.auth import views as auth_views
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from core.permissions import user_role

from .forms import ThrottledAuthenticationForm


class LoginView(auth_views.LoginView):
    template_name = "login.html"
    form_class = ThrottledAuthenticationForm
    redirect_authenticated_user = True


class LogoutView(auth_views.LogoutView):
    pass


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    u = request.user
    return Response({"username": u.username, "full_name": u.get_full_name(), "role": user_role(u),
                     "last_login": u.last_login})
