"""
Creates the two roles (groups) and the default accounts from .env.
Runs automatically when the Django container starts (safe to repeat).

    python manage.py bootstrap_roles
"""
import os

from django.contrib.auth.models import Group, User
from django.core.management.base import BaseCommand

from core.permissions import ADMIN_GROUP, ANALYST_GROUP


class Command(BaseCommand):
    help = "Create Administrator / Security Analyst roles and default users"

    def handle(self, *args, **opts):
        admin_group, _ = Group.objects.get_or_create(name=ADMIN_GROUP)
        analyst_group, _ = Group.objects.get_or_create(name=ANALYST_GROUP)

        accounts = [
            (os.getenv("DJANGO_ADMIN_USERNAME", "admin"), os.getenv("DJANGO_ADMIN_PASSWORD"), admin_group, True),
            (os.getenv("DJANGO_ANALYST_USERNAME", "analyst"), os.getenv("DJANGO_ANALYST_PASSWORD"), analyst_group, False),
        ]
        for username, password, group, is_staff in accounts:
            if not password:
                self.stdout.write(f"skip {username}: no password in environment")
                continue
            user, created = User.objects.get_or_create(username=username)
            if created:
                user.set_password(password)
                user.is_staff = is_staff
                user.is_superuser = is_staff
                user.save()
                self.stdout.write(self.style.SUCCESS(f"created user '{username}'"))
            user.groups.add(group)
        self.stdout.write(self.style.SUCCESS("roles ready: Administrator, Security Analyst"))
