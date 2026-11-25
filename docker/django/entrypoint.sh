#!/usr/bin/env bash
# Starts the Django ASGI server (HTTP + WebSocket) with Daphne.
set -e
cd /app/backend

echo "[django] waiting for MongoDB..."
python - <<'PY'
import os, sys, time
sys.path.insert(0, ".")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
from django.conf import settings
from pymongo import MongoClient
for i in range(60):
    try:
        with MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000) as c:
            c.admin.command("ping")
        print("[django] MongoDB is ready")
        break
    except Exception as exc:
        print(f"[django] MongoDB not ready yet ({exc}); retrying")
        time.sleep(2)
else:
    raise SystemExit("MongoDB never became ready")
PY

# Old migration files made for PostgreSQL use BigAutoField and do not work with
# MongoDB. Remove them once; they are re-created below for MongoDB.
for app in accounts alerts ingestion; do
  if grep -lq "BigAutoField" "$app"/migrations/0*.py 2>/dev/null; then
    echo "[django] removing old SQL migrations in $app/migrations"
    find "$app/migrations" -name "0*.py" -delete
  fi
done

# Django's built-in apps need MongoDB versions of their migrations (ObjectId keys).
python manage.py makemigrations admin auth contenttypes --noinput
python manage.py makemigrations accounts alerts ingestion --noinput
python manage.py migrate --noinput
python manage.py collectstatic --noinput > /dev/null
python manage.py bootstrap_roles

echo "[django] starting Daphne on 0.0.0.0:8000"
exec daphne -b 0.0.0.0 -p 8000 config.asgi:application
