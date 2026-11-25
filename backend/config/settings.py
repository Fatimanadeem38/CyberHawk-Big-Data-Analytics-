"""
Django settings for the Distributed Cyber Threat Detection web application.
All secrets and service addresses come from environment variables (.env).
"""
import os
import sys
from pathlib import Path
from urllib.parse import quote_plus

BASE_DIR = Path(__file__).resolve().parent.parent          # backend/
REPO_ROOT = BASE_DIR.parent                                 # project root
# shared pure-Python modules (event normaliser, Kafka producer)
sys.path.append(str(REPO_ROOT / "kafka" / "producers"))


def env_list(name, default=""):
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-insecure-key-change-me")
DEBUG = os.getenv("DJANGO_DEBUG", "0") == "1"
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1") + ["django"]
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")

INSTALLED_APPS = [
    "daphne",
    # MongoDB versions of Django's built-in apps (see config/apps.py)
    "config.apps.MongoAdminConfig",
    "config.apps.MongoAuthConfig",
    "config.apps.MongoContentTypesConfig",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "channels",
    "core",
    "accounts",
    "dashboard",
    "security_events",
    "threat_detection",
    "alerts",
    "analytics",
    "system_monitoring",
    "ingestion",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
ASGI_APPLICATION = "config.asgi.application"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [REPO_ROOT / "frontend" / "templates"],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug",
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
        "core.context_processors.user_role",
    ]},
}]

# ---------------- MongoDB (users, roles, alert workflow, notes, audit log) ----------------
MONGO_HOST = os.getenv("MONGO_HOST", "mongodb")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")
MONGO_DB = os.getenv("MONGO_DB", "threatdb")
MONGO_USER = os.getenv("MONGO_ROOT_USERNAME", "threat_admin")
MONGO_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "change_me_mongo_password")
MONGO_URI = os.getenv("MONGO_URI") or (
    f"mongodb://{quote_plus(MONGO_USER)}:{quote_plus(MONGO_PASSWORD)}@{MONGO_HOST}:{MONGO_PORT}/"
    f"?authSource=admin"
)

DATABASES = {"default": {
    "ENGINE": "django_mongodb_backend",
    "HOST": MONGO_URI,
    "NAME": MONGO_DB,
}}

# MongoDB-compatible migrations for Django's built-in apps.
# They are generated automatically by docker/django/entrypoint.sh.
MIGRATION_MODULES = {
    "admin": "mongo_migrations.admin",
    "auth": "mongo_migrations.auth",
    "contenttypes": "mongo_migrations.contenttypes",
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"          # stored in UTC; the browser shows local time
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [REPO_ROOT / "frontend" / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
WHITENOISE_USE_FINDERS = True       # serve frontend/static directly (no restart after JS/CSS edits)
WHITENOISE_AUTOREFRESH = DEBUG
DEFAULT_AUTO_FIELD = "django_mongodb_backend.fields.ObjectIdAutoField"

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"
SESSION_COOKIE_AGE = 8 * 3600
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False   # the dashboard JS reads it for AJAX calls
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 25 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 25 * 1024 * 1024

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["core.permissions.IsAnalystOrAdmin"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"]
    + (["rest_framework.renderers.BrowsableAPIRenderer"] if DEBUG else []),
    "EXCEPTION_HANDLER": "core.exceptions.api_exception_handler",
}

CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# ---------------- integration with the Big Data services ----------------
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
HDFS_WEBHDFS_URL = os.getenv("HDFS_WEBHDFS_URL", "http://namenode:9870")
HDFS_BASE_PATH = os.getenv("HDFS_BASE_PATH", "/cybersecurity")
HDFS_USER = os.getenv("HDFS_USER", "hadoop")
SPARK_UI_URL = os.getenv("SPARK_UI_URL", "http://spark-streaming:4040")
SERVICE_API_TOKEN = os.getenv("SERVICE_API_TOKEN", "")
MODEL_METRICS_FILE = REPO_ROOT / "data" / "processed" / "model_metrics.json"
REALTIME_POLL_SECONDS = float(os.getenv("REALTIME_POLL_SECONDS", "2"))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"elastic_transport": {"level": "WARNING"}, "django.request": {"level": "WARNING"}},
}
