"""
MongoDB needs every model to use ObjectIdAutoField as its primary key.
Django's built-in apps (admin, auth, contenttypes) set their own key type,
so we override them here and list these classes in INSTALLED_APPS.
"""
from django.contrib.admin.apps import AdminConfig
from django.contrib.auth.apps import AuthConfig
from django.contrib.contenttypes.apps import ContentTypesConfig

MONGO_PK = "django_mongodb_backend.fields.ObjectIdAutoField"


class MongoAdminConfig(AdminConfig):
    default_auto_field = MONGO_PK


class MongoAuthConfig(AuthConfig):
    default_auto_field = MONGO_PK


class MongoContentTypesConfig(ContentTypesConfig):
    default_auto_field = MONGO_PK
