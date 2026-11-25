from django.contrib import admin

from .models import GeneratorHeartbeat, IngestionControl, ScenarioRequest, UploadJob

admin.site.register(IngestionControl)
admin.site.register(GeneratorHeartbeat)


@admin.register(ScenarioRequest)
class ScenarioRequestAdmin(admin.ModelAdmin):
    list_display = ("scenario", "requested_by", "created_at", "consumed_at")


@admin.register(UploadJob)
class UploadJobAdmin(admin.ModelAdmin):
    list_display = ("filename", "status", "rows_total", "rows_valid", "rows_published", "uploaded_by", "created_at")
