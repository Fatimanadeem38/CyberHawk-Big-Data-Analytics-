from rest_framework import serializers

from .models import AlertStatus, InvestigationNote


class StatusUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=AlertStatus.choices, required=False)
    note = serializers.CharField(required=False, allow_blank=True, max_length=5000)
    assign_to_me = serializers.BooleanField(required=False, default=False)
    resolution_summary = serializers.CharField(required=False, allow_blank=True, max_length=2000)

    def validate(self, data):
        if not data.get("status") and not data.get("assign_to_me") and not data.get("note"):
            raise serializers.ValidationError("Nothing to update.")
        return data


class NoteSerializer(serializers.ModelSerializer):
    id = serializers.CharField(read_only=True)  # MongoDB ObjectId -> string
    author = serializers.CharField(source="author.username", read_only=True, default="")

    class Meta:
        model = InvestigationNote
        fields = ["id", "alert_id", "author", "text", "created_at"]
        read_only_fields = ["id", "alert_id", "author", "created_at"]

    def validate_text(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Note text cannot be empty.")
        return value
