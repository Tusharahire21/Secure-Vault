"""
SecureVault Dashboard – DRF Serializers (U5)
"""
from rest_framework import serializers
from .models import Anomaly


class AnomalySerializer(serializers.ModelSerializer):
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)

    class Meta:
        model = Anomaly
        fields = [
            'id', 'event_type', 'event_type_display',
            'severity', 'severity_display',
            'ip', 'timestamp', 'count', 'status_code',
            'description', 'paths', 'raw_lines',
            'source_file', 'created_at',
        ]
        read_only_fields = ['id', 'created_at']


class AnomalySummarySerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""
    class Meta:
        model = Anomaly
        fields = ['id', 'event_type', 'severity', 'ip', 'timestamp', 'count', 'description']
