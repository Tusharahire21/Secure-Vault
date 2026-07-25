"""
SecureVault Dashboard – DRF API Views (U5)
Endpoint: /api/anomalies/  (list, filter, paginate, search)
"""
from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count

from .models import Anomaly
from .serializers import AnomalySerializer, AnomalySummarySerializer


class AnomalyViewSet(viewsets.ReadOnlyModelViewSet):
    """
    DRF ViewSet for anomalies (U5 – Django REST Framework).

    Endpoints:
      GET  /api/anomalies/          – paginated list with filters
      GET  /api/anomalies/{id}/     – single anomaly detail
      GET  /api/anomalies/summary/  – severity/event-type breakdown
      GET  /api/anomalies/top_ips/  – top offending IPs
    """
    queryset = Anomaly.objects.all()
    serializer_class = AnomalySerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]

    # DjangoFilterBackend: exact matches
    filterset_fields = ['severity', 'event_type', 'ip', 'status_code']

    # SearchFilter: keyword search
    search_fields = ['ip', 'description', 'event_type']

    # OrderingFilter: ?ordering=-created_at
    ordering_fields = ['created_at', 'severity', 'count', 'ip']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return AnomalySummarySerializer
        return AnomalySerializer

    @action(detail=False, methods=['get'], url_path='summary')
    def summary(self, request):
        """Returns severity and event-type counts for charting."""
        severity_data = list(
            Anomaly.objects.values('severity').annotate(count=Count('id'))
        )
        event_data = list(
            Anomaly.objects.values('event_type').annotate(count=Count('id'))
        )
        return Response({
            'total': Anomaly.objects.count(),
            'severity_breakdown': severity_data,
            'event_type_breakdown': event_data,
        })

    @action(detail=False, methods=['get'], url_path='top-ips')
    def top_ips(self, request):
        """Returns top 10 IPs by anomaly count."""
        top = list(
            Anomaly.objects.values('ip')
            .annotate(count=Count('id'))
            .order_by('-count')[:10]
        )
        return Response(top)
