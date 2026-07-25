"""
SecureVault – DRF API URL patterns
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from dashboard.api_views import AnomalyViewSet

router = DefaultRouter()
router.register(r'anomalies', AnomalyViewSet, basename='anomaly-api')

urlpatterns = [
    path('', include(router.urls)),
]
