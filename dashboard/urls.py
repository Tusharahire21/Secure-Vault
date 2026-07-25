"""
SecureVault Dashboard – URL patterns
"""
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('anomaly/<int:pk>/', views.detail, name='detail'),
    path('ingest/', views.ingest_log, name='ingest'),
    path('api/stats/', views.api_stats, name='api_stats'),
]
