"""
SecureVault Dashboard – Models (U5)
Uses SQLite (Django ORM) as a cache/mirror of MongoDB data.
The Anomaly model stores flagged events for the dashboard.
"""
from django.db import models


class Anomaly(models.Model):
    """
    Represents a flagged security anomaly event.
    Mirrors the MongoDB document structure for the Django dashboard.
    """

    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    EVENT_TYPE_CHOICES = [
        ('BRUTE_FORCE', 'Brute Force'),
        ('404_FLOOD', '404 Flood'),
        ('PATH_SCAN', 'Path Scan'),
        ('SUSPICIOUS_AGENT', 'Suspicious Agent'),
    ]

    event_type   = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES, db_index=True)
    severity     = models.CharField(max_length=10, choices=SEVERITY_CHOICES, db_index=True)
    ip           = models.GenericIPAddressField(db_index=True)
    timestamp    = models.CharField(max_length=30, db_index=True)
    count        = models.IntegerField(default=1)
    status_code  = models.IntegerField(default=200)
    description  = models.TextField()
    paths        = models.JSONField(default=list, blank=True)
    raw_lines    = models.JSONField(default=list, blank=True)
    source_file  = models.CharField(max_length=255, blank=True)
    created_at   = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Anomaly'
        verbose_name_plural = 'Anomalies'

    def __str__(self):
        return f"[{self.severity}] {self.event_type} from {self.ip} at {self.timestamp}"

    @property
    def severity_class(self):
        """Return Bootstrap badge class for this severity."""
        mapping = {
            'LOW': 'success',
            'MEDIUM': 'warning',
            'HIGH': 'danger',
            'CRITICAL': 'dark',
        }
        return mapping.get(self.severity, 'secondary')

    @property
    def event_icon(self):
        """Return Bootstrap icon name for this event type."""
        mapping = {
            'BRUTE_FORCE': 'shield-exclamation',
            '404_FLOOD': 'exclamation-triangle',
            'PATH_SCAN': 'binoculars',
            'SUSPICIOUS_AGENT': 'bug',
        }
        return mapping.get(self.event_type, 'question-circle')
