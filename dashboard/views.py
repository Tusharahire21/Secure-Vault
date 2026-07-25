"""
SecureVault Dashboard – Views (U5)
Covers: paginated anomaly table, filter by IP/severity/date, detail view, ingest trigger
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.conf import settings

from .models import Anomaly


# ----------------------------------------------------------------
# Helper: get filter params from GET request
# ----------------------------------------------------------------

def _get_filters(request) -> dict:
    return {
        'ip':        request.GET.get('ip', '').strip(),
        'severity':  request.GET.get('severity', '').strip().upper(),
        'event_type': request.GET.get('event_type', '').strip(),
        'date_from': request.GET.get('date_from', '').strip(),
        'date_to':   request.GET.get('date_to', '').strip(),
        'search':    request.GET.get('search', '').strip(),
    }


def _apply_filters(qs, filters: dict):
    if filters['ip']:
        qs = qs.filter(ip__icontains=filters['ip'])
    if filters['severity']:
        qs = qs.filter(severity=filters['severity'])
    if filters['event_type']:
        qs = qs.filter(event_type=filters['event_type'])
    if filters['date_from']:
        qs = qs.filter(created_at__date__gte=filters['date_from'])
    if filters['date_to']:
        qs = qs.filter(created_at__date__lte=filters['date_to'])
    if filters['search']:
        qs = qs.filter(
            Q(description__icontains=filters['search']) |
            Q(ip__icontains=filters['search'])
        )
    return qs


# ----------------------------------------------------------------
# Views
# ----------------------------------------------------------------

def index(request):
    """
    Main dashboard view (U5):
    - Paginated anomaly table
    - Filter by IP, severity, event type, date range, keyword search
    """
    filters = _get_filters(request)
    qs = Anomaly.objects.all()
    qs = _apply_filters(qs, filters)

    # Summary stats for the top cards
    total        = Anomaly.objects.count()
    high_count   = Anomaly.objects.filter(severity__in=['HIGH', 'CRITICAL']).count()
    unique_ips   = Anomaly.objects.values('ip').distinct().count()

    # Severity breakdown for mini-chart
    severity_stats = (
        Anomaly.objects.values('severity')
        .annotate(count=Count('id'))
        .order_by('severity')
    )
    event_stats = (
        Anomaly.objects.values('event_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    paginator = Paginator(qs, settings.ANOMALY_PAGE_SIZE)
    page_obj  = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj':       page_obj,
        'filters':        filters,
        'total':          total,
        'high_count':     high_count,
        'unique_ips':     unique_ips,
        'severity_stats': list(severity_stats),
        'event_stats':    list(event_stats),
        'severity_choices': Anomaly.SEVERITY_CHOICES,
        'event_choices':    Anomaly.EVENT_TYPE_CHOICES,
    }
    return render(request, 'dashboard/index.html', context)


def detail(request, pk: int):
    """Single anomaly detail view (U5)."""
    anomaly = get_object_or_404(Anomaly, pk=pk)
    return render(request, 'dashboard/detail.html', {'anomaly': anomaly})


def api_stats(request):
    """Quick JSON stats endpoint used by dashboard JS for chart data."""
    severity_data = list(
        Anomaly.objects.values('severity').annotate(count=Count('id'))
    )
    event_data = list(
        Anomaly.objects.values('event_type').annotate(count=Count('id'))
    )
    top_ips = list(
        Anomaly.objects.values('ip').annotate(count=Count('id')).order_by('-count')[:10]
    )
    return JsonResponse({
        'severity': severity_data,
        'event_types': event_data,
        'top_ips': top_ips,
        'total': Anomaly.objects.count(),
    })


@require_POST
def ingest_log(request):
    """
    Trigger log ingestion from the web UI (U5 + ties all units together).
    Parses uploaded or existing log files and inserts anomalies into DB.
    """
    # Add project root to sys.path so core modules resolve
    project_root = str(settings.BASE_DIR)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    try:
        from core.log_parser import LogParser
        from core.anomaly_detector import AnomalyDetector
        from core.db_handler import DBHandler

        log_dir = Path(settings.LOGS_DIR)
        log_files = list(log_dir.glob('*.log'))

        if not log_files:
            messages.warning(request, 'No .log files found in the logs/ directory.')
            return redirect('dashboard:index')

        detector = AnomalyDetector()
        detector.load_files(log_files)
        anomalies = detector.run()

        # Store in MongoDB
        inserted_mongo = 0
        try:
            db = DBHandler()
            inserted_mongo = db.insert_many_anomalies(anomalies)
            db.close()
        except Exception as mongo_exc:
            messages.warning(request, f'MongoDB unavailable ({mongo_exc}), saving to SQLite only.')

        # Store in Django SQLite (dashboard cache)
        Anomaly.objects.all().delete()   # Clear old data before fresh ingest
        objs = []
        for a in anomalies:
            objs.append(Anomaly(
                event_type=a.event_type,
                severity=a.severity,
                ip=a.ip,
                timestamp=a.timestamp,
                count=a.count,
                status_code=a.status_code,
                description=a.description,
                paths=a.paths,
                raw_lines=a.raw_lines,
                source_file=a.source_file,
            ))
        Anomaly.objects.bulk_create(objs)

        # Save JSON report
        reports_dir = Path(settings.REPORTS_DIR)
        reports_dir.mkdir(exist_ok=True)
        detector.generate_report(reports_dir / 'latest_report.json')

        messages.success(
            request,
            f'Ingested {len(log_files)} log file(s). '
            f'Detected {len(anomalies)} anomalies. '
            f'MongoDB: {inserted_mongo} inserted.'
        )

    except Exception as exc:
        messages.error(request, f'Ingestion error: {exc}')

    return redirect('dashboard:index')
