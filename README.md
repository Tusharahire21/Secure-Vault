# SecureVault – README

A full-stack **Server Log Monitoring & Anomaly Detection System** built with Python 3.12 and Django.

---

## MCA Python Project Coverage

| Unit | Topic | Files |
|------|-------|-------|
| **U1** | Fundamentals – sets, dicts, string slicing, datetime | `core/utils.py`, `core/log_parser.py` |
| **U2** | Functions & Modules – detection functions, file I/O | `core/anomaly_detector.py` |
| **U3** | OOP / Regex / Threading | `core/log_parser.py`, `core/anomaly_detector.py` |
| **U4** | MongoDB – CRUD, indexes, filter, paginate | `core/db_handler.py` |
| **U5** | Django – Dashboard, DRF API | `dashboard/` |

---

## Project Structure

```
securevault/
├── core/
│   ├── utils.py            # U1: string/datetime utilities
│   ├── log_parser.py       # U1+U3: LogParser class (sets, dicts, regex, threading)
│   ├── anomaly_detector.py # U2+U3: AnomalyDetector class + detection functions
│   └── db_handler.py       # U4: MongoDB CRUD handler
├── dashboard/
│   ├── models.py           # U5: Anomaly Django model
│   ├── views.py            # U5: Dashboard views + filter
│   ├── api_views.py        # U5: DRF ViewSet
│   ├── serializers.py      # U5: DRF serializers
│   ├── urls.py             # Dashboard URL patterns
│   └── api_urls.py         # API URL patterns
├── templates/dashboard/
│   ├── base.html
│   ├── index.html          # Anomaly table + filters + breakdown
│   └── detail.html         # Single anomaly detail
├── static/dashboard/
│   ├── css/style.css
│   └── js/main.js
├── logs/
│   └── sample_server.log   # Sample Apache log with seeded anomalies
├── reports/                # Auto-generated JSON reports
├── ingest.py               # CLI entry point (ties all 5 units)
├── manage.py
└── requirements.txt
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run migrations
```bash
python manage.py migrate
```

### 3. Start the server
```bash
python manage.py runserver
```
Open: **http://127.0.0.1:8000/**

### 4. Ingest logs via browser
Click **"Run Ingest"** in the navbar to parse `logs/*.log` and load anomalies into the dashboard.

### 5. Ingest logs via CLI (with MongoDB)
```bash
# With MongoDB running:
python ingest.py --report

# Without MongoDB:
python ingest.py --no-mongo --report

# Parse specific file:
python ingest.py logs/sample_server.log
```

---

## Anomaly Detection Rules

| Rule | Condition | Severity |
|------|-----------|----------|
| **Brute Force** | >10 failed logins (401/403) from same IP in 60s | HIGH |
| **404 Flood** | >20 HTTP 404s from same IP | MEDIUM |
| **Path Scan** | >15 distinct paths from same IP in 30s | HIGH |
| **Suspicious Agent** | User-agent matches sqlmap, nikto, nmap, dirbuster, etc. | LOW |

---

## API Endpoints (DRF)

| Endpoint | Description |
|----------|-------------|
| `GET /api/anomalies/` | Paginated anomaly list |
| `GET /api/anomalies/?severity=HIGH` | Filter by severity |
| `GET /api/anomalies/?ip=10.0.0.15` | Filter by IP |
| `GET /api/anomalies/?search=brute` | Keyword search |
| `GET /api/anomalies/{id}/` | Single anomaly detail |
| `GET /api/anomalies/summary/` | Severity/event-type breakdown |
| `GET /api/anomalies/top-ips/` | Top 10 offending IPs |

---

## MongoDB (U4)

Ensure MongoDB is running on `localhost:27017`.

The `securevault_db` database with `anomalies` collection is created automatically on first ingest.
Indexes are created on: `ip`, `timestamp`, `severity`, `event_type`.
