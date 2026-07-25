#!/usr/bin/env python3
"""
SecureVault – ingest.py (CLI Entry Point)
=========================================
Ties together all 5 units:
  U1 – LogParser uses sets/dicts/string slicing
  U2 – AnomalyDetector calls detection functions, reads files
  U3 – OOP classes, regex, threading
  U4 – DBHandler stores results in MongoDB
  U5 – Results can be viewed in Django dashboard

Usage:
    python ingest.py                              # parse all logs/*.log files
    python ingest.py logs/sample_server.log       # parse specific file
    python ingest.py --report                     # also save JSON report
    python ingest.py --clear                      # clear MongoDB collection first
"""

import argparse
import sys
import os
from pathlib import Path

# Ensure project root is on sys.path so 'core' package resolves
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from core.log_parser import LogParser
from core.anomaly_detector import AnomalyDetector
from core.db_handler import DBHandler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ingest.py",
        description="SecureVault – Parse server logs and detect anomalies",
    )
    parser.add_argument(
        "log_files",
        nargs="*",
        help="Log file(s) to parse. Defaults to all .log files in logs/",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Save a JSON anomaly report to reports/",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing anomalies from MongoDB before ingesting",
    )
    parser.add_argument(
        "--no-mongo",
        action="store_true",
        help="Skip MongoDB insertion (useful if MongoDB is not running)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # ----------------------------------------------------------------
    # Resolve log files
    # ----------------------------------------------------------------
    if args.log_files:
        log_paths = [Path(p) for p in args.log_files]
    else:
        logs_dir = project_root / "logs"
        log_paths = list(logs_dir.glob("*.log"))
        if not log_paths:
            print(f"[ingest] No .log files found in {logs_dir}")
            sys.exit(1)

    print(f"[ingest] Found {len(log_paths)} log file(s):")
    for p in log_paths:
        print(f"         • {p}")

    # ----------------------------------------------------------------
    # U1 + U2 + U3: Parse logs & detect anomalies
    # ----------------------------------------------------------------
    detector = AnomalyDetector()          # U3 – OOP
    detector.load_files(log_paths)        # U3 – threading (parallel parse)
    anomalies = detector.run()            # U2 – detection functions
    detector.print_summary()

    # U1 – demonstrate sets and dicts
    parser: LogParser = detector.parser
    unique_ips = parser.get_unique_ips()          # U1 – set
    ip_counts  = parser.get_ip_counts()           # U1 – dict

    print(f"[U1] Unique IP addresses seen (set): {unique_ips}")
    print(f"[U1] Top 5 IPs by request count (dict):")
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_ips:
        print(f"     {ip:20s} -> {count} requests")

    # ----------------------------------------------------------------
    # U4: Store in MongoDB
    # ----------------------------------------------------------------
    if not args.no_mongo:
        try:
            db = DBHandler()                                    # U4 – connect
            if args.clear:
                removed = db.clear_all()
                print(f"[U4] Cleared {removed} existing documents from MongoDB.")
            inserted = db.insert_many_anomalies(anomalies)     # U4 – insert
            print(f"[U4] Inserted {inserted} anomaly documents into MongoDB.")

            # U4 – demo queries
            print(f"[U4] Total docs in collection : {db.count()}")
            print(f"[U4] Severity breakdown        : {db.count_by_severity()}")
            print(f"[U4] Top IPs in MongoDB        : {db.get_top_ips(3)}")
            db.close()
        except Exception as exc:
            print(f"[U4] MongoDB skipped: {exc}")
            print("     To run without MongoDB use: python ingest.py --no-mongo")
    else:
        print("[U4] MongoDB insertion skipped (--no-mongo flag set).")

    # ----------------------------------------------------------------
    # U2: Save JSON report (file I/O)
    # ----------------------------------------------------------------
    if args.report:
        reports_dir = project_root / "reports"
        reports_dir.mkdir(exist_ok=True)
        report_path = reports_dir / "latest_report.json"
        detector.generate_report(report_path)       # U2 – file I/O

    print("\n[ingest] Done! Open the Django dashboard to view results:")
    print("         python manage.py runserver")
    print("         http://127.0.0.1:8000/\n")


if __name__ == "__main__":
    main()
