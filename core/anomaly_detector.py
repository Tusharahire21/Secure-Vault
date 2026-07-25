"""
SecureVault – AnomalyDetector (U2 + U3)
Covers:
  U2 – Separate module imported from log_parser; standalone detection functions;
       file I/O with exception handling
  U3 – OOP (AnomalyDetector class), threading already handled via LogParser
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from core.log_parser import LogParser, LogEntry
from core.utils import format_timestamp, severity_rank


# -------------------------------------------------------------------
# Anomaly Dataclass
# -------------------------------------------------------------------

@dataclass
class Anomaly:
    """Represents a detected anomaly/security event."""
    event_type: str          # e.g. "BRUTE_FORCE", "404_FLOOD", etc.
    severity: str            # LOW | MEDIUM | HIGH | CRITICAL
    ip: str
    timestamp: str           # ISO format string (for JSON / MongoDB)
    count: int               # How many occurrences triggered this anomaly
    status_code: int
    description: str
    paths: list[str] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)
    source_file: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# -------------------------------------------------------------------
# Detection Functions (U2 – standalone functions)
# -------------------------------------------------------------------

def detect_brute_force(
    entries: list[LogEntry],
    threshold: int = 10,
    window_seconds: int = 60,
) -> list[Anomaly]:
    """
    Detect brute-force login attempts (U2 – function with file I/O dependency).

    Rule: >threshold failed auth (401/403) from same IP within window_seconds.
    """
    anomalies: list[Anomaly] = []
    # Group auth-failure entries by IP
    ip_failures: dict[str, list[LogEntry]] = {}
    for entry in entries:
        if entry.is_auth_failure:
            ip_failures.setdefault(entry.ip, []).append(entry)

    for ip, failures in ip_failures.items():
        # Sort by timestamp
        timed = [f for f in failures if f.timestamp is not None]
        timed.sort(key=lambda e: e.timestamp)

        # Sliding window check
        window = timedelta(seconds=window_seconds)
        i = 0
        while i < len(timed):
            j = i
            while j < len(timed) and (timed[j].timestamp - timed[i].timestamp) <= window:
                j += 1
            count = j - i
            if count >= threshold:
                ts = format_timestamp(timed[i].timestamp)
                anomalies.append(Anomaly(
                    event_type="BRUTE_FORCE",
                    severity="HIGH",
                    ip=ip,
                    timestamp=ts,
                    count=count,
                    status_code=timed[i].status,
                    description=f"{count} failed auth attempts from {ip} within {window_seconds}s",
                    paths=list({e.path for e in timed[i:j]}),
                    raw_lines=[e.raw_line for e in timed[i:j]][:5],
                    source_file=timed[i].source_file,
                ))
                i = j  # Skip past this window
            else:
                i += 1

    return anomalies


def detect_404_flood(
    entries: list[LogEntry],
    threshold: int = 20,
) -> list[Anomaly]:
    """
    Detect 404 flooding from the same IP (U2 – function).

    Rule: >threshold HTTP 404 responses to a single IP.
    """
    anomalies: list[Anomaly] = []
    ip_404: dict[str, list[LogEntry]] = {}
    for entry in entries:
        if entry.status == 404:
            ip_404.setdefault(entry.ip, []).append(entry)

    for ip, hits in ip_404.items():
        if len(hits) >= threshold:
            first = hits[0]
            anomalies.append(Anomaly(
                event_type="404_FLOOD",
                severity="MEDIUM",
                ip=ip,
                timestamp=format_timestamp(first.timestamp),
                count=len(hits),
                status_code=404,
                description=f"{len(hits)} HTTP 404 errors from {ip}",
                paths=list({e.path for e in hits})[:10],
                raw_lines=[e.raw_line for e in hits][:5],
                source_file=first.source_file,
            ))

    return anomalies


def detect_port_scan(
    entries: list[LogEntry],
    threshold: int = 15,
    window_seconds: int = 30,
) -> list[Anomaly]:
    """
    Detect port/path scanning behaviour (U2 – function).

    Rule: >threshold distinct paths from same IP within window_seconds.
    """
    anomalies: list[Anomaly] = []
    ip_entries: dict[str, list[LogEntry]] = {}
    for entry in entries:
        if entry.timestamp:
            ip_entries.setdefault(entry.ip, []).append(entry)

    window = timedelta(seconds=window_seconds)

    for ip, ents in ip_entries.items():
        ents.sort(key=lambda e: e.timestamp)
        i = 0
        while i < len(ents):
            j = i
            paths_in_window: set[str] = set()
            while j < len(ents) and (ents[j].timestamp - ents[i].timestamp) <= window:
                paths_in_window.add(ents[j].path)
                j += 1
            if len(paths_in_window) >= threshold:
                ts = format_timestamp(ents[i].timestamp)
                anomalies.append(Anomaly(
                    event_type="PATH_SCAN",
                    severity="HIGH",
                    ip=ip,
                    timestamp=ts,
                    count=len(paths_in_window),
                    status_code=ents[i].status,
                    description=f"{len(paths_in_window)} distinct paths probed by {ip} in {window_seconds}s",
                    paths=list(paths_in_window)[:10],
                    raw_lines=[e.raw_line for e in ents[i:j]][:5],
                    source_file=ents[i].source_file,
                ))
                i = j
            else:
                i += 1

    return anomalies


def detect_suspicious_agents(entries: list[LogEntry]) -> list[Anomaly]:
    """
    Detect known malicious/scanning user-agents (U2 – function).

    Rule: User-agent matches known bad patterns (regex in LogEntry.has_suspicious_agent).
    """
    anomalies: list[Anomaly] = []
    # Group by IP
    ip_bad: dict[str, list[LogEntry]] = {}
    for entry in entries:
        if entry.has_suspicious_agent:
            ip_bad.setdefault(entry.ip, []).append(entry)

    for ip, hits in ip_bad.items():
        first = hits[0]
        anomalies.append(Anomaly(
            event_type="SUSPICIOUS_AGENT",
            severity="LOW",
            ip=ip,
            timestamp=format_timestamp(first.timestamp),
            count=len(hits),
            status_code=first.status,
            description=f"Suspicious user-agent detected from {ip}: {first.user_agent[:80]}",
            paths=list({e.path for e in hits})[:5],
            raw_lines=[e.raw_line for e in hits][:5],
            source_file=first.source_file,
        ))

    return anomalies


# -------------------------------------------------------------------
# AnomalyDetector Class (U3 – OOP)
# -------------------------------------------------------------------

class AnomalyDetector:
    """
    Orchestrates anomaly detection over parsed log entries.

    Demonstrates:
    - OOP: __init__, run(), flag_anomalies(), generate_report()
    - U2:  calls standalone detection functions (separate module)
    - File I/O: generate_report() writes JSON report with exception handling
    """

    def __init__(self, parser: LogParser | None = None):
        self.parser = parser or LogParser()
        self._anomalies: list[Anomaly] = []

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def load_file(self, filepath: str | Path) -> None:
        """Parse a single log file (U2 – file I/O with exception handling)."""
        try:
            self.parser.parse_file(filepath)
        except Exception as exc:
            print(f"[AnomalyDetector] Failed to load {filepath}: {exc}")

    def load_files(self, filepaths: list[str | Path]) -> None:
        """Parse multiple log files in parallel (uses LogParser threading)."""
        try:
            self.parser.parse_files(filepaths)
        except Exception as exc:
            print(f"[AnomalyDetector] Failed to load files: {exc}")

    def run(self) -> list[Anomaly]:
        """
        Run all detection rules against parsed entries.

        Returns a sorted list of Anomaly objects (by severity desc).
        """
        entries = self.parser.get_entries()
        print(f"[AnomalyDetector] Analysing {len(entries)} log entries ...")

        self._anomalies = self.flag_anomalies(entries)
        self._anomalies.sort(key=lambda a: severity_rank(a.severity), reverse=True)

        print(f"[AnomalyDetector] Found {len(self._anomalies)} anomalies.")
        return self._anomalies

    def flag_anomalies(self, entries: list[LogEntry]) -> list[Anomaly]:
        """Apply all detection functions and aggregate results (U2 – functions)."""
        results: list[Anomaly] = []
        results.extend(detect_brute_force(entries))
        results.extend(detect_404_flood(entries))
        results.extend(detect_port_scan(entries))
        results.extend(detect_suspicious_agents(entries))
        return results

    def get_anomalies(self) -> list[Anomaly]:
        """Return detected anomalies."""
        return list(self._anomalies)

    def generate_report(self, output_path: str | Path = "securevault_report.json") -> None:
        """
        Write anomaly report to a JSON file (U2 – file I/O with exception handling).

        Args:
            output_path: Destination file path.
        """
        output_path = Path(output_path)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_entries_parsed": len(self.parser.get_entries()),
            "unique_ips": len(self.parser.get_unique_ips()),
            "total_anomalies": len(self._anomalies),
            "anomalies": [a.to_dict() for a in self._anomalies],
        }
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            print(f"[AnomalyDetector] Report saved to {output_path}")
        except OSError as exc:
            print(f"[AnomalyDetector] ERROR writing report: {exc}")

    def print_summary(self) -> None:
        """Print a CLI summary of detected anomalies."""
        print("\n" + "=" * 60)
        print(f"  SecureVault – Anomaly Detection Report")
        print("=" * 60)
        print(f"  Total entries parsed : {len(self.parser.get_entries())}")
        print(f"  Unique IPs seen      : {len(self.parser.get_unique_ips())}")
        print(f"  Anomalies detected   : {len(self._anomalies)}")
        print("-" * 60)
        for a in self._anomalies:
            print(f"  [{a.severity:8s}] {a.event_type:20s} | IP: {a.ip:15s} | {a.description[:50]}")
        print("=" * 60 + "\n")
