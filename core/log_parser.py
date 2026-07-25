"""
SecureVault – LogParser (U1 + U3)
Covers:
  U1  – Sets (unique IPs), dicts (IP → count), string slicing
  U3  – OOP (LogParser class), Regex (IP, timestamp, status, user-agent),
         Threading (ThreadPoolExecutor for parallel file processing)
"""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.utils import parse_timestamp, extract_request_path


# -------------------------------------------------------------------
# Regex Patterns (U3 – Regular Expressions)
# -------------------------------------------------------------------

# Apache Combined Log Format:
# 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "http://ref.com" "Mozilla/5.0"
_LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'          # IP address
    r'\s+\S+\s+\S+\s+'                            # ident, auth
    r'\[(?P<timestamp>[^\]]+)\]'                  # [timestamp]
    r'\s+"(?P<request>[^"]*)"'                    # "request"
    r'\s+(?P<status>\d{3})'                       # status code
    r'\s+(?P<size>\S+)'                           # response size
    r'(?:\s+"(?P<referrer>[^"]*)")?'              # optional referrer
    r'(?:\s+"(?P<user_agent>[^"]*)")?'            # optional user-agent
)

# Known suspicious user-agent substrings
_BAD_AGENTS = re.compile(
    r'(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|havij|acunetix)',
    re.IGNORECASE
)


# -------------------------------------------------------------------
# Parsed Log Entry Dataclass
# -------------------------------------------------------------------

@dataclass
class LogEntry:
    """Represents one parsed line from a server log file."""
    ip: str
    timestamp: Optional[datetime]
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referrer: str
    user_agent: str
    raw_line: str
    source_file: str = ""

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    @property
    def is_auth_failure(self) -> bool:
        return self.status in (401, 403)

    @property
    def has_suspicious_agent(self) -> bool:
        return bool(_BAD_AGENTS.search(self.user_agent))


# -------------------------------------------------------------------
# LogParser Class (U3 – OOP)
# -------------------------------------------------------------------

class LogParser:
    """
    Parses Apache/Nginx combined-format log files.

    Demonstrates:
    - OOP: __init__, instance methods, properties
    - Regex: compiled patterns for structured extraction
    - U1:  sets (unique IPs), dicts (IP → login attempt count)
    - Threading: parse_files() uses ThreadPoolExecutor
    """

    def __init__(self):
        self._entries: list[LogEntry] = []
        self._lock = threading.Lock()           # Thread-safe list appending (U3)
        self._unique_ips: set[str] = set()      # U1 – set for unique IPs
        self._ip_counts: dict[str, int] = {}    # U1 – dict for IP frequency

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def parse_file(self, filepath: str | Path) -> list[LogEntry]:
        """Parse a single log file and return its entries."""
        filepath = Path(filepath)
        entries: list[LogEntry] = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    entry = self._parse_line(line, source=str(filepath))
                    if entry:
                        entries.append(entry)
        except OSError as exc:
            print(f"[LogParser] ERROR reading {filepath}: {exc}")

        with self._lock:
            self._entries.extend(entries)
            for e in entries:
                self._unique_ips.add(e.ip)                          # U1 – set
                self._ip_counts[e.ip] = self._ip_counts.get(e.ip, 0) + 1  # U1 – dict

        return entries

    def parse_files(self, filepaths: list[str | Path], max_workers: int = 4) -> list[LogEntry]:
        """
        Parse multiple log files IN PARALLEL using ThreadPoolExecutor (U3 – Threading).

        Args:
            filepaths:   List of paths to log files.
            max_workers: Number of parallel threads.

        Returns:
            Combined list of all parsed LogEntry objects.
        """
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.parse_file, fp): fp for fp in filepaths}
            for future in as_completed(futures):
                fp = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"[LogParser] Thread error for {fp}: {exc}")

        return list(self._entries)

    def get_unique_ips(self) -> set[str]:
        """Return the set of all unique IP addresses seen (U1 – sets)."""
        return set(self._unique_ips)

    def get_ip_counts(self) -> dict[str, int]:
        """Return a dict mapping IP → total request count (U1 – dicts)."""
        return dict(self._ip_counts)

    def get_entries(self) -> list[LogEntry]:
        """Return all parsed entries."""
        return list(self._entries)

    def get_entries_by_ip(self, ip: str) -> list[LogEntry]:
        """Filter entries by IP address."""
        return [e for e in self._entries if e.ip == ip]

    def get_entries_by_status(self, status: int) -> list[LogEntry]:
        """Filter entries by HTTP status code."""
        return [e for e in self._entries if e.status == status]

    def reset(self):
        """Clear all parsed data."""
        with self._lock:
            self._entries.clear()
            self._unique_ips.clear()
            self._ip_counts.clear()

    # ----------------------------------------------------------------
    # Private Helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _parse_line(line: str, source: str = "") -> Optional[LogEntry]:
        """
        Parse one log line using regex (U3) and string operations (U1).

        Returns a LogEntry or None if the line doesn't match.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        match = _LOG_PATTERN.match(line)
        if not match:
            return None

        request_parts = match.group("request").split()
        method   = request_parts[0] if len(request_parts) > 0 else "-"
        path     = request_parts[1] if len(request_parts) > 1 else "/"
        protocol = request_parts[2] if len(request_parts) > 2 else "HTTP/1.1"

        # U1 – string slicing: keep only path (strip query string)
        clean_path = path.split("?")[0] if "?" in path else path

        try:
            size = int(match.group("size"))
        except (ValueError, TypeError):
            size = 0

        return LogEntry(
            ip=match.group("ip"),
            timestamp=parse_timestamp(match.group("timestamp")),
            method=method,
            path=clean_path,
            protocol=protocol,
            status=int(match.group("status")),
            size=size,
            referrer=match.group("referrer") or "-",
            user_agent=match.group("user_agent") or "-",
            raw_line=line,
            source_file=source,
        )
