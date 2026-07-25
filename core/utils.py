"""
SecureVault – Utility Functions (U1: Fundamentals)
Covers: datetime parsing, string slicing helpers, formatting
"""

from datetime import datetime


# -------------------------------------------------------------------
# Timestamp Parsing (U1 – using datetime.strptime)
# -------------------------------------------------------------------

LOG_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"   # Apache combined log format


def parse_timestamp(raw: str) -> datetime | None:
    """Parse Apache log timestamp string into a datetime object.

    Args:
        raw: e.g. '10/Oct/2000:13:55:36 -0700'

    Returns:
        datetime object (timezone-aware) or None if parsing fails.
    """
    try:
        return datetime.strptime(raw.strip(), LOG_TIMESTAMP_FORMAT)
    except (ValueError, AttributeError):
        return None


def format_timestamp(dt: datetime) -> str:
    """Return a human-readable timestamp string."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# -------------------------------------------------------------------
# String Slicing / Extraction Helpers (U1 – string operations)
# -------------------------------------------------------------------

def extract_ip_from_line(line: str) -> str | None:
    """Extract the first token (IP address) from a log line using string slicing."""
    line = line.strip()
    if not line:
        return None
    # The IP is always the first space-delimited token in Apache logs
    space_idx = line.find(" ")
    return line[:space_idx] if space_idx != -1 else line


def extract_status_code(line: str) -> str | None:
    """Extract HTTP status code from a log line using string splitting."""
    parts = line.split('"')
    # After the request string (in quotes), next token is the status code
    if len(parts) >= 3:
        trailing = parts[2].strip().split()
        if trailing:
            return trailing[0]
    return None


def extract_request_path(request_str: str) -> str | None:
    """Given a request string like 'GET /path HTTP/1.1', return '/path'."""
    parts = request_str.strip().split()
    return parts[1] if len(parts) >= 2 else None


# -------------------------------------------------------------------
# Severity Helpers
# -------------------------------------------------------------------

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_rank(severity: str) -> int:
    """Return numeric rank for a severity string (for sorting)."""
    return SEVERITY_ORDER.get(severity.upper(), 0)


def severity_badge_class(severity: str) -> str:
    """Return Bootstrap badge CSS class for a severity level."""
    mapping = {
        "LOW": "success",
        "MEDIUM": "warning",
        "HIGH": "danger",
        "CRITICAL": "dark",
    }
    return mapping.get(severity.upper(), "secondary")
