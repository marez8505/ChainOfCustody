"""
Utility functions for ChainOfCustody.

Author: Edward Marez
License: MIT
"""

import uuid
import hashlib
import json
from datetime import datetime, timezone


def generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def utc_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def format_timestamp(ts: str) -> str:
    """Format an ISO 8601 timestamp for human-readable display."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return str(ts)


def hash_string(value: str) -> str:
    """Compute SHA-256 hash of a string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_signature(examiner: str, timestamp: str, event_id: str) -> str:
    """
    Generate a deterministic digital signature for a custody event.

    The signature is a SHA-256 hash of the concatenation of:
        examiner name + timestamp + event_id

    This proves the examiner acknowledged the event at that timestamp.
    """
    payload = f"{examiner}|{timestamp}|{event_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def human_file_size(size_bytes: int | None) -> str:
    """Convert bytes to a human-readable size string."""
    if size_bytes is None:
        return "Unknown"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def sanitize_filename(name: str) -> str:
    """Replace filesystem-unsafe characters with underscores."""
    unsafe = r'<>:"/\\|?* '
    result = name
    for ch in unsafe:
        result = result.replace(ch, "_")
    return result


def evidence_number_from_index(index: int) -> str:
    """Convert integer index to formatted evidence number, e.g. 1 -> 'EV-001'."""
    return f"EV-{index:03d}"


def serialize_dict(d: dict) -> str:
    """Serialize a dict to a canonical JSON string (sorted keys)."""
    return json.dumps(d, sort_keys=True, default=str)
