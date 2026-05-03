"""Shared helper utilities for the CQAS framework."""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import yaml


def load_config(path: str) -> Dict[str, Any]:
    """Load a YAML configuration file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r") as fh:
        return yaml.safe_load(fh) or {}


def format_timestamp(dt: Optional[datetime] = None, fmt: str = "%Y-%m-%dT%H:%M:%SZ") -> str:
    """Format a datetime as an ISO 8601 string.

    Args:
        dt: Datetime to format. Defaults to current UTC time.
        fmt: strftime format string.

    Returns:
        Formatted timestamp string.
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(fmt)


def calculate_hash(data: Union[str, bytes], algorithm: str = "sha256") -> str:
    """Calculate a cryptographic hash of the given data.

    Args:
        data: String or bytes to hash.
        algorithm: Hash algorithm name (sha256, md5, sha1).

    Returns:
        Hex digest string.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw log event into the CQAS canonical schema.

    Canonical schema fields:
        - timestamp (str ISO 8601)
        - event_type (str)
        - src_ip (str or None)
        - dst_ip (str or None)
        - src_port (int or None)
        - dst_port (int or None)
        - username (str or None)
        - hostname (str or None)
        - action (str or None)
        - severity (str or None)
        - raw (dict) — original event preserved

    Args:
        raw: Raw event dictionary from any log source.

    Returns:
        Normalized event dictionary.
    """
    def _get(*keys: str) -> Any:
        for k in keys:
            if k in raw:
                return raw[k]
        return None

    timestamp = _get("timestamp", "@timestamp", "time", "event_time")
    if isinstance(timestamp, datetime):
        timestamp = format_timestamp(timestamp)
    elif timestamp is None:
        timestamp = format_timestamp()

    return {
        "timestamp": timestamp,
        "event_type": _get("event_type", "type", "category") or "unknown",
        "src_ip": _get("src_ip", "source_ip", "client_ip", "src"),
        "dst_ip": _get("dst_ip", "destination_ip", "dest_ip", "dst"),
        "src_port": _to_int(_get("src_port", "source_port")),
        "dst_port": _to_int(_get("dst_port", "destination_port", "port")),
        "username": _get("username", "user", "account"),
        "hostname": _get("hostname", "host", "computer"),
        "action": _get("action", "event_action", "result"),
        "severity": _get("severity", "level", "priority"),
        "message": _get("message", "msg", "description"),
        "raw": raw,
    }


def _to_int(value: Any) -> Optional[int]:
    """Convert a value to int, returning None on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def chunk_list(lst: List[Any], size: int) -> List[List[Any]]:
    """Split a list into chunks of the given size.

    Args:
        lst: Input list.
        size: Maximum chunk size.

    Returns:
        List of sublists.
    """
    return [lst[i : i + size] for i in range(0, len(lst), size)]


def deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge override into base dictionary.

    Args:
        base: Base dictionary.
        override: Dictionary with values to override.

    Returns:
        Merged dictionary (new object, base is not modified).
    """
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def safe_json_loads(text: str) -> Optional[Dict]:
    """Attempt to parse JSON, returning None on failure.

    Args:
        text: JSON string.

    Returns:
        Parsed dict or None.
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
