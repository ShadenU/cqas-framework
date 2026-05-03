"""Log parsing — transforms raw log strings into structured event dicts."""

import re
from typing import Dict, Any, List, Optional

from src.utils.helpers import normalize_event, safe_json_loads
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Common log patterns
_SYSLOG_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)"
)

_AUTH_FAILED_RE = re.compile(
    r"Failed (?P<auth_method>\w+) for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"
)

_AUTH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<auth_method>\w+) for (?P<username>\S+) "
    r"from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)"
)

_NETWORK_RE = re.compile(
    r"(?P<action>ACCEPT|DROP|REJECT)\s+.*?"
    r"SRC=(?P<src_ip>[\d.]+)\s+DST=(?P<dst_ip>[\d.]+)\s+"
    r".*?SPT=(?P<src_port>\d+)\s+DPT=(?P<dst_port>\d+)"
)


class LogParser:
    """Parse raw log entries into normalized CQAS event dicts.

    Supports JSON, syslog/RFC 3164, SSH auth logs, and iptables network logs.
    Falls back to a generic parser for unrecognized formats.
    """

    def parse(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a raw log entry dict into a normalized event.

        Args:
            entry: Dict with at least a 'raw' key containing the log string.

        Returns:
            Normalized event dictionary.
        """
        raw_text: str = entry.get("raw", "")
        source: str = entry.get("source", "unknown")

        parsed = (
            self._try_json(raw_text)
            or self._try_auth(raw_text)
            or self._try_network(raw_text)
            or self._try_syslog(raw_text)
            or self._generic(raw_text)
        )

        parsed["source"] = source
        if "timestamp" not in parsed or not parsed["timestamp"]:
            parsed["timestamp"] = entry.get("timestamp", "")

        return normalize_event(parsed)

    def parse_many(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse a list of raw log entries.

        Args:
            entries: List of raw entry dicts.

        Returns:
            List of normalized event dicts.
        """
        results = []
        for entry in entries:
            try:
                results.append(self.parse(entry))
            except Exception as exc:
                logger.warning(f"Failed to parse entry: {exc}", extra={"raw": entry.get("raw", "")[:200]})
        return results

    # ------------------------------------------------------------------ #
    # Private parsers                                                      #
    # ------------------------------------------------------------------ #

    def _try_json(self, text: str) -> Optional[Dict]:
        parsed = safe_json_loads(text)
        if parsed and isinstance(parsed, dict):
            return parsed
        return None

    def _try_auth(self, text: str) -> Optional[Dict]:
        m = _AUTH_FAILED_RE.search(text)
        if m:
            return {
                "event_type": "authentication",
                "action": "failure",
                "src_ip": m.group("src_ip"),
                "src_port": m.group("src_port"),
                "username": m.group("username"),
                "message": text,
            }
        m = _AUTH_ACCEPTED_RE.search(text)
        if m:
            return {
                "event_type": "authentication",
                "action": "success",
                "src_ip": m.group("src_ip"),
                "src_port": m.group("src_port"),
                "username": m.group("username"),
                "message": text,
            }
        return None

    def _try_network(self, text: str) -> Optional[Dict]:
        m = _NETWORK_RE.search(text)
        if m:
            return {
                "event_type": "network",
                "action": m.group("action").lower(),
                "src_ip": m.group("src_ip"),
                "dst_ip": m.group("dst_ip"),
                "src_port": m.group("src_port"),
                "dst_port": m.group("dst_port"),
                "message": text,
            }
        return None

    def _try_syslog(self, text: str) -> Optional[Dict]:
        m = _SYSLOG_RE.match(text)
        if m:
            return {
                "event_type": "syslog",
                "timestamp": m.group("timestamp"),
                "hostname": m.group("hostname"),
                "message": m.group("message"),
            }
        return None

    def _generic(self, text: str) -> Dict:
        return {"event_type": "unknown", "message": text}
