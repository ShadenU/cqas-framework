"""Log collection from files, directories, and syslog sources."""

import os
import socket
import socketserver
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Generator, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class LogCollector:
    """Collects log entries from files and syslog listeners.

    Supports:
    - Tailing one or more log files (like `tail -f`)
    - Batch reading from a log file
    - UDP syslog listener on a configurable port

    Args:
        sources: List of file paths to collect from.
        syslog_host: Host to bind the syslog listener (default: '0.0.0.0').
        syslog_port: UDP port for syslog listener (default: 514).
    """

    def __init__(
        self,
        sources: Optional[List[str]] = None,
        syslog_host: str = "0.0.0.0",
        syslog_port: int = 514,
    ) -> None:
        self.sources = sources or []
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self._syslog_server: Optional[socketserver.UDPServer] = None
        self._syslog_thread: Optional[threading.Thread] = None
        self._collected: List[dict] = []

    def read_file(self, filepath: str) -> Generator[dict, None, None]:
        """Read all lines from a log file and yield structured entries.

        Args:
            filepath: Path to the log file.

        Yields:
            Dict with 'raw', 'source', and 'timestamp' keys.
        """
        if not os.path.isfile(filepath):
            logger.warning(f"Log file not found: {filepath}")
            return
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line:
                    yield self._wrap(line, source=filepath)

    def tail_file(
        self,
        filepath: str,
        callback: Callable[[dict], None],
        poll_interval: float = 1.0,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        """Tail a log file and invoke callback for each new line.

        Args:
            filepath: Path to the log file to tail.
            callback: Function called with each new log entry dict.
            poll_interval: Seconds between file reads.
            stop_event: Threading event to signal collection stop.
        """
        if not os.path.isfile(filepath):
            logger.error(f"Cannot tail missing file: {filepath}")
            return

        with open(filepath, "r", errors="replace") as fh:
            fh.seek(0, 2)  # seek to end
            logger.info(f"Tailing file: {filepath}")
            while not (stop_event and stop_event.is_set()):
                line = fh.readline()
                if line:
                    callback(self._wrap(line.rstrip("\n"), source=filepath))
                else:
                    time.sleep(poll_interval)

    def collect_all(self) -> List[dict]:
        """Read all configured source files and return collected entries.

        Returns:
            List of log entry dicts.
        """
        entries = []
        for filepath in self.sources:
            for entry in self.read_file(filepath):
                entries.append(entry)
        logger.info(f"Collected {len(entries)} entries from {len(self.sources)} sources")
        return entries

    def start_syslog_listener(self, callback: Callable[[dict], None]) -> None:
        """Start a UDP syslog listener in a background thread.

        Args:
            callback: Function called for each received syslog message.
        """
        collector = self

        class SyslogHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                data = self.request[0].decode("utf-8", errors="replace").strip()
                if data:
                    entry = collector._wrap(data, source=f"syslog:{self.client_address[0]}")
                    callback(entry)

        self._syslog_server = socketserver.UDPServer(
            (self.syslog_host, self.syslog_port), SyslogHandler
        )
        self._syslog_thread = threading.Thread(
            target=self._syslog_server.serve_forever, daemon=True
        )
        self._syslog_thread.start()
        logger.info(f"Syslog listener started on {self.syslog_host}:{self.syslog_port}/udp")

    def stop_syslog_listener(self) -> None:
        """Stop the UDP syslog listener."""
        if self._syslog_server:
            self._syslog_server.shutdown()
            logger.info("Syslog listener stopped")

    @staticmethod
    def _wrap(raw: str, source: str = "unknown") -> dict:
        return {
            "raw": raw,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
