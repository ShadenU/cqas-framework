"""Structured logging utility for the CQAS framework."""

import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """Return a configured logger with structured output.

    Args:
        name: Logger name (typically __name__ of the calling module).
        level: Log level override. Defaults to LOG_LEVEL env var or INFO.

    Returns:
        Configured Logger instance.
    """
    log_level_str = level or os.getenv("LOG_LEVEL", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(log_level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = StructuredFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False

    return logger


class StructuredFormatter(logging.Formatter):
    """Formatter that outputs log records as structured key=value strings."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        level = record.levelname
        logger_name = record.name
        message = record.getMessage()

        base = f"time={timestamp} level={level} logger={logger_name} msg={message!r}"

        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            base += f" exception={exc_text!r}"

        extra_fields = {
            k: v
            for k, v in record.__dict__.items()
            if k
            not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
            }
        }
        for key, value in extra_fields.items():
            base += f" {key}={value!r}"

        return base


def add_file_handler(logger: logging.Logger, filepath: str) -> None:
    """Add a file handler to an existing logger.

    Args:
        logger: The logger to add the handler to.
        filepath: Absolute or relative path to the log file.
    """
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    file_handler = logging.FileHandler(filepath)
    file_handler.setFormatter(StructuredFormatter())
    logger.addHandler(file_handler)
