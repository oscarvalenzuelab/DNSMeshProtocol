"""Structured-logging setup for DMP nodes.

`configure_logging()` is idempotent and lets the node pick between a plain
human-readable formatter (default) and a one-event-per-line JSON formatter
(`DMP_LOG_FORMAT=json`). JSON logs are what ops teams want to ingest into a
logging pipeline; the human format stays useful for `docker logs` tailing.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Dict


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON object.

    Extra fields attached to the record via `logger.info("msg", extra={"k": "v"})`
    are surfaced as top-level keys, alongside the standard level/logger/msg.
    """

    _STANDARD_ATTRS = {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.gmtime(record.created),
            ) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key in self._STANDARD_ATTRS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except TypeError:
                payload[key] = repr(value)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO", format_: str = "text") -> None:
    """Install a stdout handler with the chosen format and level.

    Safe to call multiple times — replaces any existing handlers on the
    root logger rather than stacking them.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    if format_.lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
    root.addHandler(handler)
