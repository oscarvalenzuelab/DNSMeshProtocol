"""Tiny in-process metrics registry + Prometheus text exposition.

Avoids a dependency on prometheus_client. We only expose a handful of
counters and gauges, so a custom 50-line implementation is simpler than
pulling a 100 KiB library. Labels are supported via a frozen-tuple key.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

_LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_METRIC_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
LabelSet = Tuple[Tuple[str, str], ...]  # sorted tuple of (label, value) pairs


def _format_labels(labels: LabelSet) -> str:
    if not labels:
        return ""
    parts = []
    for k, v in labels:
        # Escape backslash, quote, and newline per Prom text format spec.
        esc = v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        parts.append(f'{k}="{esc}"')
    return "{" + ",".join(parts) + "}"


@dataclass
class _Metric:
    name: str
    help_text: str
    kind: str  # "counter" or "gauge"
    values: Dict[LabelSet, float]

    def __post_init__(self):
        if not _METRIC_NAME_RE.match(self.name):
            raise ValueError(f"invalid metric name: {self.name}")


class MetricsRegistry:
    """Thread-safe counter + gauge store with a Prometheus text rendering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._metrics: Dict[str, _Metric] = {}
        # Gauges can be populated lazily at scrape time (e.g. live row counts).
        self._lazy_gauges: Dict[str, Callable[[], float]] = {}

    def counter(
        self,
        name: str,
        help_text: str = "",
        labels: Optional[Dict[str, str]] = None,
        amount: float = 1.0,
    ) -> None:
        self._bump(name, "counter", help_text, labels, amount)

    def gauge(
        self,
        name: str,
        value: float,
        help_text: str = "",
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        self._set(name, "gauge", help_text, labels, value)

    def register_lazy_gauge(
        self,
        name: str,
        provider: Callable[[], float],
        help_text: str = "",
    ) -> None:
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = _Metric(name, help_text, "gauge", {})
            self._lazy_gauges[name] = provider

    def render(self) -> str:
        """Prometheus text format."""
        out_lines = []
        with self._lock:
            for name, metric in sorted(self._metrics.items()):
                if metric.help_text:
                    out_lines.append(f"# HELP {name} {metric.help_text}")
                out_lines.append(f"# TYPE {name} {metric.kind}")
                if name in self._lazy_gauges:
                    try:
                        value = float(self._lazy_gauges[name]())
                    except Exception:
                        continue
                    out_lines.append(f"{name} {value}")
                    continue
                for labels, value in sorted(metric.values.items()):
                    out_lines.append(f"{name}{_format_labels(labels)} {value}")
        return "\n".join(out_lines) + "\n"

    def _bump(
        self,
        name: str,
        kind: str,
        help_text: str,
        labels: Optional[Dict[str, str]],
        amount: float,
    ) -> None:
        key = self._label_key(labels)
        with self._lock:
            metric = self._metrics.setdefault(
                name, _Metric(name=name, help_text=help_text, kind=kind, values={})
            )
            metric.values[key] = metric.values.get(key, 0.0) + amount

    def _set(
        self,
        name: str,
        kind: str,
        help_text: str,
        labels: Optional[Dict[str, str]],
        value: float,
    ) -> None:
        key = self._label_key(labels)
        with self._lock:
            metric = self._metrics.setdefault(
                name, _Metric(name=name, help_text=help_text, kind=kind, values={})
            )
            metric.values[key] = value

    @staticmethod
    def _label_key(labels: Optional[Dict[str, str]]) -> LabelSet:
        if not labels:
            return ()
        for k in labels:
            if not _LABEL_NAME_RE.match(k):
                raise ValueError(f"invalid label name: {k}")
        return tuple(sorted(labels.items()))


# Process-global registry; DMPNode populates it at startup.
REGISTRY = MetricsRegistry()
