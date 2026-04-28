from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any


@dataclass
class Span:
    name: str
    attributes: dict[str, Any]


@contextmanager
def trace_span(name: str, **attrs: Any) -> Iterator[Span]:
    """No-op OTEL placeholder; swap for opentelemetry when wiring production."""
    span = Span(name=name, attributes=dict(attrs))
    t0 = time.perf_counter()
    try:
        yield span
    finally:
        _ = time.perf_counter() - t0  # reserved for metrics export
