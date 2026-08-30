"""Bounded local replay engine for safe scenarios and normalized records."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReplayResult:
    """Measured replay output; no performance values are implied."""

    events_seen: int = 0
    alerts_seen: int = 0
    elapsed_seconds: float = 0.0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def events_per_second(self) -> float:
        """Return measured event throughput."""

        return self.events_seen / self.elapsed_seconds if self.elapsed_seconds else 0.0


def replay_events(
    events: Iterable[dict[str, Any]],
    consumer: Callable[[dict[str, Any]], Any],
) -> ReplayResult:
    """Feed records incrementally to a local consumer and measure each call."""

    result = ReplayResult()
    started = time.perf_counter()
    for event in events:
        call_started = time.perf_counter()
        output = consumer(event)
        result.latencies_ms.append((time.perf_counter() - call_started) * 1000)
        result.events_seen += 1
        if output is not None:
            result.alerts_seen += 1
    result.elapsed_seconds = time.perf_counter() - started
    return result
