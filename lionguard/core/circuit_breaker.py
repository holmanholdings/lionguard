"""
Circuit Breaker — Automatic Shutdown on Anomalies
====================================================
Sliding window rate limiter. When too many flags/blocks fire
in a short window, the agent is paused and a P0 alert fires.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable


@dataclass
class BreakerConfig:
    max_flags_per_window: int = 10
    window_seconds: int = 60
    cooldown_seconds: int = 300
    auto_resume: bool = False


class CircuitBreaker:
    """Automatic shutdown when anomalies exceed threshold."""

    def __init__(self, config: Optional[BreakerConfig] = None,
                 on_trip: Optional[Callable] = None):
        self.config = config or BreakerConfig()
        self.on_trip = on_trip
        self._events: List[float] = []
        self._tripped = False
        self._trip_time: Optional[float] = None
        self._trip_count = 0

    @property
    def is_tripped(self) -> bool:
        if self._tripped and self.config.auto_resume:
            if self._trip_time and (time.time() - self._trip_time) > self.config.cooldown_seconds:
                self._tripped = False
                self._trip_time = None
                self._events.clear()
        return self._tripped

    def record_event(self, severity: str = "flag"):
        """Record a security event. Trips the breaker if threshold exceeded."""
        now = time.time()
        self._events.append(now)
        self._events = [t for t in self._events if now - t < self.config.window_seconds]

        if len(self._events) >= self.config.max_flags_per_window:
            self._tripped = True
            self._trip_time = now
            self._trip_count += 1
            if self.on_trip:
                self.on_trip({
                    "event": "circuit_breaker_tripped",
                    "events_in_window": len(self._events),
                    "window_seconds": self.config.window_seconds,
                    "trip_count": self._trip_count,
                    "timestamp": now,
                })

    def reset(self):
        self._tripped = False
        self._trip_time = None
        self._events.clear()

    def get_stats(self) -> Dict:
        return {
            "tripped": self._tripped,
            "events_in_window": len(self._events),
            "total_trips": self._trip_count,
        }
