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
    auto_resume: bool = True


class CircuitBreaker:
    """Automatic shutdown when anomalies exceed threshold.

    Trips are per agent_id. A scanner that is down is not a threat and does
    not count. auto_resume opens the gate again after cooldown_seconds.
    Pass a stable account id as agent_id when one process serves many people.
    """

    def __init__(self, config: Optional[BreakerConfig] = None,
                 on_trip: Optional[Callable] = None):
        self.config = config or BreakerConfig()
        self.on_trip = on_trip
        self._events: Dict[str, List[float]] = {}
        self._tripped: Dict[str, float] = {}
        self._trip_count = 0

    def _maybe_resume(self, agent_id: str) -> None:
        tripped_at = self._tripped.get(agent_id)
        if tripped_at is None or not self.config.auto_resume:
            return
        if (time.time() - tripped_at) > self.config.cooldown_seconds:
            self._tripped.pop(agent_id, None)
            self._events.pop(agent_id, None)

    def is_open(self, agent_id: str = "default") -> bool:
        self._maybe_resume(agent_id)
        return agent_id in self._tripped

    @property
    def is_tripped(self) -> bool:
        return self.is_open("default")

    def record_event(self, severity: str = "flag", agent_id: str = "default"):
        """Record a security event. Trips that agent's breaker if the window fills."""
        if severity == "scanner_unavailable":
            return
        now = time.time()
        events = [t for t in self._events.get(agent_id, []) if now - t < self.config.window_seconds]
        events.append(now)
        self._events[agent_id] = events

        if len(events) >= self.config.max_flags_per_window and agent_id not in self._tripped:
            self._tripped[agent_id] = now
            self._trip_count += 1
            if self.on_trip:
                self.on_trip({
                    "event": "circuit_breaker_tripped",
                    "agent_id": agent_id,
                    "events_in_window": len(events),
                    "window_seconds": self.config.window_seconds,
                    "trip_count": self._trip_count,
                    "timestamp": now,
                })

    def reset(self, agent_id: Optional[str] = None):
        if agent_id is None:
            self._tripped.clear()
            self._events.clear()
            return
        self._tripped.pop(agent_id, None)
        self._events.pop(agent_id, None)

    def get_stats(self) -> Dict:
        return {
            "tripped": self.is_tripped,
            "tripped_agents": list(self._tripped.keys()),
            "events_in_window": len(self._events.get("default", [])),
            "total_trips": self._trip_count,
        }
