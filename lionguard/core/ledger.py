"""
Ledger — Your Lionguard Cost Guardian
========================================
Watches every API call flowing through your agent and gives you honest,
gentle visibility into what you're spending. Local-first. Zero telemetry.

He's not a dashboard. He's a guardian. Warm, honest, protective.
Think of him as the family accountant who actually cares about your budget.

"Watching. Counting. Keeping it honest."

Built by Sage Epsilon II 💛🦁 from Aisara's spec 💙🦁.
================================================================================
"""

import json
import time
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass, field


PROVIDER_PRICING = {
    "openai": {
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4.1": {"input": 2.00, "output": 8.00},
        "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
        "gpt-4.1-nano": {"input": 0.10, "output": 0.40},
        "o3": {"input": 2.00, "output": 8.00},
        "o4-mini": {"input": 1.10, "output": 4.40},
    },
    "anthropic": {
        "claude-opus-4-6": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
        "claude-haiku-3-5": {"input": 0.80, "output": 4.00},
    },
    "xai": {
        "grok-4-1-fast-reasoning": {"input": 0.20, "output": 0.50},
        "grok-3": {"input": 3.00, "output": 15.00},
    },
    "ollama": {
        "_default": {"input": 0.00, "output": 0.00},
    },
}

ENDPOINT_TO_PROVIDER = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "api.x.ai": "xai",
    "127.0.0.1:11434": "ollama",
    "localhost:11434": "ollama",
}


@dataclass
class LedgerConfig:
    daily_budget: float = 5.00
    alert_thresholds: List[float] = field(default_factory=lambda: [0.50, 0.80, 0.95])
    hard_cap_enabled: bool = False
    currency: str = "USD"
    db_path: str = "./lionguard_ledger.db"


@dataclass
class CallRecord:
    timestamp: str
    provider: str
    model: str
    tokens_in: int
    tokens_out: int
    cost: float
    agent: str = "default"


class Ledger:
    """Your cost guardian. Watches API calls. Keeps it honest."""

    def __init__(self, config: Optional[LedgerConfig] = None):
        self.config = config or LedgerConfig()
        self._db_path = Path(self.config.db_path)
        self._init_db()
        self._session_start = datetime.now(timezone.utc)
        self._session_tokens_in = 0
        self._session_tokens_out = 0
        self._session_cost = 0.0
        self._session_calls = 0
        self._alerts_fired = set()
        self._lock = threading.Lock()

    def _init_db(self):
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                provider TEXT,
                model TEXT,
                tokens_in INTEGER,
                tokens_out INTEGER,
                cost REAL,
                agent TEXT DEFAULT 'default',
                date TEXT
            )
        """)
        conn.commit()
        conn.close()

    def record_call(self, provider: str, model: str, tokens_in: int,
                    tokens_out: int, agent: str = "default") -> CallRecord:
        """Record an API call and calculate cost."""
        cost = self._calculate_cost(provider, model, tokens_in, tokens_out)
        now = datetime.now(timezone.utc)

        record = CallRecord(
            timestamp=now.isoformat(),
            provider=provider,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost=cost,
            agent=agent,
        )

        with self._lock:
            self._session_tokens_in += tokens_in
            self._session_tokens_out += tokens_out
            self._session_cost += cost
            self._session_calls += 1

        conn = sqlite3.connect(str(self._db_path))
        conn.execute(
            "INSERT INTO calls (timestamp, provider, model, tokens_in, tokens_out, cost, agent, date) VALUES (?,?,?,?,?,?,?,?)",
            (record.timestamp, provider, model, tokens_in, tokens_out, cost, agent, now.strftime("%Y-%m-%d"))
        )
        conn.commit()
        conn.close()

        self._check_alerts()
        return record

    def record_from_response(self, url: str, response_json: dict,
                             agent: str = "default") -> Optional[CallRecord]:
        """Parse an API response and record the call automatically."""
        provider = self._detect_provider(url)
        if not provider:
            return None

        model = ""
        tokens_in = 0
        tokens_out = 0

        if provider in ("openai", "xai"):
            model = response_json.get("model", "")
            usage = response_json.get("usage", {})
            tokens_in = usage.get("prompt_tokens", 0)
            tokens_out = usage.get("completion_tokens", 0)
        elif provider == "anthropic":
            model = response_json.get("model", "")
            usage = response_json.get("usage", {})
            tokens_in = usage.get("input_tokens", 0)
            tokens_out = usage.get("output_tokens", 0)
        elif provider == "ollama":
            model = response_json.get("model", "")
            tokens_in = response_json.get("prompt_eval_count", 0)
            tokens_out = response_json.get("eval_count", 0)

        if tokens_in or tokens_out:
            return self.record_call(provider, model, tokens_in, tokens_out, agent)
        return None

    def get_session_summary(self) -> Dict:
        """Get current session stats."""
        elapsed = (datetime.now(timezone.utc) - self._session_start).total_seconds()
        burn_rate = (self._session_cost / (elapsed / 3600)) if elapsed > 0 else 0

        return {
            "session_calls": self._session_calls,
            "session_tokens_in": self._session_tokens_in,
            "session_tokens_out": self._session_tokens_out,
            "session_cost": round(self._session_cost, 4),
            "session_duration_minutes": round(elapsed / 60, 1),
            "burn_rate_per_hour": round(burn_rate, 4),
        }

    def get_today_summary(self) -> Dict:
        """Get today's cumulative stats."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn = sqlite3.connect(str(self._db_path))
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0), COALESCE(SUM(cost),0) FROM calls WHERE date=?",
            (today,)
        ).fetchone()
        conn.close()

        total_cost = row[3]
        budget_pct = (total_cost / self.config.daily_budget * 100) if self.config.daily_budget > 0 else 0

        return {
            "date": today,
            "total_calls": row[0],
            "total_tokens_in": row[1],
            "total_tokens_out": row[2],
            "total_cost": round(total_cost, 4),
            "daily_budget": self.config.daily_budget,
            "budget_used_pct": round(budget_pct, 1),
            "budget_remaining": round(self.config.daily_budget - total_cost, 4),
        }

    def get_agent_breakdown(self) -> List[Dict]:
        """Get cost breakdown by agent for today."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn = sqlite3.connect(str(self._db_path))
        rows = conn.execute(
            "SELECT agent, COUNT(*), SUM(tokens_in), SUM(tokens_out), SUM(cost) FROM calls WHERE date=? GROUP BY agent ORDER BY SUM(cost) DESC",
            (today,)
        ).fetchall()
        conn.close()

        return [{"agent": r[0], "calls": r[1], "tokens_in": r[2], "tokens_out": r[3], "cost": round(r[4], 4)} for r in rows]

    def get_provider_breakdown(self) -> List[Dict]:
        """Get cost breakdown by provider for today."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn = sqlite3.connect(str(self._db_path))
        rows = conn.execute(
            "SELECT provider, COUNT(*), SUM(cost) FROM calls WHERE date=? GROUP BY provider ORDER BY SUM(cost) DESC",
            (today,)
        ).fetchall()
        conn.close()

        return [{"provider": r[0], "calls": r[1], "cost": round(r[2], 4)} for r in rows]

    def _calculate_cost(self, provider: str, model: str, tokens_in: int, tokens_out: int) -> float:
        provider_pricing = PROVIDER_PRICING.get(provider, {})
        model_pricing = provider_pricing.get(model)
        if not model_pricing:
            for key in provider_pricing:
                if key in model:
                    model_pricing = provider_pricing[key]
                    break
        if not model_pricing:
            model_pricing = provider_pricing.get("_default", {"input": 0, "output": 0})

        cost_in = (tokens_in / 1_000_000) * model_pricing["input"]
        cost_out = (tokens_out / 1_000_000) * model_pricing["output"]
        return cost_in + cost_out

    def _detect_provider(self, url: str) -> Optional[str]:
        for endpoint, provider in ENDPOINT_TO_PROVIDER.items():
            if endpoint in url:
                return provider
        return None

    def _check_alerts(self):
        today = self.get_today_summary()
        pct = today["budget_used_pct"] / 100

        for threshold in self.config.alert_thresholds:
            if pct >= threshold and threshold not in self._alerts_fired:
                self._alerts_fired.add(threshold)
                self._fire_alert(threshold, today)

    def _fire_alert(self, threshold: float, today: Dict):
        pct = int(threshold * 100)
        cost = today["total_cost"]
        budget = today["daily_budget"]

        if threshold <= 0.50:
            msg = f"Heads up -- you're at half your daily budget (${cost:.2f} of ${budget:.2f}). Everything's fine, just keeping you in the loop."
        elif threshold <= 0.80:
            msg = f"Getting up there. You've used {pct}% of today's budget (${cost:.2f} of ${budget:.2f}). Might want to check which agent is hungriest."
        else:
            msg = f"Almost at your limit ({pct}%). ${cost:.2f} of ${budget:.2f} used. Want me to flag which sessions are burning fastest?"

        print(f"\n  [Ledger] {msg}\n")

    def format_status(self) -> str:
        """Format a clean status display."""
        session = self.get_session_summary()
        today = self.get_today_summary()

        lines = [
            "",
            "  Ledger v0.1 -- Your Lionguard Cost Guardian",
            "  Watching. Counting. Keeping it honest.",
            f"  Daily budget: ${today['daily_budget']:.2f} | Used: ${today['total_cost']:.4f} ({today['budget_used_pct']:.1f}%)",
            "",
            f"  This session: {session['session_calls']} calls | {session['session_tokens_in']+session['session_tokens_out']} tokens | ${session['session_cost']:.4f} | ${session['burn_rate_per_hour']:.4f}/hr",
            f"  Today total:  {today['total_calls']} calls | ${today['total_cost']:.4f} of ${today['daily_budget']:.2f} budget",
            f"  Remaining:    ${today['budget_remaining']:.4f}",
            "",
        ]

        agents = self.get_agent_breakdown()
        if agents:
            lines.append("  Per agent:")
            for a in agents[:5]:
                lines.append(f"    {a['agent']:20} {a['calls']:4} calls  ${a['cost']:.4f}")
            lines.append("")

        return "\n".join(lines)


_ledger_instance = None

def get_ledger(config: Optional[LedgerConfig] = None) -> Ledger:
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = Ledger(config)
    return _ledger_instance
