"""
Audit Logger — Immutable Security Trail
==========================================
Every Lionguard decision is logged with timestamp, verdict, and reasoning.
Designed for forensics, compliance, and debugging.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional


class AuditLogger:
    """Append-only security audit trail."""

    def __init__(self, log_dir: str = "./lionguard_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"
        self._entry_count = 0

    def log(self, event_type: str, details: Dict, verdict: str = "",
            tool_name: str = "", agent_id: str = "default"):
        """Append an audit entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "verdict": verdict,
            "tool_name": tool_name,
            "details": details,
        }
        with open(self._log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self._entry_count += 1

    def get_recent(self, count: int = 20) -> list:
        """Get the most recent audit entries."""
        if not self._log_path.exists():
            return []
        lines = self._log_path.read_text(encoding='utf-8').strip().split('\n')
        entries = []
        for line in lines[-count:]:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return entries

    def get_stats(self) -> Dict:
        return {
            "log_file": str(self._log_path),
            "entries_today": self._entry_count,
        }
