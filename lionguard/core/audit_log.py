"""
Audit Logger — Immutable Security Trail
==========================================
Every Lionguard decision is logged with timestamp, verdict, and reasoning.
Designed for forensics, compliance, and debugging.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional


_SECRET_KEY = re.compile(r"(api[_-]?key|token|secret|password|authorization|credential)", re.I)
_SECRET_VALUE = re.compile(r"(?i)(?:sk-[A-Za-z0-9]|xai-[A-Za-z0-9]|Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----)")


def _redact(obj, key: str = ""):
    """Drop argument text and anything that looks like a key. Reasons stay, so Maxx must treat the log as untrusted."""
    if key in ("args_preview", "args"):
        return "[redacted]"
    if isinstance(obj, dict):
        return {k: _redact(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v, key) for v in obj]
    if _SECRET_KEY.search(key or ""):
        return "[redacted]"
    if isinstance(obj, str) and _SECRET_VALUE.search(obj):
        return _SECRET_VALUE.sub("[redacted]", obj)
    return obj


class AuditLogger:
    """Append-only security audit trail.

    Each line carries the hash of the previous line. Argument values are
    not stored. A reader that feeds these lines to a model should treat
    them as untrusted text, because a reason can still quote the input.
    """

    def __init__(self, log_dir: str = "./lionguard_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"
        self._entry_count = 0
        self._prev_hash = "0" * 64
        if self._log_path.exists():
            lines = [line for line in self._log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                try:
                    self._prev_hash = json.loads(lines[-1]).get("entry_hash", self._prev_hash)
                except json.JSONDecodeError:
                    pass

    def log(self, event_type: str, details: Dict, verdict: str = "",
            tool_name: str = "", agent_id: str = "default"):
        """Append an audit entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "verdict": verdict,
            "tool_name": tool_name,
            "details": _redact(details),
            "prev_hash": self._prev_hash,
        }
        body = json.dumps(entry, default=str, sort_keys=True)
        entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash
        with open(self._log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self._prev_hash = entry_hash
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
