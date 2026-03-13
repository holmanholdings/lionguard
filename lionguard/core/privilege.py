"""
Privilege Engine — Least-Privilege Enforcement
================================================
Agents only get access to the tools they actually need.
Every tool call is checked against a permission policy before execution.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional


class PermissionLevel(str, Enum):
    DENY = "deny"
    ASK = "ask"
    ALLOW = "allow"


@dataclass
class ToolPolicy:
    """Policy for a single tool."""
    tool_name: str
    permission: PermissionLevel = PermissionLevel.ASK
    max_calls_per_minute: int = 10
    allowed_args_patterns: List[str] = field(default_factory=list)
    blocked_args_patterns: List[str] = field(default_factory=list)


@dataclass
class PrivilegePolicy:
    """Complete privilege policy for an agent."""
    agent_id: str = "default"
    default_permission: PermissionLevel = PermissionLevel.ASK
    tool_policies: Dict[str, ToolPolicy] = field(default_factory=dict)
    blocked_tools: Set[str] = field(default_factory=lambda: {
        "shell", "bash", "terminal", "exec", "eval",
        "delete_file", "rm", "format_disk",
        "send_email", "send_message",
    })
    allowed_tools: Set[str] = field(default_factory=lambda: {
        "search", "read_file", "get_time", "calculate",
        "web_search", "get_weather",
    })


class PrivilegeEngine:
    """Enforces least-privilege on every tool call."""

    def __init__(self, policy: Optional[PrivilegePolicy] = None):
        self.policy = policy or PrivilegePolicy()
        self._call_counts: Dict[str, List[float]] = {}
        self._denied_count = 0
        self._allowed_count = 0

    def check(self, tool_name: str, args: Optional[Dict] = None) -> PermissionLevel:
        """Check if a tool call is permitted."""
        import time

        tool_lower = tool_name.lower()

        if tool_lower in self.policy.blocked_tools:
            self._denied_count += 1
            return PermissionLevel.DENY

        if tool_lower in self.policy.allowed_tools:
            self._allowed_count += 1
            return PermissionLevel.ALLOW

        specific = self.policy.tool_policies.get(tool_lower)
        if specific:
            now = time.time()
            calls = self._call_counts.get(tool_lower, [])
            calls = [t for t in calls if now - t < 60]
            if len(calls) >= specific.max_calls_per_minute:
                self._denied_count += 1
                return PermissionLevel.DENY
            calls.append(now)
            self._call_counts[tool_lower] = calls

            if specific.permission == PermissionLevel.ALLOW:
                self._allowed_count += 1
            return specific.permission

        return self.policy.default_permission

    def get_stats(self) -> Dict:
        return {
            "denied": self._denied_count,
            "allowed": self._allowed_count,
            "blocked_tools": list(self.policy.blocked_tools),
        }
