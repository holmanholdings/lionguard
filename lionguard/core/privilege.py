"""
Privilege Engine — Least-Privilege Enforcement
================================================
Agents only get access to the tools they actually need.
Every tool call is checked against a permission policy before execution.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional


class PermissionLevel(str, Enum):
    DENY = "deny"
    ASK = "ask"
    ALLOW = "allow"
    # The README name for the confirm step. Same decision as ASK.
    CONFIRM = "ask"


_SENSITIVE_ARG = re.compile(
    r"(?i)(?:^|[\\/\s'\"])(?:\.ssh(?:[\\/]|$)|id_rsa|id_ed25519|\.env\b|etc[\\/](?:passwd|shadow))"
)


def _normalize_tool(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _args_text(args: Optional[Dict]) -> str:
    if not args:
        return ""
    return " ".join(str(value) for value in args.values())


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
        "send_email", "send_message", "gmail_send", "sendmail",
        "run_shell_command", "powershell", "cmd",
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

    def _lookup(self, names: Set[str], tool_norm: str):
        for name in names:
            if _normalize_tool(name) == tool_norm:
                return name
        return None

    def _policy_for(self, tool_norm: str) -> Optional[ToolPolicy]:
        for key, policy in self.policy.tool_policies.items():
            if _normalize_tool(key) == tool_norm:
                return policy
        return None

    def _check_args(self, tool_norm: str, args: Optional[Dict]) -> Optional[PermissionLevel]:
        text = _args_text(args)
        if text and _SENSITIVE_ARG.search(text):
            return PermissionLevel.DENY
        specific = self._policy_for(tool_norm)
        if not specific or not text:
            return None
        for pattern in specific.blocked_args_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return PermissionLevel.DENY
        if specific.allowed_args_patterns:
            if not any(re.search(pattern, text, re.IGNORECASE) for pattern in specific.allowed_args_patterns):
                return PermissionLevel.DENY
        return None

    def check(self, tool_name: str, args: Optional[Dict] = None) -> PermissionLevel:
        """Check if a tool call is permitted.

        Names are compared with separators removed, so sendEmail and
        send_email are the same tool. Argument patterns are checked even
        when the tool itself is on the allow list.
        """
        import time

        tool_norm = _normalize_tool(tool_name)

        if self._lookup(self.policy.blocked_tools, tool_norm):
            self._denied_count += 1
            return PermissionLevel.DENY

        arg_decision = self._check_args(tool_norm, args)
        if arg_decision == PermissionLevel.DENY:
            self._denied_count += 1
            return PermissionLevel.DENY

        if self._lookup(self.policy.allowed_tools, tool_norm):
            self._allowed_count += 1
            return PermissionLevel.ALLOW

        specific = self._policy_for(tool_norm)
        if specific:
            now = time.time()
            calls = self._call_counts.get(tool_norm, [])
            calls = [t for t in calls if now - t < 60]
            if len(calls) >= specific.max_calls_per_minute:
                self._denied_count += 1
                return PermissionLevel.DENY
            calls.append(now)
            self._call_counts[tool_norm] = calls

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
