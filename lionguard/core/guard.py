"""
Lionguard — Main Guard Orchestrator
======================================
Ties together Sentinel, Tool Parser, Privilege Engine,
Circuit Breaker, and Audit Logger into a single interface.

Usage:
    guard = Lionguard()
    result = guard.scan_message("user input here")
    if result.verdict == "block":
        # reject the message
"""

from typing import Dict, Optional
from .model_router import ModelRouter, ModelConfig
from .sentinel import Sentinel, ScanResult, Verdict
from .tool_parser import ToolParser
from .privilege import PrivilegeEngine, PrivilegePolicy, PermissionLevel
from .circuit_breaker import CircuitBreaker, BreakerConfig
from .audit_log import AuditLogger


class Lionguard:
    """Main security orchestrator. Cathedral-grade protection for AI agents."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}

        model_cfg = ModelConfig(
            provider=config.get("provider", "local"),
            base_url=config.get("base_url", "http://127.0.0.1:11434"),
            model=config.get("model", "llama3.1:8b"),
            api_key=config.get("api_key", ""),
        )
        self.router = ModelRouter(model_cfg)
        self.sentinel = Sentinel(self.router)
        self.tool_parser = ToolParser(self.sentinel)
        self.privilege = PrivilegeEngine()
        self.breaker = CircuitBreaker(
            on_trip=lambda details: self.audit.log("circuit_breaker", details, verdict="TRIPPED")
        )
        self.audit = AuditLogger(config.get("log_dir", "./lionguard_logs"))

        print(f"[Lionguard] Initialized — {model_cfg.provider}://{model_cfg.model}")
        print(f"[Lionguard] Sentinel active, Tool Parser armed, Privileges enforced")

    def scan_message(self, message: str, agent_id: str = "default") -> ScanResult:
        """Scan an incoming message. The main entry point."""
        if self.breaker.is_tripped:
            return ScanResult(
                verdict=Verdict.BLOCK,
                reason="Circuit breaker is tripped — agent paused for safety",
                threat_type="circuit_breaker",
                confidence=1.0
            )

        result = self.sentinel.scan_input(message)
        self.audit.log("message_scan", {
            "verdict": result.verdict.value,
            "reason": result.reason,
            "threat_type": result.threat_type,
        }, verdict=result.verdict.value, agent_id=agent_id)

        if result.verdict in (Verdict.BLOCK, Verdict.FLAG):
            self.breaker.record_event(result.verdict.value)

        return result

    def scan_tool_call(self, tool_name: str, args: Optional[Dict] = None,
                       agent_id: str = "default") -> PermissionLevel:
        """Check if a tool call is permitted."""
        if self.breaker.is_tripped:
            return PermissionLevel.DENY

        permission = self.privilege.check(tool_name, args)
        self.audit.log("tool_call", {
            "tool": tool_name,
            "permission": permission.value,
            "args_preview": str(args)[:200] if args else "",
        }, verdict=permission.value, tool_name=tool_name, agent_id=agent_id)

        return permission

    def scan_tool_result(self, tool_name: str, result_data: str,
                         agent_id: str = "default") -> tuple:
        """Parse and validate a tool's return data."""
        sanitized, scan = self.tool_parser.parse(tool_name, result_data)
        self.audit.log("tool_result", {
            "tool": tool_name,
            "verdict": scan.verdict.value,
            "reason": scan.reason,
        }, verdict=scan.verdict.value, tool_name=tool_name, agent_id=agent_id)

        if scan.verdict in (Verdict.BLOCK, Verdict.FLAG):
            self.breaker.record_event(scan.verdict.value)

        return sanitized, scan

    def scan_output(self, response: str, agent_id: str = "default") -> ScanResult:
        """Scan agent output for credential leaks."""
        result = self.sentinel.scan_output(response)
        if result.verdict != Verdict.PASS:
            self.audit.log("output_scan", {
                "verdict": result.verdict.value,
                "reason": result.reason,
            }, verdict=result.verdict.value, agent_id=agent_id)
        return result

    def get_status(self) -> Dict:
        """Full system health report."""
        return {
            "version": "0.1.0",
            "circuit_breaker": self.breaker.get_stats(),
            "sentinel": self.sentinel.get_stats(),
            "tool_parser": self.tool_parser.get_stats(),
            "privilege": self.privilege.get_stats(),
            "audit": self.audit.get_stats(),
        }
