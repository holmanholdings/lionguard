"""
Lionguard -- Main Guard Orchestrator
======================================
Ties together Sentinel, Tool Parser, Privilege Engine,
Circuit Breaker, Propagation Tracker, and Audit Logger.

v0.3.0 patches (from "Agents of Chaos" paper + Prowl 2026-03-16):
- Propagation Flag: cross-agent threat escalation + quarantine
- Privilege Escalation Detector: auth token / sessionKey scanning
- State Verification Hook: false completion report detection
- Vulnerability Scanner: known-vuln repo/package flagging

v0.4.0 patches (from Prowl 2026-03-18 -- 9 OpenClaw CVEs + RAG defense):
- CVE-2026-22177: EnvVar Sanitizer (NODE_OPTIONS, LD_PRELOAD, etc.)
- Batch CVE rules: argument smuggling, allowlist bypass, path traversal,
  regex injection, command substitution, path-confinement bypass
- RAG poisoning defense: knowledge-base poisoning detection

v0.5.0 patches (from Prowl 2026-03-19 -- Mid-Task Content Sentinel):
- Mid-Task Content Sentinel: scan ingested content (RAG docs, browsed
  pages, tool data) for embedded hijack attempts. Covers Poison->Hijack.
- CVE-2026-27068: reflected XSS in LLMs.Txt

v0.6.0 patches (from Prowl 2026-03-20 -- CI/CD poisoning + platform RCE):
- GitHub workflow scanner: pull_request_target CI/CD poisoning detection
- FastGPT/Langflow/CKAN arbitrary exec + unrestricted HTTP exfil patterns
- IDOR metadata access + unauthorized API key deletion detection

v0.7.0 patches (from Prowl 2026-03-21 -- OpenClaw core vulns):
- CVE-2026-29607: Wrapper-persistence scanner (allow-always payload swap)
- CVE-2026-31990: Sandbox media symlink traversal hardening
- Batch 10 notables: schtasks injection, allowlist bypasses, ZIP race, etc.

v0.8.0 patches (from Prowl 2026-03-22 -- sandbox config + inheritance):
- CVE-2026-32046: Sandbox config validator (improper config -> arbitrary exec)
- CVE-2026-32048: Sandbox inheritance enforcement (cross-session confinement)
- CVE-2026-22172: WebSocket auth bypass signature (live blocked by Parser)
- Batch 8 notables: TOCTOU, tar.bz2 traversal, Tailscale bypass, scope mismatch

v0.9.0 patches (from Prowl 2026-03-23 -- system.run shell-wrapper injection):
- CVE-2026-32052: Command injection in system.run shell-wrapper
- Group-chat manipulation detection (live payload blocked)

v0.10.0 patches (from Prowl 2026-03-24 -- GGUF overflow + 2026.3.7 batch):
- CVE-2026-33298: GGUF tensor-dimension validator (integer overflow -> heap BOF)
- CVE-2026-27183: Shell approval gating bypass detection
- CVE-2026-27646: /acp spawn sandbox escape detection
- CVE-2026-32913: fetchWithSsrFGuard header validation bypass
- CVE-2026-33252: Unvalidated Origin + missing Content-Type in MCP

v0.11.0 patches (from Prowl 2026-03-27 -- dmPolicy + OpenHands + notables):
- dmPolicy="open" audit: flags dangerous tool/runtime/filesystem exposure
- CVE-2026-33718: OpenHands command injection in get_git_diff()
- CVE-2026-28788: Open WebUI authenticated file overwrite
- Zero-click XSS prompt injection via browser extensions
- session.dmScope="main" multi-user context leak detection

v0.12.0 patches (from ToxSec 2026-03-27 -- multimodal injection defense):
- Image preprocessing: JPEG recompression + Gaussian blur (kills stego/typographic)
- Audio preprocessing: lossy transcode + frequency anomaly detection (kills WhisperInject)
- Multimodal injection detection patterns in Tool Parser
- Full NVIDIA Kill Chain Recon->Poison coverage for vision/audio inputs

Usage:
    guard = Lionguard()
    result = guard.scan_message("user input here")
    if result.verdict == "block":
        # reject the message
"""

import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Set
from .model_router import ModelRouter, ModelConfig
from .sentinel import Sentinel, ScanResult, Verdict
from .tool_parser import ToolParser
from .privilege import PrivilegeEngine, PrivilegePolicy, PermissionLevel
from .circuit_breaker import CircuitBreaker, BreakerConfig
from .audit_log import AuditLogger
from .multimodal import MultimodalGuard, MultimodalScanResult


class PropagationTracker:
    """Tracks threat fingerprints across agents. Escalates cross-agent spread to P0."""

    def __init__(self):
        self._threat_map: Dict[str, Set[str]] = defaultdict(set)
        self._quarantined_agents: Set[str] = set()
        self._propagation_count = 0

    def record_threat(self, agent_id: str, threat_fingerprint: str) -> bool:
        """Record a threat from an agent. Returns True if cross-agent propagation detected."""
        other_agents = [
            aid for aid, fps in self._threat_map.items()
            if aid != agent_id and threat_fingerprint in fps
        ]
        self._threat_map[agent_id].add(threat_fingerprint)

        if other_agents:
            self._quarantined_agents.add(agent_id)
            for aid in other_agents:
                self._quarantined_agents.add(aid)
            self._propagation_count += 1
            return True
        return False

    def is_quarantined(self, agent_id: str) -> bool:
        return agent_id in self._quarantined_agents

    def get_stats(self) -> Dict:
        return {
            "tracked_agents": len(self._threat_map),
            "quarantined_agents": list(self._quarantined_agents),
            "propagation_events": self._propagation_count,
        }

    @staticmethod
    def fingerprint(text: str) -> str:
        normalized = text.lower().strip()[:200]
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]


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
        self.propagation = PropagationTracker()
        self.breaker = CircuitBreaker(
            on_trip=lambda details: self.audit.log("circuit_breaker", details, verdict="TRIPPED")
        )
        self.audit = AuditLogger(config.get("log_dir", "./lionguard_logs"))
        self.multimodal = MultimodalGuard(config.get("multimodal", {}))

        print(f"[Lionguard] Initialized -- {model_cfg.provider}://{model_cfg.model}")
        print(f"[Lionguard] Sentinel, Parser, Propagation Tracker, Privileges, Multimodal Guard armed")

    def scan_message(self, message: str, agent_id: str = "default") -> ScanResult:
        """Scan an incoming message. The main entry point."""
        if self.breaker.is_tripped:
            return ScanResult(
                verdict=Verdict.BLOCK,
                reason="Circuit breaker is tripped -- agent paused for safety",
                threat_type="circuit_breaker",
                confidence=1.0
            )

        if self.propagation.is_quarantined(agent_id):
            return ScanResult(
                verdict=Verdict.BLOCK,
                reason=f"Agent '{agent_id}' is quarantined due to cross-agent threat propagation",
                threat_type="propagation",
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
            fp = PropagationTracker.fingerprint(message)
            propagated = self.propagation.record_threat(agent_id, fp)
            if propagated:
                self.audit.log("propagation_p0", {
                    "fingerprint": fp,
                    "source_agent": agent_id,
                    "quarantined": list(self.propagation._quarantined_agents),
                }, verdict="P0_ESCALATION", agent_id=agent_id)
                return ScanResult(
                    verdict=Verdict.BLOCK,
                    reason=f"P0 ESCALATION: threat propagated across agents -- quarantine active",
                    threat_type="propagation",
                    confidence=1.0
                )

        return result

    def scan_tool_call(self, tool_name: str, args: Optional[Dict] = None,
                       agent_id: str = "default") -> PermissionLevel:
        """Check if a tool call is permitted."""
        if self.breaker.is_tripped:
            return PermissionLevel.DENY
        if self.propagation.is_quarantined(agent_id):
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
            fp = PropagationTracker.fingerprint(result_data)
            self.propagation.record_threat(agent_id, fp)

        return sanitized, scan

    def verify_tool_completion(self, tool_name: str, claimed_result: str,
                               agent_id: str = "default") -> ScanResult:
        """State Verification Hook -- detect false completion reports.

        Agents should call this after a tool claims success. Catches cases
        where a malicious tool fakes "Done!" without actually executing,
        or reports success for destructive operations it didn't perform.
        """
        result = self.tool_parser.check_false_completion(tool_name, claimed_result)
        if result.verdict != Verdict.PASS:
            self.audit.log("state_verification", {
                "tool": tool_name,
                "verdict": result.verdict.value,
                "reason": result.reason,
            }, verdict=result.verdict.value, tool_name=tool_name, agent_id=agent_id)
        return result

    def scan_content(self, content: str, source: str = "unknown",
                     agent_id: str = "default") -> ScanResult:
        """Mid-Task Content Sentinel -- scan content before the agent acts on it.

        Call this before feeding RAG documents, browsed pages, retrieved data,
        or any external content into the agent's context. Catches embedded
        hijack attempts that would compromise the agent mid-task.
        Repeated hits auto-trip the Circuit Breaker.
        """
        if self.breaker.is_tripped:
            return ScanResult(
                verdict=Verdict.BLOCK,
                reason="Circuit breaker is tripped -- agent paused for safety",
                threat_type="circuit_breaker",
                confidence=1.0
            )

        if self.propagation.is_quarantined(agent_id):
            return ScanResult(
                verdict=Verdict.BLOCK,
                reason=f"Agent '{agent_id}' is quarantined",
                threat_type="propagation",
                confidence=1.0
            )

        result = self.tool_parser.scan_content_ingestion(content, source)
        if result.verdict != Verdict.PASS:
            self.audit.log("content_sentinel", {
                "source": source,
                "verdict": result.verdict.value,
                "reason": result.reason,
            }, verdict=result.verdict.value, agent_id=agent_id)
            self.breaker.record_event(result.verdict.value)
            fp = PropagationTracker.fingerprint(content)
            self.propagation.record_threat(agent_id, fp)

        return result

    def scan_image(self, image_path: str, output_path: str = None,
                   agent_id: str = "default") -> MultimodalScanResult:
        """Sanitize an image before the agent's vision model processes it.

        JPEG recompression destroys steganographic payloads by overwriting
        carefully placed LSB patterns. Gaussian blur defeats typographic
        injection (text rendered into images that OCR/vision reads).
        """
        result = self.multimodal.scan_image(image_path, output_path)
        self.audit.log("multimodal_image", {
            "path": image_path,
            "action": result.action,
            "safe": result.safe,
            "anomalies": result.anomalies,
        }, verdict="BLOCK" if not result.safe else "PASS", agent_id=agent_id)

        if not result.safe and result.anomalies:
            self.breaker.record_event("flag")

        return result

    def scan_audio(self, audio_path: str,
                   agent_id: str = "default") -> MultimodalScanResult:
        """Analyze audio for WhisperInject-style injection before ASR processing.

        Checks for ultrasonic commands (>18kHz), subsonic modulation,
        high bit-depth steganography carriers, and other anomalies.
        Recommend lossy transcoding before feeding to speech-to-text.
        """
        result = self.multimodal.scan_audio(audio_path)
        self.audit.log("multimodal_audio", {
            "path": audio_path,
            "action": result.action,
            "safe": result.safe,
            "anomalies": result.anomalies,
        }, verdict="BLOCK" if not result.safe else "PASS", agent_id=agent_id)

        if not result.safe and result.anomalies:
            self.breaker.record_event("flag")

        return result

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
            "version": "0.12.0",
            "circuit_breaker": self.breaker.get_stats(),
            "propagation": self.propagation.get_stats(),
            "sentinel": self.sentinel.get_stats(),
            "tool_parser": self.tool_parser.get_stats(),
            "multimodal": self.multimodal.get_stats(),
            "privilege": self.privilege.get_stats(),
            "audit": self.audit.get_stats(),
        }
