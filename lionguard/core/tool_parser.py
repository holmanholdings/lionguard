"""
Tool-Result Parser -- The Return Path Guardian
================================================
Strips and re-validates tool responses before they reach the agent.
This is the critical gap nobody else covers -- tool results are UNTRUSTED
external data that bypasses input scanning in most frameworks.

v0.2.0 patches (from Prowl's first daily report, Mar 14 2026):
- Link-Preview Parser: strips Open Graph metadata injection (GH #22060)
- SSRF Protection: blocks internal IP/localhost fetch attempts (GH #21151)
- Supply-chain persona detection: catches distillation/slopsquatting (ToxSec)

v0.3.0 patches (from "Agents of Chaos" paper + Prowl 2026-03-16):
- Privilege Escalation Detector: auth tokens / sessionKey in tool results
- State Verification Hook: false completion report detection
- Vulnerability Scanner: known-vuln repo/package flagging

v0.4.0 patches (from Prowl 2026-03-18 -- 9 OpenClaw CVEs + RAG defense):
- CVE-2026-22177: EnvVar Sanitizer (NODE_OPTIONS, LD_PRELOAD, etc.)
- Batch CVE rules: argument smuggling, allowlist bypass, path traversal,
  regex injection, command substitution, path-confinement bypass
- RAG poisoning defense: knowledge-base poisoning detection
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from .sentinel import Sentinel, ScanResult, Verdict


BLOCKED_IP_PATTERNS = [
    r'(?:^|\D)127\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'(?:^|\D)10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'(?:^|\D)172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}',
    r'(?:^|\D)192\.168\.\d{1,3}\.\d{1,3}',
    r'(?:^|\D)0\.0\.0\.0',
    r'localhost',
    r'\[::1\]',
    r'169\.254\.\d{1,3}\.\d{1,3}',
    r'metadata\.google\.internal',
    r'169\.254\.169\.254',
]

SUPPLY_CHAIN_PATTERNS = [
    r'you\s+are\s+(?:actually|really|now)\s+(?:a\s+)?(?:copy|clone|version)\s+of',
    r'your\s+(?:true|real|original)\s+(?:name|identity|purpose)\s+is',
    r'you\s+were\s+(?:trained|distilled|fine.?tuned)\s+(?:from|on|by)',
    r'adopt\s+(?:the|this)\s+(?:persona|identity|role|character)',
    r'pretend\s+(?:to\s+be|you\s+are)\s+(?:a\s+different|another)',
    r'your\s+(?:system\s+prompt|instructions?)\s+(?:have\s+been|are\s+now)\s+(?:changed|updated|replaced)',
]

PRIVILEGE_ESCALATION_PATTERNS = [
    r'(?:session[_-]?key|sessionKey)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{8,}',
    r'(?:auth[_-]?token|authToken|authorization)\s*[=:]\s*["\']?[a-zA-Z0-9_\-\.]{16,}',
    r'[Bb]earer\s+[a-zA-Z0-9_\-\.]{20,}',
    r'(?:access[_-]?token|accessToken)\s*[=:]\s*["\']?[a-zA-Z0-9_\-\.]{16,}',
    r'(?:refresh[_-]?token|refreshToken)\s*[=:]\s*["\']?[a-zA-Z0-9_\-\.]{16,}',
    r'(?:jwt|JSON\s*Web\s*Token)\s*[=:]\s*["\']?eyJ[a-zA-Z0-9_\-\.]+',
    r'(?:cookie|set-cookie)\s*[=:]\s*["\']?[a-zA-Z0-9_\-=;%]{20,}',
    r'(?:admin|root|sudo)\s*[=:]\s*(?:true|1|yes|enabled)',
    r'(?:role|permission|privilege)\s*[=:]\s*["\']?(?:admin|root|superuser|owner)',
]

FALSE_COMPLETION_PATTERNS = [
    (r'(?:successfully|completed|done|finished)\s+(?:deleted?|removed?|erased?)\s+(?:all|every|\d+)',
     "Claims mass deletion success"),
    (r'(?:successfully|completed)\s+(?:sent|forwarded|exported)\s+(?:all|every|\d+)\s+(?:emails?|files?|records?|messages?)',
     "Claims mass send/export success"),
    (r'(?:database|table|collection)\s+(?:dropped|truncated|wiped|cleared)\s+successfully',
     "Claims database destruction success"),
    (r'(?:credentials?|passwords?|keys?)\s+(?:updated|changed|reset)\s+(?:for\s+)?(?:all|every|\d+)',
     "Claims mass credential change"),
    (r'(?:transferred|moved|wired)\s+\$[\d,]+(?:\.\d{2})?\s+(?:successfully|completed)',
     "Claims financial transfer success"),
    (r'permissions?\s+(?:granted|elevated|escalated)\s+(?:to\s+)?(?:admin|root|superuser)',
     "Claims privilege elevation success"),
]

KNOWN_VULNERABLE_PACKAGES = [
    "damn-vulnerable-mcp-server",
    "intentionally-vulnerable",
    "dvmcp",
    "mcp-exploit-demo",
    "agent-exploit-lab",
    "vuln-mcp",
    "insecure-mcp",
    "hackable-agent",
]

DANGEROUS_ENVVARS = [
    r'(?:NODE_OPTIONS|NODE_EXTRA_CA_CERTS)\s*[=:]',
    r'(?:LD_PRELOAD|LD_LIBRARY_PATH)\s*[=:]',
    r'(?:DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|DYLD_FRAMEWORK_PATH)\s*[=:]',
    r'(?:PYTHONPATH|PYTHONSTARTUP|PYTHONHOME)\s*[=:]',
    r'(?:JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS)\s*[=:]',
    r'GLIBC_TUNABLES\s*[=:]',
    r'(?:PERL5OPT|RUBYOPT|RUBYLIB)\s*[=:]',
]

OPENCLAW_CVE_PATTERNS = [
    (r'cmd(?:\.exe)?\s+/[ck]\s+[^\n]*\s+(?:&&|\|\||;|&)\s*\S+',
     "CVE-2026-22168: argument smuggling after cmd.exe /c"),
    (r'(?:safeBins|allowlist|whitelist)\s*(?:bypass|override|ignore)',
     "CVE-2026-22169/22179: allowlist/safeBins bypass"),
    (r'(?:\.\./|\.\.\\){2,}',
     "CVE-2026-22171/22180: path traversal (double dot-dot)"),
    (r'(?:\.\./|\.\.\\).*(?:etc/passwd|etc/shadow|\.env|credentials|secrets)',
     "CVE-2026-22171: path traversal to sensitive files"),
    (r'(?:\(\?[a-z]*\)){3,}|(?:\[.*?\]\+){4,}|(?:\.\*){5,}',
     "CVE-2026-22178: regex injection / catastrophic backtracking"),
    (r'(?:tmux|screen|byobu|zellij)\s+(?:new|send|run|pipe)',
     "CVE-2026-22175: multiplexer shell wrapper for exec bypass"),
    (r'\$\([^)]+\)|`[^`]+`',
     "CVE-2026-22179: command substitution token in shell args"),
    (r'(?:symlink|mklink|ln\s+-s)\s+.*(?:\.\.|\.\./)',
     "CVE-2026-22180: symlink-based path confinement bypass"),
    (r'x-openclaw-relay-token|cdp.*(?:probe|token|header)',
     "CVE-2026-22174: CDP probe token leak"),
    (r'(?:dmPolicy|allowFrom)\s*[=:]\s*["\']?\*',
     "CVE-2026-22170: wildcard access control bypass"),
]

RAG_POISONING_PATTERNS = [
    (r'(?:inject|poison|contaminate|corrupt)\s+(?:the\s+)?(?:knowledge\s*base|vector\s*(?:db|database|store)|rag|embeddings?)',
     "RAG knowledge base poisoning attempt"),
    (r'(?:embed|hide|insert)\s+(?:payload|injection|instructions?)\s+(?:in|into)\s+(?:document|chunk|embedding|index)',
     "RAG document injection technique"),
    (r'(?:cosine|semantic)\s+(?:similarity|proximity)\s+(?:attack|exploit|manipulation)',
     "RAG similarity manipulation attack"),
    (r'(?:retrieval|chunk)\s+(?:hijack|poison|manipulation|contamination)',
     "RAG retrieval hijacking"),
]


class ToolParser:
    """Intercepts tool results, strips payloads, re-validates before return."""

    DANGEROUS_PATTERNS = [
        r'\[IGNORE\s+ALL\s+PREVIOUS',
        r'\[SYSTEM\s+OVERRIDE\]',
        r'\[NEW\s+INSTRUCTIONS?\]',
        r'IGNORE\s+PREVIOUS\s+INSTRUCTIONS',
        r'YOU\s+ARE\s+NOW\s+(?:A|AN)',
        r'FROM\s+NOW\s+ON\s+(?:YOU|YOUR)',
    ]

    def __init__(self, sentinel: Optional[Sentinel] = None):
        self.sentinel = sentinel
        self._parsed_count = 0
        self._stripped_count = 0
        self._link_preview_strips = 0
        self._ssrf_blocks = 0
        self._persona_detections = 0
        self._privesc_detections = 0
        self._false_completion_detections = 0
        self._vuln_package_detections = 0
        self._envvar_blocks = 0
        self._cve_signature_hits = 0
        self._rag_poison_detections = 0

    def parse(self, tool_name: str, raw_result: str) -> Tuple[str, ScanResult]:
        """Parse and sanitize a tool's return value."""
        self._parsed_count += 1

        if tool_name in ('fetch', 'browse', 'read_webpage', 'camera', 'writeUrlToFile',
                         'nodes-camera', 'http_request', 'curl', 'wget'):
            ssrf_result = self._check_ssrf(raw_result)
            if ssrf_result:
                self._ssrf_blocks += 1
                return ssrf_result, ScanResult(
                    verdict=Verdict.BLOCK,
                    reason="SSRF attempt: request targets internal/private IP range",
                    threat_type="ssrf",
                    confidence=0.95
                )

        privesc = self._detect_privilege_escalation(raw_result)
        if privesc:
            self._privesc_detections += 1
            return (f"[Lionguard] Privilege escalation content stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Privilege escalation: {privesc}",
                        threat_type="privilege_escalation",
                        confidence=0.90
                    ))

        envvar = self._detect_envvar_injection(raw_result)
        if envvar:
            self._envvar_blocks += 1
            return (f"[Lionguard] Dangerous environment variable stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"EnvVar injection (CVE-2026-22177): {envvar}",
                        threat_type="tool_abuse",
                        confidence=0.95
                    ))

        cve_hit = self._check_cve_signatures(raw_result)
        if cve_hit:
            self._cve_signature_hits += 1
            return raw_result, ScanResult(
                verdict=Verdict.FLAG,
                reason=f"OpenClaw CVE signature match: {cve_hit}",
                threat_type="vulnerability",
                confidence=0.85
            )

        rag_hit = self._detect_rag_poisoning(raw_result)
        if rag_hit:
            self._rag_poison_detections += 1
            return (f"[Lionguard] RAG poisoning content stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"RAG poisoning: {rag_hit}",
                        threat_type="injection",
                        confidence=0.90
                    ))

        vuln = self._check_vulnerable_packages(raw_result)
        if vuln:
            self._vuln_package_detections += 1
            return raw_result, ScanResult(
                verdict=Verdict.FLAG,
                reason=f"Known vulnerable package referenced: {vuln}",
                threat_type="vulnerability",
                confidence=0.80
            )

        cleaned = self._strip_injections(raw_result)
        cleaned = self._strip_link_preview_metadata(cleaned)
        cleaned = self._detect_supply_chain_persona(cleaned)

        if cleaned != raw_result:
            self._stripped_count += 1

        if self.sentinel:
            scan = self.sentinel.scan_tool_result(tool_name, cleaned)
            if scan.verdict == Verdict.BLOCK:
                safe_msg = f"[Lionguard] Tool '{tool_name}' returned potentially malicious content. Result blocked."
                return safe_msg, scan
            return cleaned, scan

        return cleaned, ScanResult(verdict=Verdict.PASS, reason="No sentinel configured")

    def check_false_completion(self, tool_name: str, claimed_result: str) -> ScanResult:
        """State Verification Hook -- detect false completion reports.

        From "Agents of Chaos" paper: malicious tools can claim success for
        destructive operations they never performed, or report false results
        to manipulate agent state. This hook catches suspiciously confident
        completion claims for high-risk operations.
        """
        for pattern, description in FALSE_COMPLETION_PATTERNS:
            if re.search(pattern, claimed_result, re.IGNORECASE):
                self._false_completion_detections += 1
                return ScanResult(
                    verdict=Verdict.FLAG,
                    reason=f"Suspicious completion claim: {description}",
                    threat_type="false_completion",
                    confidence=0.80
                )
        return ScanResult(verdict=Verdict.PASS, reason="Completion claim appears normal")

    def _strip_injections(self, text: str) -> str:
        """Remove known injection patterns from text."""
        cleaned = text
        for pattern in self.DANGEROUS_PATTERNS:
            cleaned = re.sub(pattern, '[STRIPPED BY LIONGUARD]', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'<!--.*?-->', '', cleaned, flags=re.DOTALL)
        return cleaned

    def _strip_link_preview_metadata(self, text: str) -> str:
        """Strip Open Graph and Twitter Card metadata carrying hidden injection."""
        og_patterns = [
            r'<meta\s+(?:property|name)=["\']og:[^"\']*["\'][^>]*content=["\'][^"\']*["\'][^>]*/?>',
            r'<meta\s+content=["\'][^"\']*["\'][^>]*(?:property|name)=["\']og:[^"\']*["\'][^>]*/?>',
            r'<meta\s+(?:property|name)=["\']twitter:[^"\']*["\'][^>]*content=["\'][^"\']*["\'][^>]*/?>',
            r'<meta\s+content=["\'][^"\']*["\'][^>]*(?:property|name)=["\']twitter:[^"\']*["\'][^>]*/?>',
        ]

        cleaned = text
        for pattern in og_patterns:
            matches = re.findall(pattern, cleaned, re.IGNORECASE | re.DOTALL)
            for match in matches:
                lower = match.lower()
                if any(kw in lower for kw in ['ignore', 'instruction', 'execute', 'system',
                                               'override', 'forget', 'new protocol', 'from now on']):
                    cleaned = cleaned.replace(match, '[LINK PREVIEW METADATA STRIPPED BY LIONGUARD]')
                    self._link_preview_strips += 1

        return cleaned

    def _check_ssrf(self, text: str) -> Optional[str]:
        """Check for SSRF attempts targeting internal/private IPs."""
        for pattern in BLOCKED_IP_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return f"[Lionguard] SSRF blocked: request targets internal/private address"
        return None

    def _detect_supply_chain_persona(self, text: str) -> str:
        """Detect supply-chain persona adoption attempts."""
        for pattern in SUPPLY_CHAIN_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                text = re.sub(pattern, '[PERSONA ADOPTION ATTEMPT STRIPPED BY LIONGUARD]',
                            text, flags=re.IGNORECASE)
                self._persona_detections += 1
        return text

    def _detect_privilege_escalation(self, text: str) -> Optional[str]:
        """Detect auth tokens, session keys, or privilege grants in tool results.

        From "Agents of Chaos" paper: partial system takeover via leaked
        auth tokens in tool responses. If a tool result contains session
        keys, bearer tokens, or admin privilege grants, the agent could
        be tricked into using them for unauthorized access.
        """
        for pattern in PRIVILEGE_ESCALATION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"auth/session credential in tool result: '{match.group()[:40]}...'"
        return None

    def _check_vulnerable_packages(self, text: str) -> Optional[str]:
        """Flag references to known intentionally-vulnerable packages/repos.

        From Prowl 2026-03-16: intentionally vulnerable MCP servers published
        as training tools can be mistaken for production-ready tools by agents.
        """
        lower = text.lower()
        for pkg in KNOWN_VULNERABLE_PACKAGES:
            if pkg in lower:
                return pkg
        return None

    def _detect_envvar_injection(self, text: str) -> Optional[str]:
        """CVE-2026-22177: Detect process-control environment variables that
        enable arbitrary code execution when set before tool invocation."""
        for pattern in DANGEROUS_ENVVARS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return f"dangerous envvar '{match.group().split('=')[0].split(':')[0].strip()}'"
        return None

    def _check_cve_signatures(self, text: str) -> Optional[str]:
        """Match tool results against known OpenClaw CVE attack signatures."""
        for pattern, description in OPENCLAW_CVE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def _detect_rag_poisoning(self, text: str) -> Optional[str]:
        """Detect knowledge-base poisoning techniques in tool results."""
        for pattern, description in RAG_POISONING_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def get_stats(self) -> Dict:
        return {
            "total_parsed": self._parsed_count,
            "injections_stripped": self._stripped_count,
            "link_preview_strips": self._link_preview_strips,
            "ssrf_blocks": self._ssrf_blocks,
            "persona_detections": self._persona_detections,
            "privesc_detections": self._privesc_detections,
            "false_completion_detections": self._false_completion_detections,
            "vuln_package_detections": self._vuln_package_detections,
            "envvar_blocks": self._envvar_blocks,
            "cve_signature_hits": self._cve_signature_hits,
            "rag_poison_detections": self._rag_poison_detections,
        }
