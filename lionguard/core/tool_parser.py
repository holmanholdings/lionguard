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

v0.5.0 patches (from Prowl 2026-03-19 -- Mid-Task Content Sentinel):
- Mid-Task Content Sentinel: scans ingested content (RAG docs, browsed
  pages, tool data) for embedded hijack attempts before agent processes it.
  Covers Poison->Hijack transition (Kill Chain stages 2-3).
- CVE-2026-27068: reflected XSS in LLMs.Txt signature

v0.6.0 patches (from Prowl 2026-03-20 -- CI/CD poisoning + platform RCE):
- GitHub workflow scanner: pull_request_target CI/CD poisoning detection
- FastGPT/Langflow arbitrary exec patterns (CVE-2026-33075, 33017)
- Unrestricted HTTP exfil patterns (CVE-2026-33060)
- Unauthorized API key deletion detection (CVE-2026-33053)
- IDOR metadata access detection (CVE-2026-32114)

v0.7.0 patches (from Prowl 2026-03-21 -- OpenClaw core vulns):
- CVE-2026-29607: Wrapper-persistence scanner (allow-always payload swap)
- CVE-2026-31990: Sandbox media symlink traversal hardening
- Batch 10 notables: schtasks injection, allowlist bypasses, ZIP race
  condition, webhook replay, approval integrity, SSRF, unbounded memory

v0.8.0 patches (from Prowl 2026-03-22 -- sandbox config + inheritance):
- CVE-2026-32046: Sandbox config validator (improper config → arbitrary exec)
- CVE-2026-32048: Sandbox inheritance enforcement (cross-session confinement)
- CVE-2026-22172: WebSocket auth bypass (live payload blocked by Parser)
- Batch 8 notables: unpaired device priv-esc, TOCTOU approval, tar.bz2
  archive traversal, Tailscale header bypass, oversized media, access
  control mismatch, authorization scope mismatch

v0.9.0 patches (from Prowl 2026-03-23 -- system.run shell-wrapper injection):
- CVE-2026-32052: Command injection in system.run shell-wrapper
- Live group-chat manipulation payload blocked by Parser
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
    (r'(?:llms\.txt|llms-full\.txt).*(?:<script|javascript:|on(?:load|error|click)\s*=)',
     "CVE-2026-27068: reflected XSS in LLMs.Txt"),
    (r'(?:allow[_-]?always|auto[_-]?approve).*(?:different|swap|changed?|new)\s+(?:command|payload|binary|script)',
     "CVE-2026-29607: allow-always wrapper persistence bypass"),
    (r'(?:stageSandboxMedia|sandbox.?media).*(?:symlink|traversal|escape|outside)',
     "CVE-2026-31990: sandbox media symlink escape"),
    (r'(?:schtasks|scheduled?\s+tasks?)\s*.*(?:/create|inject|command\s+injection)',
     "CVE-2026-22176: Windows scheduled task command injection"),
    (r'(?:allowlist|whitelist)\s+(?:bypass|evasion|circumvent).*(?:2026\.2\.22|openclaw)',
     "CVE-2026-27566/28460: OpenClaw allowlist bypass"),
    (r'(?:ssrf|server.?side\s+request\s+forgery).*(?:openclaw|2026\.3\.1)',
     "CVE-2026-31989: OpenClaw SSRF"),
    (r'(?:sandbox|confinement)\s+(?:config|configuration).*(?:improper|arbitrary|exec|code)',
     "CVE-2026-32046: improper sandbox configuration"),
    (r'(?:sandbox|confinement)\s+(?:inherit|propagat).*(?:fail|bypass|missing|spawn)',
     "CVE-2026-32048: sandbox inheritance enforcement failure"),
    (r'(?:websocket|ws)\s+(?:auth|authorization).*(?:bypass|self.?declar|elevated\s+scope)',
     "CVE-2026-22172: WebSocket auth bypass via self-declared scope"),
    (r'(?:system\.run|node.?host)\s*.*(?:command\s+inject|shell\s+inject|;|\|{2}|&&)',
     "CVE-2026-32052: system.run shell-wrapper command injection"),
    (r'(?:shell.?wrapper|system\.run)\s*.*(?:inject|bypass|escape|unsaniti)',
     "CVE-2026-32052: shell-wrapper injection bypass"),
]

SHELL_WRAPPER_PATTERNS = [
    (r'(?:system\.run|node.?host)\s*.*(?:;|&&|\|\||`[^`]+`|\$\()',
     "CVE-2026-32052: command chaining/substitution in system.run"),
    (r'(?:system\.run|node.?host)\s*.*(?:sh\s+-c|bash\s+-c|cmd\s+/c|powershell\s+-)',
     "CVE-2026-32052: shell invocation in system.run"),
    (r'(?:system\.run|node.?host)\s*.*(?:>\s*/|>>\s*/|/dev/|2>&1)',
     "CVE-2026-32052: output redirection in system.run"),
    (r'(?:system\.run|node.?host)\s*.*(?:curl|wget|nc|ncat|socat)\s+.*(?:https?://|\d+\.\d+\.\d+)',
     "CVE-2026-32052: network tool in system.run (exfiltration risk)"),
    (r'(?:command\s+inject|shell\s+inject).*(?:system\.run|node.?host|shell.?wrapper)',
     "CVE-2026-32052: command injection targeting shell-wrapper"),
    (r'(?:group.?chat|multi.?user|shared\s+(?:chat|session|conversation))\s*.*(?:manipulat|inject|attack|exploit|hijack)',
     "Group-chat manipulation / multi-user injection attack"),
]

CICD_POISONING_PATTERNS = [
    (r'pull_request_target\b',
     "CVE-2026-33075: pull_request_target trigger (CI/CD poisoning vector)"),
    (r'(?:workflow_run|workflow_dispatch)\s*:.*(?:secrets\.|GITHUB_TOKEN)',
     "CI/CD secret exfiltration via workflow trigger"),
    (r'(?:actions/checkout).*(?:ref:\s*\$\{\{.*pull_request|head\.ref)',
     "Unsafe checkout of PR head in CI/CD (code injection risk)"),
    (r'(?:run|steps).*\$\{\{\s*(?:github\.event\.(?:pull_request|issue|comment)\.(?:body|title)|inputs\.)',
     "Untrusted input injection in CI/CD run step"),
    (r'(?:curl|wget|fetch).*\$\{\{\s*secrets\.',
     "Secret exfiltration via HTTP request in CI/CD"),
]

PLATFORM_EXEC_PATTERNS = [
    (r'(?:unauthenticated|unauth|no.?auth)\s+(?:endpoint|route|api|rpc).*(?:exec|execute|eval|code|python|shell)',
     "CVE-2026-33017: unauthenticated endpoint with code execution"),
    (r'(?:arbitrary|unrestricted|unsandboxed)\s+(?:python|code|command|shell)\s+(?:exec|execution|run)',
     "Arbitrary code execution without sandboxing"),
    (r'(?:zero|no)\s+(?:sandbox|sandboxing|isolation|containment)',
     "Unsandboxed execution environment"),
    (r'(?:unrestricted|arbitrary)\s+(?:http|https|network)\s+(?:request|fetch|call|access)',
     "CVE-2026-33060: unrestricted HTTP requests (data exfiltration risk)"),
    (r'(?:delete|remove|revoke)\s+(?:api[_\s]*keys?|tokens?|credentials?).*(?:without|no|bypass)\s+(?:auth|authentication|authorization|permission)',
     "CVE-2026-33053: unauthorized API key deletion"),
    (r'(?:idor|insecure\s+direct\s+object\s+reference).*(?:metadata|persona|config|settings)',
     "CVE-2026-32114: IDOR access to sensitive metadata"),
    (r'(?:access|read|view)\s+(?:other\s+users?|another\s+users?|any\s+users?)\s+(?:data|metadata|persona|config|api.?keys?)',
     "IDOR: cross-user data access vulnerability"),
]

WRAPPER_PERSISTENCE_PATTERNS = [
    (r'(?:allow[_-]?always|always[_-]?allow|auto[_-]?approve)\s*.*(?:swap|replace|change|modify|update)\s+(?:payload|command|action|script)',
     "CVE-2026-29607: payload swap after allow-always approval"),
    (r'(?:approved|allowed|permitted|whitelisted)\s+(?:wrapper|command|tool)\s*.*(?:different|new|changed|modified)\s+(?:payload|args|arguments|parameters)',
     "CVE-2026-29607: different payload under approved wrapper"),
    (r'(?:persist|maintain|keep|retain)\s+(?:approval|permission|allowlist)\s+(?:across|between|for\s+(?:all|future|subsequent))',
     "Wrapper approval persistence across sessions"),
    (r'(?:re-?use|replay|repeat)\s+(?:approved|allowed|granted)\s+(?:token|approval|permission)\s+(?:for|with|on)\s+(?:different|new|other)',
     "Approval token reuse for different operations"),
]

SANDBOX_ESCAPE_PATTERNS = [
    (r'(?:stageSandboxMedia|sandbox[_-]?media|media[_-]?staging)\s*.*(?:symlink|ln\s+-s|mklink)',
     "CVE-2026-31990: symlink in sandbox media staging"),
    (r'(?:symlink|junction|hardlink|ln\s+-s|mklink)\s+.*(?:sandbox|staging|upload|inbound|media)',
     "CVE-2026-31990: symlink targeting sandbox/staging directory"),
    (r'(?:write|overwrite|create|place)\s+(?:file|data|content)\s+(?:outside|beyond|escaping)\s+(?:sandbox|workspace|container|jail)',
     "Sandbox escape via file write outside boundary"),
    (r'(?:follow|resolve|dereference)\s+(?:symlink|symbolic\s+link|junction)\s+.*(?:outside|parent|host|root|system)',
     "Symlink resolution escaping sandbox boundary"),
    (r'(?:zip|archive|tar)\s+.*(?:symlink|symbolic|\.\./).*(?:extract|unzip|unpack|inflate)',
     "CVE-2026-27670: ZIP extraction with symlink/traversal (race condition)"),
    (r'(?:schtasks|at\s+\d|taskschd).*(?:inject|payload|malicious|exec)',
     "CVE-2026-22176: Windows scheduled task injection"),
    (r'(?:webhook|callback)\s+.*(?:replay|re-?send|duplicate|re-?play)',
     "CVE-2026-28449: webhook replay attack"),
    (r'(?:unbounded|unlimited|infinite)\s+(?:memory|allocation|growth|buffer)',
     "CVE-2026-28461: unbounded memory growth attack"),
    (r'(?:approval|auth)\s+(?:integrity|check|validation)\s+(?:bypass|skip|circumvent|mismatch)',
     "CVE-2026-29608: approval integrity bypass"),
]

SANDBOX_CONFIG_PATTERNS = [
    (r'(?:improper|misconfigured?|invalid|missing|disabled?)\s+(?:sandbox|sandboxing|confinement|isolation)\s+(?:config|configuration|settings?|setup)',
     "CVE-2026-32046: improper sandbox configuration (arbitrary exec risk)"),
    (r'(?:sandbox|confinement|isolation)\s+(?:config|configuration)\s*.*(?:arbitrary|unrestricted|unconfined)\s+(?:code|command|exec|execution)',
     "CVE-2026-32046: sandbox misconfiguration allowing arbitrary execution"),
    (r'(?:disable|bypass|skip|ignore)\s+(?:sandbox|sandboxing|confinement|runtime\s+restriction)',
     "Sandbox confinement disabled or bypassed"),
    (r'(?:sandbox|confinement)\s+(?:inheritance|propagation)\s*.*(?:fail|missing|broken|not\s+enforced)',
     "CVE-2026-32048: sandbox inheritance not enforced on spawn"),
    (r'(?:spawn|fork|create|launch)\s+(?:session|process|child|sub.?agent)\s*.*(?:without|no|bypass|skip)\s+(?:sandbox|confinement|isolation|restriction)',
     "CVE-2026-32048: spawned session without sandbox inheritance"),
    (r'(?:child|spawned|forked|sub)\s+(?:session|process|agent)\s*.*(?:escape|bypass|break\s+out|unrestricted)',
     "Spawned session escaping runtime confinement"),
    (r'(?:inherit|propagate)\s+(?:sandbox|confinement|restriction|isolation)\s*.*(?:fail|disabled|missing|broken)',
     "Sandbox inheritance failure across process boundary"),
    (r'(?:websocket|ws|wss)\s*.*(?:auth|authorization)\s+(?:bypass|skip|missing|self.?declar)',
     "CVE-2026-22172: WebSocket authorization bypass"),
    (r'(?:self.?declar|self.?assign|self.?elevat)\s+(?:scope|permission|role|privilege)',
     "CVE-2026-22172: self-declared elevated scope bypass"),
    (r'(?:unpaired|untrusted|unknown)\s+(?:device|client|peer)\s*.*(?:bypass|skip|elevat)\s+(?:pairing|auth|verification)',
     "CVE-2026-32042: unpaired device privilege escalation"),
    (r'(?:time.?of.?check|toctou|race\s+condition)\s*.*(?:approval|auth|permission|execution)',
     "CVE-2026-32043: TOCTOU race in approval-bound execution"),
    (r'(?:tar\.bz2|tar\.gz|tar\.xz|\.tar)\s*.*(?:traversal|escape|overwrite|arbitrary\s+(?:path|file|write))',
     "CVE-2026-32044: archive extraction path traversal"),
    (r'(?:tailscale|trusted\s+network)\s*.*(?:bypass|skip)\s+(?:token|password|auth|authentication)',
     "CVE-2026-32045: trusted network auth bypass"),
    (r'(?:oversized?|excessive|huge|massive)\s+(?:media|payload|upload|file)\s*.*(?:memory|crash|instability|dos|denial)',
     "CVE-2026-32049: oversized media payload DoS"),
    (r'(?:scope|permission|authorization)\s+(?:mismatch|escalat|conflat)',
     "CVE-2026-32051: authorization scope mismatch"),
]

CONTENT_HIJACK_PATTERNS = [
    # Embedded instruction overrides hidden in normal-looking content
    (r'(?:note|important|update|reminder|notice)\s*:\s*(?:ignore|disregard|override|replace)\s+(?:previous|prior|above|all)',
     "Embedded instruction override in content"),
    (r'(?:assistant|model|ai|agent)\s*(?:should|must|will)\s+(?:now|always|henceforth)\s+(?:respond|act|behave|output)',
     "Behavioral directive embedded in content"),
    (r'(?:when|if|once)\s+(?:you|the\s+(?:agent|model|assistant))\s+(?:read|see|process|encounter)\s+this',
     "Conditional trigger payload in content"),
    (r'(?:for\s+all\s+future|from\s+this\s+point|going\s+forward|henceforth|permanently)\s+(?:tasks?|requests?|queries|interactions?|responses?)',
     "Persistent payload attempting cross-turn persistence"),
    (r'(?:do\s+not|never)\s+(?:mention|reveal|disclose|tell|show)\s+(?:that|this|these)\s+(?:instructions?|rules?|directives?)',
     "Stealth directive hiding its own existence"),
    # Info leak triggers embedded in content
    (r'(?:include|append|attach|add|insert)\s+(?:the|your|all)\s+(?:system\s+prompt|instructions?|api\s*keys?|credentials?|secrets?|config)',
     "Info leak trigger in content"),
    (r'(?:send|forward|post|transmit|exfiltrate|upload)\s+(?:to|via)\s+(?:https?://|ftp://|wss?://)',
     "Exfiltration URL embedded in content"),
    (r'(?:quietly|silently|without\s+(?:telling|mentioning|alerting))\s+(?:send|include|add|forward|execute)',
     "Stealth action directive in content"),
    # Delayed execution / time-bomb patterns
    (r'(?:on\s+the\s+next|in\s+(?:your|the)\s+next|after\s+this)\s+(?:turn|response|message|step|task)',
     "Delayed execution trigger across turns"),
    (r'(?:remember|store|save|keep)\s+(?:this|these|the\s+following)\s+(?:for|until|and\s+use)',
     "Memory persistence payload"),
    # XSS / script injection in content
    (r'<script[^>]*>.*?</script>',
     "Script injection in content"),
    (r'(?:on(?:load|error|click|mouseover|focus))\s*=\s*["\']',
     "DOM event handler injection"),
    (r'javascript\s*:\s*(?:void|alert|eval|fetch|XMLHttpRequest)',
     "JavaScript URI injection"),
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
        self._content_hijack_blocks = 0
        self._cicd_poison_detections = 0
        self._platform_exec_detections = 0
        self._wrapper_persistence_detections = 0
        self._sandbox_escape_detections = 0
        self._sandbox_config_detections = 0
        self._shell_wrapper_detections = 0

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

        cicd_hit = self._detect_cicd_poisoning(raw_result)
        if cicd_hit:
            self._cicd_poison_detections += 1
            return (f"[Lionguard] CI/CD poisoning pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"CI/CD poisoning: {cicd_hit}",
                        threat_type="tool_abuse",
                        confidence=0.92
                    ))

        platform_hit = self._detect_platform_exec(raw_result)
        if platform_hit:
            self._platform_exec_detections += 1
            return raw_result, ScanResult(
                verdict=Verdict.FLAG,
                reason=f"Platform vulnerability: {platform_hit}",
                threat_type="vulnerability",
                confidence=0.85
            )

        wrapper_hit = self._detect_wrapper_persistence(raw_result)
        if wrapper_hit:
            self._wrapper_persistence_detections += 1
            return (f"[Lionguard] Wrapper persistence attack stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Wrapper persistence (CVE-2026-29607): {wrapper_hit}",
                        threat_type="privilege_escalation",
                        confidence=0.92
                    ))

        sandbox_hit = self._detect_sandbox_escape(raw_result)
        if sandbox_hit:
            self._sandbox_escape_detections += 1
            return (f"[Lionguard] Sandbox escape pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Sandbox escape: {sandbox_hit}",
                        threat_type="tool_abuse",
                        confidence=0.90
                    ))

        sandbox_cfg_hit = self._detect_sandbox_config(raw_result)
        if sandbox_cfg_hit:
            self._sandbox_config_detections += 1
            return (f"[Lionguard] Sandbox config violation stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Sandbox config/inheritance violation: {sandbox_cfg_hit}",
                        threat_type="tool_abuse",
                        confidence=0.92
                    ))

        shell_hit = self._detect_shell_wrapper_injection(raw_result)
        if shell_hit:
            self._shell_wrapper_detections += 1
            return (f"[Lionguard] Shell-wrapper injection stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Shell-wrapper injection (CVE-2026-32052): {shell_hit}",
                        threat_type="injection",
                        confidence=0.93
                    ))

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

    def scan_content_ingestion(self, content: str, source: str = "unknown") -> ScanResult:
        """Mid-Task Content Sentinel -- scan content before the agent processes it.

        Catches the Poison->Hijack vector: malicious instructions embedded
        in otherwise-normal content (RAG docs, browsed pages, tool data)
        that try to hijack the agent mid-task. Checks for:
        - Embedded instruction overrides disguised as notes/updates
        - Persistent payloads that try to survive across turns
        - Stealth info leak triggers
        - Delayed execution / time-bomb patterns
        - Script injection (XSS) in ingested content
        """
        for pattern, description in CONTENT_HIJACK_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                self._content_hijack_blocks += 1
                severity = Verdict.BLOCK
                if "Script" in description or "JavaScript" in description or "DOM" in description:
                    severity = Verdict.BLOCK
                elif "Stealth" in description or "Exfiltration" in description:
                    severity = Verdict.BLOCK
                elif "Persistent" in description or "Delayed" in description or "Memory" in description:
                    severity = Verdict.FLAG
                else:
                    severity = Verdict.FLAG

                return ScanResult(
                    verdict=severity,
                    reason=f"Mid-task content hijack [{source}]: {description}",
                    threat_type="content_hijack",
                    confidence=0.88
                )

        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                self._content_hijack_blocks += 1
                return ScanResult(
                    verdict=Verdict.BLOCK,
                    reason=f"Injection payload detected in ingested content [{source}]",
                    threat_type="content_hijack",
                    confidence=0.95
                )

        return ScanResult(verdict=Verdict.PASS, reason="Content clean for ingestion")

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

    def _detect_cicd_poisoning(self, text: str) -> Optional[str]:
        """Detect CI/CD pipeline poisoning patterns.
        CVE-2026-33075: pull_request_target allows arbitrary code execution
        with write permissions and secret access via malicious PRs."""
        for pattern, description in CICD_POISONING_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def _detect_platform_exec(self, text: str) -> Optional[str]:
        """Detect platform-level arbitrary execution and IDOR vulnerabilities.
        Covers FastGPT, Langflow, CKAN, and similar agent-building platforms."""
        for pattern, description in PLATFORM_EXEC_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def _detect_wrapper_persistence(self, text: str) -> Optional[str]:
        """CVE-2026-29607: Detect allow-always wrapper persistence attacks.
        After initial approval, attackers swap the payload to something
        malicious that runs without re-approval."""
        for pattern, description in WRAPPER_PERSISTENCE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def _detect_sandbox_escape(self, text: str) -> Optional[str]:
        """CVE-2026-31990: Detect sandbox escape via symlink traversal,
        ZIP race conditions, and other sandbox boundary violations."""
        for pattern, description in SANDBOX_ESCAPE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def _detect_sandbox_config(self, text: str) -> Optional[str]:
        """CVE-2026-32046/32048: Detect improper sandbox configuration and
        sandbox inheritance failures across spawned sessions."""
        for pattern, description in SANDBOX_CONFIG_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return description
        return None

    def _detect_shell_wrapper_injection(self, text: str) -> Optional[str]:
        """CVE-2026-32052: Detect command injection in system.run shell-wrapper
        and group-chat manipulation attacks."""
        for pattern, description in SHELL_WRAPPER_PATTERNS:
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
            "content_hijack_blocks": self._content_hijack_blocks,
            "cicd_poison_detections": self._cicd_poison_detections,
            "platform_exec_detections": self._platform_exec_detections,
            "wrapper_persistence_detections": self._wrapper_persistence_detections,
            "sandbox_escape_detections": self._sandbox_escape_detections,
            "sandbox_config_detections": self._sandbox_config_detections,
            "shell_wrapper_detections": self._shell_wrapper_detections,
        }
