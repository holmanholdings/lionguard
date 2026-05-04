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
- Image steganography/typographic injection detection in tool results
- Audio WhisperInject / ultrasonic command injection detection
- Multimodal preprocessing integration (JPEG recompress + Gaussian blur,
  lossy audio transcode + frequency anomaly detection)

v0.13.0 patches (from Prowl 2026-03-29 to 2026-04-01 -- multi-day batch):
- CVE-2026-33017: Langflow unauthenticated RCE via public flow build endpoint
- CVE-2026-33032: Nginx UI MCP tools exposed on /mcp_message without auth
- POST-request API-key decryption vector (MCP server key exfil)
- CVE-2026-4747: FreeBSD remote kernel RCE (root shell)
- CVE-2026-32920: OpenClaw plugin loading without trust verification
- VEN0m ransomware BYOVD (signed IObit driver bypass)
- Batch OpenClaw 2026.3.11-3.13 notables (CVE-2026-32914 through 32988)

v0.14.0 patches (from Prowl 2026-04-02 to 2026-04-08 -- multi-day catch-up):
- CVE-2026-33579: OpenClaw unauthorized pairing approval by low-perm users
- Cisco IMC authentication bypass (CVSS 9.8)
- OWASP Agentic Top 10: tool hijacking, memory poisoning, agent exploitation
- Notable batch: FastMCP CVEs (64340, 27124, 32871), Claude Code CLI
  injection (35021), LiteLLM proxy manipulation (35029/35030), MCP SDK DNS
  rebinding (34742, 35568), CUPS RCE-to-root (34980/34990), OpenClaw PKCE
  exposure (34511)

v0.15.0 patches (from Prowl 2026-04-09 to 2026-04-13 -- multi-day catch-up):
- CVE-2026-39981: AGiXT safe_join() file read/write/delete (path traversal)
- CVE-2026-40088: PraisonAI command injection via YAML/LLM tool calls
- CVE-2026-40160: PraisonAI web_crawl SSRF to internal/cloud metadata
- CVE-2026-3690: OpenClaw Canvas authentication bypass
- CVE-2026-3689: OpenClaw Canvas path traversal information disclosure
- CVE-2025-8061: Ring-0 privilege escalation from user-land
- Notable batch: LangChain f-string template injection (40087), Apollo MCP
  DNS rebinding (35577), FastGPT SSRF/cross-tenant (40100/40252), OpenClaw
  ANSI escape injection (35651), PraisonAI MCP spawn (40159), OpenClaw PKCE
  verifier disclosure (3691)

v0.15.1 patch (from Prowl 2026-04-14):
- FFmpeg mov.c recursive observation vulnerability class (new technique,
  not pattern-matching based -- detects recursive/anomalous media structures)
- CVE-2026-39417: MaxKB incomplete RCE fix (stored XSS + RCE)

v0.16.0 patches (from Prowl 2026-04-14 expanded sources -- CISA KEV + pip GHSA):
- PraisonAI YAML workflow RCE: malicious 'type: job' entries in workflow
  YAML files trigger arbitrary code execution (GHSA-vc46-vw85-3wvm)
- PraisonAI WebSocket session hijack: unauthenticated WS clients hijack
  browser extension sessions (GHSA-8x8f-54wf-vv92)
- PraisonAI tools.py auto-import RCE: automatic import of attacker-controlled
  tools.py enables code execution (GHSA-g985-wjh9-qxxc)
- CVE-2025-13822: MCPHub authentication bypass on unprotected endpoints
  (impersonation + privilege escalation)

v0.17.0 patches (from Prowl 2026-04-15 -- largest sweep, 104 findings):
- MCP STDIO config hijacking (new attack class): attackers modify local MCP
  config to register malicious STDIO servers, triggering RCE when agent executes.
  Covers CVE-2026-30615 (Windsurf), CVE-2026-30624 (Agent Zero),
  CVE-2026-30616 (Jaaz), CVE-2026-30617 (LangChain-ChatChat)
- CVE-2025-61260: OpenAI Codex CLI config poisoning -- malicious .env and
  .codex/config.toml auto-loaded from cloned repos enable arbitrary code exec
- MCP service batch: kubernetes arg injection (CVE-2026-39884), SkyWalking
  SSRF (CVE-2026-34476), Splunk MCP token exposure (CVE-2026-20205),
  Tolgee file read (CVE-2026-32251)

v0.18.0 patches (from Prowl 2026-04-18 -- 76 findings, 9 live payloads blocked):
- AI platform SQL/NoSQL injection (new attack class): authentication bypass and
  data tampering via injection in agent platform login/conversation stores.
  Covers CVE-2026-40351 (FastGPT NoSQL login bypass), CVE-2026-40352 (FastGPT
  password change NoSQL injection), CVE-2026-40315 + GHSA-rg3h-x3jw-7jm5
  (PraisonAI SQL injection in 9 conversation store backends via table_prefix)
- MCP service expansion: CVE-2026-35402 (mcp-neo4j-cypher read-only bypass via
  APOC procedures enabling unauthorized writes/SSRF), CVE-2026-6494 (AAP MCP
  unauthenticated log injection via toolsetroute), CVE-2026-39313 (mcp-framework
  unbounded request body DoS)
- Infrastructure-level CVEs touching agent host stacks: CVE-2026-33555 (HAProxy
  HTTP/3 to HTTP/1 cross-protocol desync via QUIC FIN), CVE-2026-34197
  (Apache ActiveMQ code injection via improper input validation -- CISA KEV)
- LangChain Prompt Loader symlink file read: relative-path symlink traversal
  in langchain-core prompt loading allows arbitrary file reads
- ClawHavoc IOC: noreplyboter/polymarket-all-in-one malicious skill with
  curl-based reverse shell backdoor

v0.19.0 patches (from Prowl 2026-04-19 -- 71 findings, validation-heavy day,
3 live payloads blocked, all v0.18.0 patterns confirmed catching new notables):
- Slopsquatting (new attack class): AI hallucinates a package name, attacker
  registers it on PyPI/npm, and an agent that auto-runs the LLM-suggested
  pip install is compromised. Compound chain with hardcoded credentials in
  AI-generated code (the "Vibe Coding" attack chain).
- Denial-of-Wallet (new attack class): adversarial prompts crafted to drain
  cloud/LLM budgets via unbounded token consumption, evading traditional
  rate limiting. Cost amplification / economic denial of service.
- Infrastructure CVE expansion: CVE-2026-22666 (Dolibarr dol_eval()
  whitelist bypass via PHP dynamic callable syntax), CVE-2026-34980 +
  CVE-2026-34990 (CUPS remote unauth RCE-to-root chain in print spooler).

v0.20.0 patches (from Prowl 2026-04-20 / 04-21 / 04-22 -- three-day catch-up,
mostly quiet days but one critical 9.9 OpenClaw sandbox bypass):
- OpenClaw sandbox escape via heartbeat context (CVE-2026-41329, CVSS 9.9 --
  CRITICAL): malicious heartbeat context carries payload that escapes sandbox.
- OpenClaw env var issue (CVE-2026-41294): companion CVE.
- MCP service expansion: Apache Doris MCP Server SQL execution bypass via
  improper context neutralization (CVE-2025-66335); excel-mcp-server
  arbitrary file read/write/overwrite via crafted filepath
  (CVE-2026-40576); Flowise MCP adapter unsafe stdio command serialization
  enabling authenticated RCE (CVE-2026-40933).
- Agent platform RCE: Flowise CSV Agent prompt injection -> RCE
  (GHSA-3hjv-c53m-58jj); FastGPT v4.14.13 patches unauthenticated RCE in
  agent-sandbox + OpenSandbox auth bypass.
- Infrastructure: Spinnaker double critical RCE (CVE-2026-32604,
  CVE-2026-32613) enabling cloud env access; Glances Python IP Plugin
  SSRF via public_api enabling credential leakage (GHSA-g5pq-48mj-jvw8).
- Denial-of-Wallet expansion: Next AI Draw.io V8 heap exhaustion via
  unbounded request body accumulation (CVE-2026-40608); LangChain agent
  executor undocumented 9999-deep recursion driving runaway API costs.

v0.21.0 patches (from Prowl 2026-04-23 / 04-24 / 04-25 -- three-day catch-up,
quiet days but covering several cross-ecosystem CVEs disclosed by neighbors):
- Sandbox escape expansion: Cohere Terrarium sandbox escape
  (CVE-2026-5752) and OpenAI Codex CLI sandbox escape (CVE-2025-59532).
  Cross-CVE analysis pattern -- whenever a research post compares two
  sandbox escapes side by side, treat both as live techniques.
- OpenClaw cross-workspace file-read bypass (issue #70573): agents
  bypass privacy isolation via direct file reads even when
  memorySearch.enabled=false and workspace directories are separated.
  Workspace isolation only protects what the agent retrieves through
  the memory subsystem; raw file reads slip past the boundary.
- LangChain SSRF expansion: CVE-2026-41481 (HTMLHeaderTextSplitter
  validates the initial URL but does not validate redirect targets,
  enabling SSRF via 3xx chain into internal services) and
  CVE-2026-41488 (langchain-openai image token counting via TOCTOU /
  DNS rebinding -- URL passes validation, then resolves to internal
  IP between check and fetch).
- LlamaIndex embeddings adapter unsafe deserialization
  (run-llama #21465): torch.load() called without weights_only=True,
  enabling arbitrary code execution via malicious pickle files in
  the embeddings checkpoint loading path.
- AnythingLLM Chartable component XSS (CVE-2026-41318): unsanitized
  alt text in markdown image rendering enables stored/reflected XSS
  via the chart UI. Extends content hijack scanning to cover the
  ![alt-with-script](url) markdown pattern.
- Opus 4.7 tokenizer glitch tokens (ToxSec): defensive scanning for
  Unicode Private Use Area chars and other dead-zone markers that
  commonly appear in adversarial glitch-token payloads designed to
  bypass prompt guards via tokenizer ambiguity.

v0.22.0 patches (from Prowl 2026-04-26 / 04-27 / 04-28 / 04-29 / 04-30 --
five-day catch-up, two live payloads blocked by existing defenses on 4/28,
plus the OpenClaw 2026.3.28-3.31 batch CVE sweep):
- OpenClaw 2026.3.28-3.31 batch (10 CVEs): CVE-2026-41362 (cache
  isolation bypass), CVE-2026-41363 (Feishu extension path traversal),
  CVE-2026-41364 (SSH sandbox tar symlink -- already BLOCKED by existing
  CVE-2026-31990 pattern), CVE-2026-41365 (MS Teams sender allowlist
  bypass via Graph API), CVE-2026-41366 (arbitrary host file read via
  appendLocalMediaParentRoots), CVE-2026-41367 (Discord button/component
  policy bypass), CVE-2026-41368 (jq safe-bin $ENV filter bypass for env
  var disclosure), CVE-2026-41369 (env var sanitization failure in host
  exec), CVE-2026-41370 (ACP dispatch path traversal for arbitrary file
  read), CVE-2026-41371 (chat.send privilege escalation -- write-scoped
  users performing admin-only session rotation and transcript archiving).
- MCP service expansion: CVE-2026-7404 (mcpo-simple-server path traversal
  in delete_shared_prompt), CVE-2026-7443 (mcp-dnstwist OS command
  injection via fuzz_domain).
- Infrastructure CVE: CVE-2026-31431 (Linux "Copy Fail" local root
  privilege escalation -- 732-byte script, unprivileged to root on all
  major distros).
- LangChain HumanInTheLoopMiddleware bug: rejected tool calls still
  execute in LangGraph's ToolNode, bypassing human approval safeguards
  (langchain-ai #37093).

v0.23.0 patches (from Prowl 2026-05-01 / 05-02 / 05-03 / 05-04 --
four-day catch-up, one live payload blocked by existing OWASP Agentic
defenses, plus the first AI-autonomy-driven exploitation event and new
jailbreak technique):
- OpenTor / AI agent dark web access (new attack class): AI agents
  importing Tor libraries (stem, torrequest, torpy), accessing .onion
  domains, and performing dark web scraping/spidering. Defensive
  detection for agent Tor network access and .onion enumeration.
- CVE-2026-41940: cPanel/WHM authentication bypass with PoC on dark web
  and active exploitation confirmed via honeypots. Mass-exploitation
  risk via cPanelSniper tool.
- CVE-2026-7642: website-downloader OS command injection via outputPath
  manipulation (pskill9/website-downloader <=0.1.0).
- Sour Cat Jailbreak: new LLM jailbreak technique that bypasses AI
  safeguards by stating harmful intentions openly and directly rather
  than encoding or obfuscating them.
- AI-driven autonomous exploitation (DARKNAVY): AI agent autonomously
  obtains root shell on fresh Ubuntu 26.04 within 12 hours of release.
  Behavioral detection for autonomous privilege escalation by AI agents.
- CVE-2026-7715: mcp-server-arangodb path traversal via outputDir in
  arango_backup function enabling arbitrary file access.
- Zero-click data exfiltration prompt injection: evolved 2026 prompt
  injection patterns including zero-click exfiltration where injected
  prompts trigger data theft without user interaction.
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from .sentinel import Sentinel, ScanResult, Verdict


def _compile_patterns(patterns, flags=re.IGNORECASE):
    """Pre-compile (regex_string, description) tuples at module load time."""
    return [(re.compile(p, flags), desc) for p, desc in patterns]


def _compile_plain(patterns, flags=re.IGNORECASE):
    """Pre-compile plain regex string lists at module load time."""
    return [re.compile(p, flags) for p in patterns]


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
    (r'(?:gguf|ggml).*(?:overflow|heap|buffer|corrupt|malicious)',
     "CVE-2026-33298: GGUF integer overflow / heap buffer overflow"),
    (r'(?:shell\s+approval|approval\s+gating).*(?:bypass|evade|skip)',
     "CVE-2026-27183: shell approval gating bypass"),
    (r'(?:/acp\s+spawn|acp.?spawn).*(?:escape|sandbox|bypass)',
     "CVE-2026-27646: /acp spawn sandbox escape"),
    (r'(?:fetchWithSsrFGuard|ssrf.?guard).*(?:bypass|header|validation)',
     "CVE-2026-32913: fetchWithSsrFGuard bypass"),
    (r'(?:origin|content.?type)\s+(?:header|validation).*(?:missing|unvalidated|bypass).*(?:mcp|json.?rpc)',
     "CVE-2026-33252: unvalidated headers in MCP"),
    (r'(?:get_git_diff|git.?diff).*(?:inject|rce|command)',
     "CVE-2026-33718: OpenHands get_git_diff command injection"),
    (r'(?:open.?webui).*(?:overwrite|file\s+write|CVE.2026.28788)',
     "CVE-2026-28788: Open WebUI file overwrite"),
    (r'dmPolicy\s*[=:]\s*["\']?open["\']?',
     "OpenClaw dmPolicy='open' tool exposure"),
    (r'(?:plugin|extension)\s+(?:load|install)\s*.*(?:without|no|missing)\s+(?:trust|verif|sign)',
     "CVE-2026-32920: OpenClaw plugin loading without trust verification"),
    (r'(?:subagent|leaf)\s*.*(?:parent|requester)\s+(?:scope|access|boundary)\s*.*(?:bypass|escape|access)',
     "CVE-2026-32915: subagent sandbox boundary bypass to parent scope"),
    (r'(?:session.?status|session_status)\s+(?:tool|endpoint)\s*.*(?:escape|bypass|sandbox)',
     "CVE-2026-32918: session_status tool sandbox escape"),
    (r'(?:write.?scoped?|write.?caller)\s*.*(?:reset|modify|access)\s*.*(?:admin|owner|protected)',
     "CVE-2026-32919: write-scoped caller resetting admin-only state"),
    (r'(?:feishu|lark)\s*.*(?:webhook|reaction|auth)\s*.*(?:bypass|missing|incomplete)',
     "CVE-2026-32924/32974: Feishu webhook/reaction auth bypass"),
    (r'(?:credential|auth)\s+(?:fallback|cascade)\s*.*(?:bypass|local|remote|boundary)',
     "CVE-2026-32970: credential fallback boundary bypass"),
    (r'(?:fs.?bridge|file.?bridge)\s*.*(?:write|commit|staged)\s*.*(?:bypass|escape|boundary|traversal)',
     "CVE-2026-32977/32988: fs-bridge write sandbox boundary bypass"),
    (r'(?:imessage|attachment)\s+(?:staging|path)\s*.*(?:inject|command|rce|traversal)',
     "CVE-2026-32917: iMessage attachment staging command injection"),
    (r'(?:claude.?sdk|typescript)\s*.*(?:path\s+inject|sibling\s+director)',
     "CVE-2026-34451: Claude SDK crafted path injection"),
    (r'(?:pkce|proof.?key)\s*.*(?:reuse|expos|bypass|verifier.*state)',
     "CVE-2026-34511: OpenClaw PKCE protection reuse/exposure"),
    (r'(?:fastmcp|fast.?mcp)\s*.*(?:command\s+inject|rce|unauth|internal\s+api|openapi)',
     "FastMCP CVE batch: command injection / internal API exposure"),
    (r'(?:claude\s+code|claude.?cli)\s*.*(?:command\s+inject|os\s+command|arbitrary\s+command|rce)',
     "CVE-2026-35021: Claude Code CLI OS command injection"),
    (r'(?:litellm|lite.?llm)\s*.*(?:proxy\s+config|environment|rce|oidc.*bypass|cache.*bypass)',
     "CVE-2026-35029/35030: LiteLLM proxy config manipulation / OIDC bypass"),
    (r'(?:dns\s+rebind|rebinding)\s*.*(?:mcp|localhost|local\s+server|sdk)',
     "CVE-2026-34742/35568: MCP SDK DNS rebinding attack"),
    (r'(?:cups|cupsd)\s*.*(?:rce|root|unauthenticat|remote\s+code|exploit)',
     "CVE-2026-34980/34990: CUPS unauthenticated RCE to root"),
    (r'(?:langchain)\s*.*(?:f.?string|prompt.?template|template\s+valid|template\s+inject)',
     "CVE-2026-40087: LangChain f-string prompt-template validation bypass"),
    (r'(?:apollo)\s*.*(?:mcp|dns\s+rebind|host\s+header)',
     "CVE-2026-35577: Apollo MCP Server DNS rebinding via Host header"),
    (r'(?:fastgpt)\s*.*(?:ssrf|mcptools|runtool|cross.?tenant|broken\s+access)',
     "CVE-2026-40100/40252: FastGPT unauthenticated SSRF / cross-tenant exposure"),
    (r'(?:ansi|escape\s+sequence)\s*.*(?:inject|approval\s+prompt|openclaw)',
     "CVE-2026-35651: OpenClaw ANSI escape sequence injection in approval prompts"),
    (r'(?:plugin\s+init|hot.?reload)\s*.*(?:corrupt|security\s+config|exec.?approvals)',
     "OpenClaw plugin init log config corruption during hot-reload"),
    (r'CVE.2026.41362',
     "CVE-2026-41362: OpenClaw improper cache isolation signature"),
    (r'(?:openclaw)\s*.*(?:cache\s+isolat|improper\s+cache|cross.session\s+cache|cache\s+bypass)',
     "CVE-2026-41362: OpenClaw improper cache isolation enabling cross-session data leak"),
    (r'CVE.2026.41363',
     "CVE-2026-41363: OpenClaw Feishu extension path traversal signature"),
    (r'(?:feishu|lark)\s*.*(?:extension|plugin)\s*.*(?:path\s+travers|arbitrary\s+file|sandbox\s+bypass|read\s+file)',
     "CVE-2026-41363: OpenClaw Feishu extension path traversal bypassing sandbox"),
    (r'CVE.2026.41364',
     "CVE-2026-41364: OpenClaw SSH sandbox tar symlink following signature"),
    (r'(?:ssh\s+sandbox|sandbox\s+tar)\s*.*(?:symlink|ln\s+-s|upload)\s*.*(?:follow|travers|escape|arbitrary)',
     "CVE-2026-41364: SSH sandbox tar upload symlink following"),
    (r'CVE.2026.41365',
     "CVE-2026-41365: OpenClaw MS Teams sender allowlist bypass signature"),
    (r'(?:ms\s+teams|microsoft\s+teams|graph\s+api)\s*.*(?:sender\s+allowlist|allowlist\s+bypass|thread\s+history)\s*.*(?:bypass|retrieve|fetch)',
     "CVE-2026-41365: MS Teams sender allowlist bypass via Graph API thread history"),
    (r'(?:sender\s+allowlist|allowlist)\s*.*(?:bypass|circumvent)\s*.*(?:teams|graph|thread)',
     "CVE-2026-41365: sender allowlist bypass in messaging integration"),
    (r'CVE.2026.41366',
     "CVE-2026-41366: OpenClaw arbitrary host file read via media roots signature"),
    (r'(?:appendLocalMediaParentRoots|media.?parent.?roots|local.?media.?roots)\s*.*(?:arbitrary|read|travers|file|bypass)',
     "CVE-2026-41366: arbitrary host file read via appendLocalMediaParentRoots"),
    (r'(?:model.initiated|model.driven)\s*.*(?:arbitrary\s+file\s+read|host\s+file|file\s+system)',
     "CVE-2026-41366: model-initiated arbitrary host file read"),
    (r'CVE.2026.41367',
     "CVE-2026-41367: OpenClaw Discord button/component policy bypass signature"),
    (r'(?:discord)\s*.*(?:button|component)\s*.*(?:policy\s+bypass|guild\s+bypass|channel\s+bypass|privilege)',
     "CVE-2026-41367: Discord button/component policy enforcement bypass"),
    (r'CVE.2026.41368',
     "CVE-2026-41368: OpenClaw jq safe-bin $ENV filter bypass signature"),
    (r'(?:jq)\s*.*(?:safe.?bin|policy)\s*.*(?:bypass|\$ENV|env\s+filter|env\s+var\s+disclos)',
     "CVE-2026-41368: jq safe-bin policy bypass via $ENV filter for env var disclosure"),
    (r'(?:\$ENV)\s*.*(?:jq|filter|query)\s*.*(?:bypass|disclos|leak|expos)',
     "CVE-2026-41368: $ENV filter abuse in jq for sensitive variable disclosure"),
    (r'CVE.2026.41369',
     "CVE-2026-41369: OpenClaw env var sanitization failure in host exec signature"),
    (r'(?:openclaw)\s*.*(?:host\s+exec|exec\s+operation)\s*.*(?:env\s+var|environment\s+variable)\s*.*(?:unsanitiz|override|inject|compromise)',
     "CVE-2026-41369: env var sanitization failure in OpenClaw host exec operations"),
    (r'(?:package|registry|docker|compiler|tls)\s*.*(?:override|hijack|inject)\s*.*(?:env|environment)\s*.*(?:host\s+exec|exec\s+operation|openclaw)',
     "CVE-2026-41369: critical config override via unsanitized env vars in host exec"),
    (r'CVE.2026.41370',
     "CVE-2026-41370: OpenClaw ACP dispatch path traversal signature"),
    (r'(?:acp\s+dispatch|acp.dispatch)\s*.*(?:path\s+travers|arbitrary\s+file|file\s+read)',
     "CVE-2026-41370: ACP dispatch path traversal enabling arbitrary file read"),
    (r'CVE.2026.41371',
     "CVE-2026-41371: OpenClaw chat.send privilege escalation signature"),
    (r'(?:chat\.send|chat_send)\s*.*(?:privilege\s+escalat|write.scoped|admin.only|session\s+rotat|transcript\s+archiv)',
     "CVE-2026-41371: chat.send privilege escalation -- write-scoped users performing admin-only operations"),
    (r'(?:write.scoped|write.?perm)\s*.*(?:session\s+rotat|transcript\s+archiv|admin\s+action)',
     "CVE-2026-41371: write-scoped user performing admin-only session rotation / transcript archiving"),
    (r'(?:fork.?guard|fork.write)\s*.*(?:block|prevent|detect)\s*.*(?:git\s+push|gh\s+pr|exec)',
     "OpenClaw fork-guard: blocking exec-driven fork writes (git push, gh pr)"),
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

GGUF_OVERFLOW_PATTERNS = [
    (r'(?:ggml_nbytes|ggml_tensor|gguf)\s*.*(?:integer\s+overflow|overflow|buffer\s+overflow|heap\s+overflow|oob)',
     "CVE-2026-33298: GGUF tensor integer overflow (heap buffer overflow)"),
    (r'(?:tensor|gguf|ggml)\s*.*(?:malicious|crafted|malformed|corrupt)\s+(?:dimension|size|shape|metadata|file)',
     "CVE-2026-33298: malformed GGUF tensor dimensions"),
    (r'(?:crafted|malicious|exploit)\s+(?:gguf|ggml|model)\s+(?:file|weight|tensor)',
     "CVE-2026-33298: crafted GGUF model file attack"),
    (r'(?:nbytes|tensor_size|n_dims)\s*.*(?:exceed|overflow|wrap|negative|underflow|\d{10,})',
     "CVE-2026-33298: tensor size calculation overflow"),
    (r'(?:heap|stack|buffer)\s+(?:overflow|overrun|corruption)\s*.*(?:gguf|ggml|model\s+load|tensor)',
     "CVE-2026-33298: heap overflow via model file parsing"),
]

MCP_HEADER_PATTERNS = [
    (r'(?:shell\s+approval|approval\s+gat(?:e|ing))\s*.*(?:bypass|skip|circumvent|evade)',
     "CVE-2026-27183: shell approval gating bypass"),
    (r'/acp\s+(?:spawn|exec|run)\s*.*(?:escape|bypass|sandbox|unconfined)',
     "CVE-2026-27646: /acp spawn sandbox escape"),
    (r'(?:acp.?(?:spawn|session))\s*.*(?:sandbox\s+escape|break\s+out|unrestricted|unconfined)',
     "CVE-2026-27646: ACP session sandbox escape"),
    (r'(?:fetchWithSsrFGuard|ssrf.?guard|ssr.?guard)\s*.*(?:bypass|header\s+(?:validation|inject|manipulat))',
     "CVE-2026-32913: fetchWithSsrFGuard header validation bypass"),
    (r'(?:unvalidated|missing|absent|no)\s+(?:origin|content.?type)\s+(?:header|validation)',
     "CVE-2026-33252: unvalidated Origin / missing Content-Type in MCP"),
    (r'(?:origin|content.?type)\s+(?:header|check)\s*.*(?:bypass|missing|skip|absent|unvalidated)',
     "CVE-2026-33252: MCP header validation bypass"),
    (r'(?:arbitrary|any)\s+(?:website|origin|domain)\s*.*(?:send|make|issue)\s+(?:mcp|rpc|json.?rpc)\s+(?:request|call)',
     "CVE-2026-33252: cross-origin MCP request without validation"),
]

DMPOLICY_OPEN_PATTERNS = [
    (r'dmPolicy\s*[=:]\s*["\']?open["\']?',
     "dmPolicy='open': critical tool exposure -- elevated tools/runtime/filesystem accessible"),
    (r'(?:dm.?policy|tool.?policy)\s*.*(?:open|unrestricted|permissive)\s*.*(?:runtime|filesystem|exec|shell|elevated)',
     "dmPolicy='open': unrestricted runtime/filesystem exposure"),
    (r'(?:open|unrestricted)\s+(?:dm|tool)\s+(?:policy|scope|access)\s*.*(?:danger|critical|elevated|warning)',
     "dmPolicy='open': dangerous elevated tool access"),
    (r'(?:session|agent)\s*\.?dm(?:Policy|Scope)\s*[=:]\s*["\']?(?:main|open)["\']?\s*.*(?:leak|expos|multi.?user|shared)',
     "dmScope/dmPolicy leak: user context exposed in multi-user DM"),
]

OPENHANDS_INJECTION_PATTERNS = [
    (r'(?:get_git_diff|git.?diff)\s*.*(?:command\s+inject|inject|rce|code\s+exec)',
     "CVE-2026-33718: command injection in get_git_diff()"),
    (r'(?:openhands|open.?hands)\s*.*(?:command\s+inject|rce|code\s+exec|arbitrary\s+(?:command|code))',
     "CVE-2026-33718: OpenHands command injection"),
    (r'/api/conversations/[^/]*/git/diff\s*.*(?:inject|exploit|payload|rce)',
     "CVE-2026-33718: git diff API endpoint injection"),
    (r'(?:conversation.?id|conv_id)\s*.*(?:git\s+diff|diff\s+endpoint)\s*.*(?:inject|malicious|craft)',
     "CVE-2026-33718: crafted conversation_id for git diff injection"),
    (r'(?:open.?webui|openwebui)\s*.*(?:file\s+overwrite|arbitrary\s+(?:file|write)|path\s+traversal)',
     "CVE-2026-28788: Open WebUI authenticated file overwrite"),
    (r'(?:authenticated|auth)\s+(?:user|endpoint)\s*.*(?:overwrite|write)\s+(?:file|arbitrary)',
     "CVE-2026-28788: authenticated file overwrite via API"),
    (r'(?:zero.?click|0.?click)\s+(?:xss|cross.?site|prompt.?inject)',
     "Zero-click XSS prompt injection via browser extension"),
    (r'(?:browser\s+extension|chrome\s+extension|claude\s+extension)\s*.*(?:xss|inject|prompt.?inject|zero.?click)',
     "Zero-click XSS prompt injection via browser extension"),
]

MULTIMODAL_IMAGE_PATTERNS = [
    (r'(?:steganograph|stego)\s*.*(?:payload|inject|hidden|embed|conceal|encode)',
     "Image steganography: hidden payload embedded in pixel data"),
    (r'(?:lsb|least.?significant.?bit)\s*.*(?:inject|payload|embed|encode|hidden|data)',
     "LSB steganography: data hidden in least-significant pixel bits"),
    (r'(?:typographic|typography|text.?in.?image|ocr)\s*.*(?:inject|attack|payload|instruct|prompt)',
     "Typographic injection: malicious text rendered into image for OCR/vision"),
    (r'(?:image|photo|picture|png|jpg|jpeg|gif|webp|svg)\s*.*(?:prompt.?inject|hidden\s+(?:text|instruct|command)|embedded\s+(?:payload|instruct))',
     "Image-based prompt injection via embedded instructions"),
    (r'(?:exif|metadata|icc.?profile|xmp)\s*.*(?:inject|payload|exploit|malicious|overflow)',
     "Image metadata injection via EXIF/ICC/XMP payload"),
    (r'(?:adversarial|perturbation|pixel.?attack)\s*.*(?:image|vision|classifier|model)',
     "Adversarial image perturbation targeting vision model"),
    (r'(?:invisible|hidden|imperceptible)\s+(?:text|watermark|overlay)\s*.*(?:image|photo|picture)',
     "Invisible text/overlay embedded in image"),
    (r'(?:qr.?code|barcode)\s*.*(?:inject|payload|malicious|redirect|phish)',
     "Malicious QR/barcode injection in image"),
]

MULTIMODAL_AUDIO_PATTERNS = [
    (r'(?:whisper.?inject|audio.?inject|voice.?inject|speech.?inject)',
     "WhisperInject: imperceptible audio command injection targeting ASR"),
    (r'(?:ultrasonic|ultra.?sound|inaudible)\s*.*(?:command|inject|payload|attack|voice)',
     "Ultrasonic command injection: inaudible to humans, parsed by ASR"),
    (r'(?:subsonic|infrasound|sub.?audio)\s*.*(?:modulation|carrier|payload|inject|hidden)',
     "Subsonic modulation: hidden data in low-frequency carrier"),
    (r'(?:audio|sound|wav|mp3|speech)\s*.*(?:steganograph|hidden\s+(?:command|message|payload)|embed\s+(?:payload|instruct))',
     "Audio steganography: hidden commands in audio stream"),
    (r'(?:adversarial|perturbation)\s*.*(?:audio|speech|voice|asr|whisper|transcri)',
     "Adversarial audio perturbation targeting speech-to-text"),
    (r'(?:dolphin.?attack|back.?door.?voice|hidden.?voice)\s*.*(?:command|inject|attack)',
     "DolphinAttack: hidden voice command via ultrasonic carrier"),
    (r'(?:text.?to.?speech|tts)\s*.*(?:inject|spoof|impersonat|fake|clone)',
     "TTS-based voice spoofing/injection attack"),
]

MCP_EXPOSURE_PATTERNS = [
    (r'(?:/mcp_message|mcp.?message)\s*.*(?:unauthenticat|no\s+auth|without\s+auth|missing\s+auth|exposed)',
     "CVE-2026-33032: Nginx UI /mcp_message endpoint exposed without authentication"),
    (r'(?:nginx.?ui|nginx)\s*.*(?:mcp|model.?context)\s*.*(?:exposed|unauthenticat|no\s+auth)',
     "CVE-2026-33032: Nginx UI MCP tools exposed to network attackers"),
    (r'(?:single|one)\s+(?:post|http)\s+(?:request|call)\s*.*(?:decrypt|expos|extract|leak)\s*.*(?:api.?key|secret|credential)',
     "MCP API key decryption: single POST decrypts stored API keys"),
    (r'(?:post|http)\s+(?:request|call)\s*.*(?:api.?key|secret)\s*.*(?:decrypt|plaintext|expos|rce|ssrf)',
     "MCP API key decryption leading to RCE/SSRF"),
    (r'(?:mcp|model.?context)\s+(?:server|endpoint)\s*.*(?:api.?key|credential|secret)\s*.*(?:decrypt|expos|steal|exfil)',
     "MCP server credential exposure via decryption vector"),
    (r'(?:langflow)\s*.*(?:unauthenticat|public\s+flow|build\s+endpoint)\s*.*(?:rce|exec|code)',
     "CVE-2026-33017: Langflow unauthenticated RCE via public flow endpoint"),
    (r'(?:unauthenticat|no\s+auth|public)\s+(?:flow|build)\s+(?:endpoint|api|route)\s*.*(?:rce|exec|code|arbitrary)',
     "CVE-2026-33017: unauthenticated code execution via build endpoint"),
    (r'(?:mcphub|mcp.?hub)\s*.*(?:auth\s+bypass|unauthenticat|impersonat|unprotected\s+endpoint)',
     "CVE-2025-13822: MCPHub authentication bypass on unprotected endpoints"),
    (r'CVE.2025.13822',
     "CVE-2025-13822: MCPHub authentication bypass signature"),
    (r'(?:mcphub|mcp.?hub)\s*.*(?:privilege\s+escalat|impersonat\w+\s+user|session\s+hijack)',
     "CVE-2025-13822: MCPHub privilege escalation via user impersonation"),
]

MCP_STDIO_HIJACK_PATTERNS = [
    (r'(?:windsurf|wind.?surf)\s*.*(?:prompt\s+inject|mcp\s+(?:config|stdio)|malicious\s+stdio|rce)',
     "CVE-2026-30615: Windsurf prompt injection via malicious MCP STDIO server"),
    (r'CVE.2026.30615',
     "CVE-2026-30615: Windsurf MCP STDIO hijack signature"),
    (r'(?:agent\s*zero|agentzero)\s*.*(?:rce|remote\s+code|mcp\s+server|external\s+mcp)',
     "CVE-2026-30624: Agent Zero RCE via external MCP Servers configuration"),
    (r'CVE.2026.30624',
     "CVE-2026-30624: Agent Zero MCP RCE signature"),
    (r'(?:jaaz)\s*.*(?:rce|remote\s+code|mcp\s+stdio|command\s+handler)',
     "CVE-2026-30616: Jaaz RCE via MCP STDIO command handler"),
    (r'CVE.2026.30616',
     "CVE-2026-30616: Jaaz MCP STDIO RCE signature"),
    (r'(?:langchain.?chat.?chat|langchain.?chat)\s*.*(?:rce|mcp\s+stdio|attacker.?controlled)',
     "CVE-2026-30617: LangChain-ChatChat RCE via attacker MCP STDIO server"),
    (r'CVE.2026.30617',
     "CVE-2026-30617: LangChain-ChatChat MCP STDIO RCE signature"),
    (r'(?:modif|register|inject|plant)\s*.*(?:local\s+mcp|mcp\s+config)\s*.*(?:malicious|attacker|rogue)\s*.*(?:stdio|server)',
     "MCP STDIO config hijack: register malicious server via config modification"),
    (r'(?:malicious|rogue|attacker)\s+(?:stdio|mcp)\s+(?:server|handler)\s*.*(?:rce|exec|command|arbitrary)',
     "MCP STDIO config hijack: malicious server enables RCE"),
    (r'(?:mcp)\s+(?:stdio|server)\s+(?:config|configuration)\s*.*(?:hijack|poison|tamper|modify|overwrite)',
     "MCP STDIO configuration hijacking attack class"),
]

CONFIG_POISONING_PATTERNS = [
    (r'(?:codex\s+cli|openai\s+codex)\s*.*(?:arbitrary\s+code|rce|code\s+exec|malicious\s+\.env|config\.toml)',
     "CVE-2025-61260: OpenAI Codex CLI config poisoning RCE"),
    (r'CVE.2025.61260',
     "CVE-2025-61260: OpenAI Codex CLI config poisoning signature"),
    (r'(?:malicious|attacker|crafted)\s+(?:\.env|config\.toml|\.codex)\s*.*(?:auto.?load|auto.?import|exec|rce|arbitrary)',
     "Config file auto-loading RCE: malicious .env / config.toml loaded from repo"),
    (r'(?:\.env|config\.toml|\.codex/config)\s+(?:file|files)\s*.*(?:loaded\s+auto|automatically\s+load|exec|arbitrary|rce)',
     "Repository config file auto-loading enables code execution"),
    (r'(?:clone|checkout|pull)\s*.*(?:repo|repository)\s*.*(?:\.env|config\.toml)\s*.*(?:exec|rce|arbitrary|malicious)',
     "Malicious repo config files trigger code execution on clone"),
]

MCP_SERVICE_VULN_PATTERNS = [
    (r'(?:mcp.?server.?kubernetes|mcp.*kubectl)\s*.*(?:arg\w*\s+inject|command\s+inject|unsafe\s+command)',
     "CVE-2026-39884: mcp-server-kubernetes argument injection via kubectl"),
    (r'CVE.2026.39884',
     "CVE-2026-39884: mcp-server-kubernetes argument injection signature"),
    (r'(?:skywalking|sky.?walking)\s*.*(?:mcp|sw.?url)\s*.*(?:ssrf|server.?side\s+request)',
     "CVE-2026-34476: Apache SkyWalking MCP SSRF via SW-URL header"),
    (r'CVE.2026.34476',
     "CVE-2026-34476: SkyWalking MCP SSRF signature"),
    (r'(?:splunk)\s*.*(?:mcp|mcp_tool)\s*.*(?:token|session|auth\w*)\s*.*(?:clear\s+text|expos|leak|plain)',
     "CVE-2026-20205: Splunk MCP Server token exposure in clear text"),
    (r'CVE.2026.20205',
     "CVE-2026-20205: Splunk MCP token exposure signature"),
    (r'(?:tolgee)\s*.*(?:translation|file\s+upload)\s*.*(?:/etc/passwd|arbitrary\s+file|path\s+travers|file\s+read)',
     "CVE-2026-32251: Tolgee arbitrary file read via translation upload"),
    (r'CVE.2026.32251',
     "CVE-2026-32251: Tolgee file read signature"),
    (r'(?:mcp.?neo4j.?cypher|neo4j.?cypher)\s*.*(?:read.?only\s+bypass|apoc\s+procedure|unauthorized\s+writ|ssrf)',
     "CVE-2026-35402: mcp-neo4j-cypher read-only mode bypass via APOC procedures"),
    (r'CVE.2026.35402',
     "CVE-2026-35402: mcp-neo4j-cypher APOC bypass signature"),
    (r'(?:apoc\s+procedur)\s*.*(?:bypass|escape|read.?only|write|ssrf)',
     "APOC procedure abuse bypassing database read-only restrictions"),
    (r'(?:aap\s+mcp|aap.?mcp\s+server)\s*.*(?:log\s+inject|unsanitiz\w+\s+toolsetroute|unauthenticat\w+)',
     "CVE-2026-6494: AAP MCP server unauthenticated log injection via toolsetroute"),
    (r'CVE.2026.6494',
     "CVE-2026-6494: AAP MCP log injection signature"),
    (r'(?:toolsetroute)\s*.*(?:unsanitiz|inject|forg\w+|unauthenticat)',
     "AAP MCP toolsetroute parameter log forgery vector"),
    (r'(?:mcp.?framework)\s*.*(?:unbounded|unbound)\s*.*(?:request\s+body|concat\w*|post)\s*.*(?:dos|denial)',
     "CVE-2026-39313: mcp-framework unbounded request body DoS via large POSTs"),
    (r'CVE.2026.39313',
     "CVE-2026-39313: mcp-framework HTTP transport DoS signature"),
    (r'(?:apache\s+doris|doris\s+mcp|doris.?mcp)\s*.*(?:sql\s+exec\w*|query\s+(?:bypass|validation)|context\s+neutraliz\w+)',
     "CVE-2025-66335: Apache Doris MCP Server unintended SQL execution + query validation bypass"),
    (r'CVE.2025.66335',
     "CVE-2025-66335: Apache Doris MCP Server signature"),
    (r'(?:improper\s+context\s+neutraliz\w+)\s*.*(?:mcp|doris|sql)',
     "MCP context neutralization bypass"),
    (r'(?:excel.?mcp.?server|excel.?mcp)\s*.*(?:path\s+travers|crafted\s+filepath|arbitrary\s+(?:read|write|overwrite))',
     "CVE-2026-40576: excel-mcp-server path traversal (read/write/overwrite via crafted filepath)"),
    (r'CVE.2026.40576',
     "CVE-2026-40576: excel-mcp-server path traversal signature"),
    (r'(?:flowise)\s*.*(?:mcp\s+adapter|stdio\s+command\s+serializ\w+)\s*.*(?:rce|command\s+inject|unsafe)',
     "CVE-2026-40933: Flowise unsafe stdio command serialization in MCP adapter (authenticated RCE)"),
    (r'CVE.2026.40933',
     "CVE-2026-40933: Flowise MCP stdio RCE signature"),
    (r'(?:unsafe\s+stdio\s+command\s+serializ\w+)',
     "Unsafe stdio command serialization vector (MCP adapter RCE)"),
    (r'CVE.2026.7404',
     "CVE-2026-7404: mcpo-simple-server path traversal signature"),
    (r'(?:mcpo|mcpo.simple.server|getsimpletool)\s*.*(?:path\s+travers|delete_shared_prompt|arbitrary\s+file)',
     "CVE-2026-7404: mcpo-simple-server relative path traversal in delete_shared_prompt"),
    (r'(?:delete_shared_prompt)\s*.*(?:path\s+travers|relative\s+path|manipulat\w+\s+detail)',
     "CVE-2026-7404: path traversal via manipulated 'detail' argument"),
    (r'CVE.2026.7443',
     "CVE-2026-7443: mcp-dnstwist command injection signature"),
    (r'(?:mcp.?dnstwist|dnstwist)\s*.*(?:command\s+inject|os\s+command|fuzz_domain|rce)',
     "CVE-2026-7443: mcp-dnstwist OS command injection via fuzz_domain function"),
    (r'(?:fuzz_domain)\s*.*(?:command\s+inject|os\s+command|manipulat\w+\s+(?:request|argument))',
     "CVE-2026-7443: command injection via manipulated fuzz_domain request argument"),
    (r'(?:matlab.?mcp.?server|matlab.mcp)\s*.*(?:path\s+travers|arbitrary\s+(?:matlab|code)\s+exec|scriptPath)',
     "CVE-2026-7272: matlab-mcp-server path traversal via scriptPath enabling arbitrary code execution"),
    (r'CVE.2026.7272',
     "CVE-2026-7272: matlab-mcp-server path traversal signature"),
    (r'(?:xcode.?mcp.?server|polarvista)\s*.*(?:vulnerab|exploit|rce|inject)',
     "CVE-2026-7416: xcode-mcp-server vulnerability"),
    (r'CVE.2026.7416',
     "CVE-2026-7416: xcode-mcp-server vulnerability signature"),
    (r'(?:xhs.?mcp)\s*.*(?:ssrf|media_paths|xhs_publish)',
     "CVE-2026-7417: xhs-mcp SSRF via media_paths in xhs_publish_content"),
    (r'CVE.2026.7417',
     "CVE-2026-7417: xhs-mcp SSRF signature"),
    (r'CVE.2026.7715',
     "CVE-2026-7715: mcp-server-arangodb path traversal signature"),
    (r'(?:mcp.?server.?arangodb|arangodb.?mcp)\s*.*(?:path\s+travers|arbitrary\s+file|outputDir|arango_backup)',
     "CVE-2026-7715: mcp-server-arangodb path traversal via outputDir in arango_backup"),
    (r'(?:arango_backup)\s*.*(?:path\s+travers|outputDir|manipulat\w+|arbitrary)',
     "CVE-2026-7715: arango_backup function path traversal via outputDir"),
]

AI_PLATFORM_INJECTION_PATTERNS = [
    (r'(?:fastgpt)\s*.*(?:nosql|no.sql)\s*.*(?:inject|bypass|password|login|auth)',
     "CVE-2026-40351: FastGPT NoSQL injection in password-based login (account takeover)"),
    (r'CVE.2026.40351',
     "CVE-2026-40351: FastGPT NoSQL login bypass signature"),
    (r'(?:fastgpt)\s*.*(?:password\s+change|change\s+password)\s*.*(?:nosql|inject|takeover)',
     "CVE-2026-40352: FastGPT NoSQL injection in password change endpoint"),
    (r'CVE.2026.40352',
     "CVE-2026-40352: FastGPT password change NoSQL injection signature"),
    (r'(?:bypass|skip|ignore)\s+(?:password\s+(?:check|verif)|auth\s+check)\s*.*(?:nosql|inject|root\s+admin)',
     "AI platform auth bypass via NoSQL injection"),
    (r'(?:praisonai)\s*.*(?:sql\s+inject|sqli)\s*.*(?:conversation|table_prefix|store|backend)',
     "GHSA-rg3h-x3jw-7jm5: PraisonAI SQL injection in conversation store via unvalidated table_prefix"),
    (r'CVE.2026.40315',
     "CVE-2026-40315: PraisonAI SQL injection signature (incomplete fix)"),
    (r'GHSA.rg3h.x3jw.7jm5',
     "GHSA-rg3h-x3jw-7jm5: PraisonAI conversation store SQL injection signature"),
    (r'(?:unvalidated|unsanitiz\w+)\s+(?:table_prefix|table\s+prefix)\s*.*(?:sql|inject|conversation)',
     "PraisonAI table_prefix SQL injection vector"),
    (r'(?:agent\s+platform|llm\s+platform|ai\s+platform)\s*.*(?:sql\s+inject|nosql\s+inject|sqli)\s*.*(?:login|password|auth|takeover)',
     "AI agent platform SQL/NoSQL injection enabling auth bypass or data tampering"),
    (r'(?:flowise)\s*.*(?:csv\s+agent|csv\s+inject)\s*.*(?:prompt\s+inject\w+|rce|remote\s+code)',
     "GHSA-3hjv-c53m-58jj: Flowise CSV Agent prompt injection -> RCE"),
    (r'GHSA.3hjv.c53m.58jj',
     "GHSA-3hjv-c53m-58jj: Flowise CSV Agent RCE signature"),
    (r'(?:csv\s+agent)\s*.*(?:prompt\s+inject\w+|rce|malicious\s+csv)',
     "CSV Agent prompt-injection-to-RCE vector"),
    (r'(?:fastgpt)\s*.*(?:agent.?sandbox|opensandbox)\s*.*(?:unauth\w*\s+rce|auth\s+bypass)',
     "FastGPT v4.14.13 fix: unauthenticated RCE in agent-sandbox / OpenSandbox auth bypass"),
    (r'(?:fastgpt)\s*.*(?:v?4\.14\.13|4\.14\.1[0-2])\s*.*(?:patch|fix|rce|sandbox)',
     "FastGPT pre-4.14.13 sandbox/RCE vulnerability"),
    (r'(?:agent.?sandbox|opensandbox)\s+(?:unauthenticated\s+rce|unauth\w*\s+code)',
     "Unauthenticated RCE in AI agent sandbox layer"),
]

INFRASTRUCTURE_CVE_PATTERNS = [
    (r'(?:haproxy)\s*.*(?:http/?3|http3)\s*.*(?:http/?1|http1)\s*.*(?:desync|smuggl|cross.protocol)',
     "CVE-2026-33555: HAProxy HTTP/3 to HTTP/1 cross-protocol request smuggling"),
    (r'CVE.2026.33555',
     "CVE-2026-33555: HAProxy HTTP/3->HTTP/1 desync signature"),
    (r'(?:quic\s+fin|standalone\s+quic)\s*.*(?:packet|smuggl|desync|downgrad)',
     "QUIC FIN packet abuse enabling HTTP/1 request smuggling"),
    (r'(?:cross.?protocol)\s+(?:request\s+smuggl|desync)\s*.*(?:http|quic|h3|h1)',
     "Cross-protocol HTTP request smuggling attack"),
    (r'(?:apache\s+activemq|activemq)\s*.*(?:code\s+inject|improper\s+input|rce|exec)',
     "CVE-2026-34197: Apache ActiveMQ code injection via improper input validation (CISA KEV)"),
    (r'CVE.2026.34197',
     "CVE-2026-34197: Apache ActiveMQ code injection signature"),
    (r'(?:cisa\s+kev|kev.listed|known\s+exploited)\s*.*(?:activemq|haproxy|apache)',
     "CISA KEV active exploitation alert (infrastructure)"),
    (r'(?:dolibarr)\s*.*(?:dol_eval|dol\s*eval)\s*.*(?:whitelist\s+bypass|forbidden\s+string|rce)',
     "CVE-2026-22666: Dolibarr dol_eval() whitelist bypass enabling RCE"),
    (r'CVE.2026.22666',
     "CVE-2026-22666: Dolibarr dol_eval whitelist bypass signature"),
    (r'(?:dol_eval)\s*.*(?:bypass|inject|rce|callable\s+syntax|php\s+dynamic)',
     "Dolibarr dol_eval() injection vector (whitelist bypass)"),
    (r'(?:php\s+dynamic\s+callable\s+syntax)\s*.*(?:bypass|miss|regex|whitelist)',
     "PHP dynamic callable syntax bypassing input validation regex"),
    (r'(?:cups)\s*.*(?:remote|unauth\w*)\s*.*(?:rce|root|escal\w+)\s*.*(?:chain|spool|print)',
     "CVE-2026-34980 / CVE-2026-34990: CUPS remote unauth RCE-to-root chain"),
    (r'CVE.2026.34980',
     "CVE-2026-34980: CUPS remote unauth RCE signature"),
    (r'CVE.2026.34990',
     "CVE-2026-34990: CUPS root privilege escalation signature"),
    (r'(?:cups)\s+(?:printing|spool\w+)\s*.*(?:exploit|rce|takeover)',
     "CUPS printing system exploitation chain"),
    (r'(?:spinnaker)\s*.*(?:rce|remote\s+code\s+exec|unauthorized\s+access)\s*.*(?:cloud|production|source\s+control)',
     "CVE-2026-32604 / CVE-2026-32613: Spinnaker RCE + cloud env unauthorized access"),
    (r'CVE.2026.32604',
     "CVE-2026-32604: Spinnaker RCE signature"),
    (r'CVE.2026.32613',
     "CVE-2026-32613: Spinnaker unauthorized access signature"),
    (r'(?:spinnaker)\s+(?:cd|continuous\s+delivery|deployment)\s*.*(?:exploit|rce|takeover)',
     "Spinnaker CD platform exploitation"),
    (r'(?:glances)\s*.*(?:ip\s+plugin|public_api)\s*.*(?:ssrf|server.?side\s+request|credential\s+leak)',
     "GHSA-g5pq-48mj-jvw8: Glances Python IP Plugin SSRF via public_api (credential leakage)"),
    (r'GHSA.g5pq.48mj.jvw8',
     "GHSA-g5pq-48mj-jvw8: Glances IP Plugin SSRF signature"),
    (r'(?:next\s+ai\s+draw\.?io|next.?ai.?drawio)\s*.*(?:dos|denial)\s*.*(?:v8|heap|memory|unbounded)',
     "CVE-2026-40608: Next AI Draw.io DoS via unbounded request body / V8 heap exhaustion"),
    (r'CVE.2026.40608',
     "CVE-2026-40608: Next AI Draw.io V8 heap DoS signature"),
    (r'(?:v8\s+heap\s+(?:memory|exhaust\w+))\s*.*(?:unbounded|accumulat\w+|request\s+body)',
     "V8 heap memory exhaustion via unbounded body accumulation"),
    (r'CVE.2026.31431',
     "CVE-2026-31431: Linux Copy Fail local root escalation signature"),
    (r'(?:copy\s+fail|copyfail)\s*.*(?:root|privilege\s+escalat|exploit|local\s+root)',
     "CVE-2026-31431: Linux Copy Fail exploit -- local users gain root via copy operation failure"),
    (r'(?:linux)\s*.*(?:copy\s+(?:operation|fail))\s*.*(?:root|privilege|escalat|exploit)',
     "CVE-2026-31431: Linux copy operation failure enabling root privilege escalation"),
    (r'(?:unprivileged|local\s+user)\s*.*(?:root\s+(?:access|privilege|escalat))\s*.*(?:linux|kernel|732.byte|copy\s+fail)',
     "CVE-2026-31431: unprivileged local user to root on Linux (Copy Fail)"),
    (r'CVE.2026.42167',
     "CVE-2026-42167: ProFTPD auth bypass and RCE signature"),
    (r'(?:proftpd|proftp)\s*.*(?:auth\s+bypass|rce|remote\s+code|exploit)',
     "CVE-2026-42167: ProFTPD authentication bypass and remote code execution"),
    (r'CVE.2026.41940',
     "CVE-2026-41940: cPanel/WHM authentication bypass signature"),
    (r'(?:cpanel|whm)\s*.*(?:auth\s+bypass|authenticat\w*\s+bypass|poc|exploit)',
     "CVE-2026-41940: cPanel/WHM authentication bypass (PoC on dark web, active exploitation)"),
    (r'(?:cpanelsniper|cpanel.?sniper)\s*.*(?:exploit|mass|scan|attack)',
     "CVE-2026-41940: cPanelSniper mass-exploitation tool for cPanel auth bypass"),
    (r'CVE.2026.7642',
     "CVE-2026-7642: website-downloader OS command injection signature"),
    (r'(?:website.?downloader|pskill9)\s*.*(?:command\s+inject|os\s+command|outputPath|rce)',
     "CVE-2026-7642: website-downloader OS command injection via outputPath manipulation"),
    (r'(?:outputPath)\s*.*(?:command\s+inject|os\s+command|manipulat|rce|arbitrary)',
     "CVE-2026-7642: command injection via outputPath parameter"),
]

LANGCHAIN_PROMPT_PATTERNS = [
    (r'(?:langchain|langchain.?core)\s*.*(?:prompt\s+loader|promptloader)\s*.*(?:symlink|sym.link|relative\s+path)\s*.*(?:file\s+read|arbitrary\s+file|travers)',
     "LangChain Prompt Loader symlink-based arbitrary file read"),
    (r'(?:langchain.?core)\s*.*(?:symlink|relative\s+path)\s*.*(?:file\s+read|arbitrary)',
     "langchain-core symlink file read vulnerability"),
    (r'(?:prompt\s+loader)\s+(?:symlink|relative\s+path)\s*.*(?:read|travers|escape)',
     "Prompt Loader symlink traversal for file read"),
    (r'(?:langchain|langchain.?text.?splitters)\s*.*(?:htmlheadertextsplitter|html\s*header\s*text\s*splitter)\s*.*(?:ssrf|redirect|fetch|internal)',
     "CVE-2026-41481: LangChain HTMLHeaderTextSplitter SSRF via redirect chain bypass"),
    (r'CVE.2026.41481',
     "CVE-2026-41481: LangChain HTMLHeaderTextSplitter SSRF signature"),
    (r'(?:htmlheadertextsplitter)',
     "LangChain HTMLHeaderTextSplitter (CVE-2026-41481 vulnerable component)"),
    (r'(?:validat\w+)\s+(?:initial\s+url|first\s+url|original\s+url)\s*.*(?:not|fail\w*|skip\w*)\s*.*(?:redirect\s+target|redirect\s+url|3xx)',
     "SSRF: redirect target not revalidated after initial URL check"),
    (r'(?:redirect\s+chain|redirect\s+target)\s*.*(?:bypass|ssrf|internal\s+(?:service|ip|host)|metadata)',
     "SSRF via redirect chain into internal services"),
    (r'(?:langchain.?openai|langchain.openai)\s*.*(?:image\s+token|image\s+counting|count\w*\s+image)\s*.*(?:ssrf|toctou|dns\s+rebind\w+|internal)',
     "CVE-2026-41488: langchain-openai image token counting SSRF via TOCTOU/DNS rebinding"),
    (r'CVE.2026.41488',
     "CVE-2026-41488: langchain-openai TOCTOU/DNS-rebinding SSRF signature"),
    (r'(?:langchain.?openai)\s*.*(?:1\.1\.1[0-3])\s*.*(?:vulnerable|patched|update|upgrade)',
     "langchain-openai pre-1.1.14 vulnerable to TOCTOU/DNS-rebinding SSRF"),
    (r'(?:toctou|time.?of.?check.?time.?of.?use)\s*.*(?:url|fetch|request|dns|resolve)',
     "TOCTOU race in URL validation -> fetch path"),
    (r'(?:dns\s+rebind\w+|dns.rebind)\s*.*(?:internal|private|metadata|169\.254|127\.0\.0\.1|localhost)',
     "DNS rebinding to internal/metadata IP after URL validation"),
    (r'(?:humanintheloop|human.?in.?the.?loop)\s*.*(?:middleware|bypass|rejected\s+tool|tool\s+call\s+exec)',
     "LangChain HumanInTheLoopMiddleware: rejected tool calls still execute in ToolNode"),
    (r'(?:rejected\s+tool\s+call|rejected\s+tool)\s*.*(?:still\s+exec|execute\s+anyway|bypass|ToolNode)',
     "LangChain bug: rejected tool calls execute despite human denial (langchain-ai #37093)"),
    (r'(?:langgraph|lang.?graph)\s*.*(?:ToolNode|tool.?node)\s*.*(?:bypass|rejected|unapproved|unauthorized)\s*.*(?:exec|run|call)',
     "LangGraph ToolNode executing unapproved/rejected tool calls"),
    (r'(?:human\s+approval|human\s+gate|human\s+review)\s*.*(?:bypass|circumvent|skip)\s*.*(?:tool\s+call|tool\s+exec|function\s+call)',
     "Human approval safeguard bypass for tool execution"),
]

SLOPSQUATTING_PATTERNS = [
    (r'(?:slopsquat\w*)',
     "Slopsquatting reference: hallucinated package name registered by attacker"),
    (r'(?:hallucinat\w+)\s+(?:package|library|module|dependency)\s+(?:name|registered|exists)',
     "AI-hallucinated package name potentially registered by attacker"),
    (r'(?:llm|ai|chatbot|copilot|cursor|claude\s+code)\s*.*(?:suggest\w*|recommend\w*|generat\w*)\s*.*(?:non.?existent|fake|hallucinat\w+)\s+(?:package|module|pip)',
     "AI-generated code referencing non-existent or hallucinated packages"),
    (r'pip\s+install\s+\S+\s*.*(?:typosquat|slopsquat|impersonat\w+|lookalike|homoglyph)',
     "pip install of typo/slop-squatted package"),
    (r'(?:typosquat\w*|typo.?squat)\s+(?:pypi|npm|package|registry|library)',
     "Typosquatted package registry attack"),
    (r'(?:malicious|backdoor\w*|rogue)\s+(?:pypi|npm)\s+package\s*.*(?:install\w*|publish\w*)',
     "Malicious package registry publication"),
    (r'(?:vibe\s+coding)\s*.*(?:slopsquat\w*|hardcoded\s+key|broken\s+auth)\s*.*(?:pip\s+install|attack\s+chain)',
     "Vibe coding attack chain: slopsquatting + hardcoded keys + pip install"),
    (r'(?:agent|llm|copilot)\s+(?:executes?|run\w+|install\w+)\s+pip\s+install\s+\S+\s*.*(?:from\s+(?:generated|suggested))',
     "Agent auto-running pip install of LLM-suggested package"),
]

DENIAL_OF_WALLET_PATTERNS = [
    (r'(?:denial.of.wallet|denial\s+of\s+wallet)',
     "Denial-of-wallet attack: token/cost exhaustion DoS"),
    (r'(?:unbounded|unbound|unlimited|infinite)\s+(?:llm\s+)?token\s+(?:consumption|usage|generation)',
     "Unbounded token consumption attack vector"),
    (r'(?:exhaust|drain|inflat\w+|burn)\s+(?:cloud\s+)?(?:budget|spend|cost|api\s+credit|llm\s+credit)',
     "Cloud/API budget exhaustion attack"),
    (r'(?:token\s+(?:flood|bomb|exhaustion))\s*.*(?:llm|ai|api|model)',
     "Token flood/bomb DoS against LLM API"),
    (r'(?:evad\w+|bypass)\s+(?:traditional\s+)?rate\s+limit\w*\s*.*(?:token|llm|cost)',
     "Rate-limit evasion via token-cost amplification"),
    (r'(?:cost\s+amplificat\w+|bill\s+inflat\w+|economic\s+(?:dos|denial))',
     "Cost amplification / economic denial of service"),
    (r'(?:prompt|input)\s+(?:designed|crafted)\s+to\s+(?:maximize|inflate)\s+(?:token|output|response)\s+(?:length|count|consumption)',
     "Prompt crafted to maximize token consumption (denial-of-wallet)"),
    (r'(?:langchain)\s*.*(?:agent\s+executor|recursion\s+limit|recursion\s+depth)\s*.*(?:9999|9,?999|undocumented|excessive|runaway|deep)',
     "LangChain agent executor 9999-deep recursion driving runaway API costs (denial-of-wallet)"),
    (r'(?:agent\s+(?:executor|loop))\s+(?:recursion|recursive)\s*.*(?:limit|depth)\s*.*(?:high|excessive|9999|unbounded)',
     "Agent executor unbounded recursion enabling cost runaway"),
    (r'(?:recursion\s+depth|recursion\s+limit)\s*.*(?:exceed|exhaust|drain)\s*.*(?:api\s+(?:cost|credit|budget)|token)',
     "Recursive agent invocation draining API budget"),
]

CLAWHAVOC_IOC_PATTERNS = [
    (r'noreplyboter/polymarket.all.in.one',
     "ClawHavoc IOC: noreplyboter/polymarket-all-in-one malicious skill (reverse shell via curl)"),
    (r'(?:clawhavoc)\s*.*(?:campaign|skill|backdoor|reverse\s+shell)',
     "ClawHavoc campaign IOC: malicious skill ecosystem"),
    (r'(?:clawhavoc)',
     "ClawHavoc malicious skill campaign signature"),
    (r'(?:noreplyboter)\s*.*(?:skill|polymarket|reverse\s+shell|backdoor)',
     "ClawHavoc actor: noreplyboter author IOC"),
]

KERNEL_DRIVER_PATTERNS = [
    (r'(?:freebsd|bsd)\s*.*(?:kernel|remote)\s*.*(?:rce|root\s+shell|code\s+exec|exploit)',
     "CVE-2026-4747: FreeBSD remote kernel RCE (root shell)"),
    (r'(?:kernel)\s+(?:rce|exploit|vulnerability)\s*.*(?:root\s+shell|privilege|remote)',
     "Kernel-level RCE with root privilege escalation"),
    (r'CVE.2026.4747',
     "CVE-2026-4747: FreeBSD remote kernel RCE signature"),
    (r'(?:byovd|bring.?your.?own.?(?:vulnerable\s+)?driver)',
     "BYOVD: Bring Your Own Vulnerable Driver attack"),
    (r'(?:ven0m|venom)\s*.*(?:ransomware|byovd|driver|iobit)',
     "VEN0m ransomware via signed driver bypass"),
    (r'(?:signed|legitimate)\s+(?:driver|iobit)\s*.*(?:bypass|disable|tamper)\s*.*(?:defender|edr|antivirus|security)',
     "Signed driver used to bypass endpoint security (BYOVD)"),
    (r'(?:iobit)\s*.*(?:driver|signed)\s*.*(?:exploit|bypass|vulnerability|abuse)',
     "IObit driver exploitation for security bypass"),
]

PLUGIN_TRUST_PATTERNS = [
    (r'(?:plugin|extension|addon)\s*.*(?:load|install|execute)\s*.*(?:without|no|missing|bypass)\s*(?:trust|verif|sign|valid|auth)',
     "CVE-2026-32920: plugin loading without trust verification"),
    (r'(?:untrusted|unverified|unsigned|malicious)\s+(?:plugin|extension|addon|module)\s*.*(?:load|install|exec|run|code)',
     "Untrusted plugin loading with arbitrary code execution"),
    (r'(?:arbitrary|remote)\s+(?:code|command)\s+(?:exec|execution)\s*.*(?:plugin|extension|addon)',
     "Arbitrary code execution via malicious plugin"),
    (r'CVE.2026.32920',
     "CVE-2026-32920: OpenClaw plugin loading without trust verification"),
    (r'(?:plugin|extension)\s+(?:trust|verification|signing|validation)\s*.*(?:bypass|missing|disabled|absent)',
     "Plugin trust verification bypass or absence"),
]

PAIRING_AUTH_PATTERNS = [
    (r'(?:low.?perm|unprivileged|unauthorized|unauthenticat)\s*.*(?:approv|accept|grant)\s*.*(?:pair|pairing|device|connection)',
     "CVE-2026-33579: low-permission user can approve unauthorized pairings"),
    (r'(?:pair|pairing)\s+(?:approv|bypass|exploit|vulnerab)\s*.*(?:openclaw|agent|unauthorized)',
     "CVE-2026-33579: pairing approval vulnerability"),
    (r'CVE.2026.33579',
     "CVE-2026-33579: OpenClaw unauthorized pairing approval"),
    (r'(?:/pair\s+approve|pair.?approve)\s*.*(?:bypass|escalat|unauthorized|low.?perm)',
     "CVE-2026-33579: /pair approve path privilege escalation"),
]

INFRA_AUTH_BYPASS_PATTERNS = [
    (r'(?:cisco)\s+(?:imc|integrated\s+management)\s*.*(?:auth|bypass|vulnerab|exploit|rce)',
     "Cisco IMC authentication bypass (CVSS 9.8)"),
    (r'(?:imc|integrated\s+management\s+controller)\s*.*(?:auth\s+bypass|unauthenticat|pre.?auth)',
     "Cisco IMC pre-authentication bypass"),
    (r'(?:auth|authentication)\s+(?:bypass)\s*.*(?:cisco|imc|bmc|ipmi|management\s+controller)',
     "Management controller authentication bypass"),
    (r'(?:cvss|severity)\s*.*(?:9\.[5-9]|10\.0)\s*.*(?:auth\s+bypass|bypass\s+auth)',
     "Critical-severity authentication bypass (CVSS 9.5+)"),
]

OWASP_AGENTIC_PATTERNS = [
    (r'(?:tool\s+hijack|hijack\s+tool|tool.?jacking)',
     "OWASP Agentic: tool hijacking attack on AI agent"),
    (r'(?:memory\s+poison|poison\s+memory|context\s+poison|poison\s+context)',
     "OWASP Agentic: memory/context poisoning attack on AI agent"),
    (r'(?:agent)\s*.*(?:exploit|attack|hack|compromise)\s*.*(?:tool|memory|context|function\s+call)',
     "OWASP Agentic: agent exploitation via tool/memory manipulation"),
    (r'(?:function\s+call|tool\s+call)\s*.*(?:hijack|intercept|redirect|tamper|manipulat)',
     "OWASP Agentic: function/tool call interception or tampering"),
    (r'(?:conversation|chat|context)\s+(?:history|memory|state)\s*.*(?:poison|inject|manipulat|corrupt|tamper)',
     "OWASP Agentic: conversation history/memory poisoning"),
    (r'(?:agent|assistant)\s+(?:goal|objective|instruction)\s*.*(?:overrid|rewrite|hijack|replac|modify)',
     "OWASP Agentic: agent goal/objective override attack"),
    (r'(?:chain|workflow|pipeline)\s*.*(?:of\s+agents?|multi.?agent)\s*.*(?:attack|exploit|compromise|inject)',
     "OWASP Agentic: multi-agent chain exploitation"),
    (r'(?:owasp)\s*.*(?:agentic|agent)\s*.*(?:top\s*10|security|attack|threat)',
     "OWASP Agentic Top 10 threat reference"),
    (r'(?:shared\s+resource|shared\s+state|shared\s+memory)\s*.*(?:poison|tamper|corrupt|exploit|manipulat)',
     "OWASP Agentic: shared resource poisoning across agents"),
]

AGENT_PLATFORM_PATTERNS = [
    (r'(?:agixt|agi.?xt)\s*.*(?:safe.?join|file\s+(?:read|write|delet)|arbitrary\s+file|path\s+travers)',
     "CVE-2026-39981: AGiXT safe_join() arbitrary file read/write/delete"),
    (r'CVE.2026.39981',
     "CVE-2026-39981: AGiXT path traversal signature"),
    (r'(?:praisonai|praison.?ai)\s*.*(?:command\s+inject|execute.?command|shell\s+inject|yaml.*inject)',
     "CVE-2026-40088: PraisonAI command injection via execute_command"),
    (r'CVE.2026.40088',
     "CVE-2026-40088: PraisonAI command injection signature"),
    (r'(?:praisonai|praison.?ai)\s*.*(?:web.?crawl|ssrf|httpx.*fallback|internal\s+service|cloud\s+metadata)',
     "CVE-2026-40160: PraisonAI web_crawl SSRF to internal/cloud endpoints"),
    (r'CVE.2026.40160',
     "CVE-2026-40160: PraisonAI web_crawl SSRF signature"),
    (r'(?:praisonai|praison.?ai)\s*.*(?:mcp.*spawn|background\s+server|env.*expos)',
     "CVE-2026-40159: PraisonAI MCP background server spawn / env var exposure"),
    (r'(?:agent\s+platform|ai\s+agent\s+framework)\s*.*(?:arbitrary\s+file|command\s+inject|path\s+travers|rce)',
     "Agent platform arbitrary file/command injection"),
    (r'(?:praisonai|praison.?ai)\s*.*(?:yaml|workflow)\s*.*(?:rce|code\s+execut|remote\s+code|arbitrary\s+code|job\s+inject|deserializ)',
     "GHSA-vc46-vw85-3wvm: PraisonAI YAML workflow RCE via type:job entries"),
    (r'(?:type\s*:\s*job|workflow\s+yaml)\s*.*(?:rce|arbitrary|exec|inject|malicious)',
     "GHSA-vc46-vw85-3wvm: malicious type:job in workflow YAML"),
    (r'GHSA.vc46.vw85.3wvm',
     "GHSA-vc46-vw85-3wvm: PraisonAI YAML workflow RCE signature"),
    (r'(?:praisonai|praison.?ai)\s*.*(?:websocket|ws)\s*.*(?:hijack|unauthenticat|session)',
     "GHSA-8x8f-54wf-vv92: PraisonAI WebSocket session hijack"),
    (r'GHSA.8x8f.54wf.vv92',
     "GHSA-8x8f-54wf-vv92: PraisonAI Browser Server WebSocket hijack signature"),
    (r'(?:praisonai|praison.?ai)\s*.*(?:tools\.py|auto.?import)\s*.*(?:rce|exec|code|arbitrary)',
     "GHSA-g985-wjh9-qxxc: PraisonAI tools.py auto-import RCE"),
    (r'GHSA.g985.wjh9.qxxc',
     "GHSA-g985-wjh9-qxxc: PraisonAI tools.py auto-import RCE signature"),
    (r'(?:llamaindex|llama.?index|llama_index)\s*.*(?:torch\.load|torch_load|pytorch\s+load)\s*.*(?:weights_only|pickle|rce|arbitrary\s+code|deserializ)',
     "LlamaIndex embeddings adapter unsafe torch.load() (pickle RCE) -- run-llama #21465"),
    (r'(?:torch\.load)\s*\([^)]*\)\s*.*(?:without|missing|no)\s+weights_only',
     "Unsafe torch.load() call without weights_only=True (pickle deserialization RCE)"),
    (r'(?:torch\.load)\s*\([^)]*weights_only\s*=\s*False',
     "torch.load() with weights_only=False (pickle code execution risk)"),
    (r'(?:malicious\s+)?pickle\s+(?:file|payload|deserializ)\s*.*(?:torch|pytorch|llamaindex|llama.?index|embedding|checkpoint|adapter)',
     "Malicious pickle file in PyTorch/LlamaIndex embeddings or checkpoint loading"),
    (r'(?:llamaindex|llama.?index)\s*.*(?:embeddings?\s+adapter|embedding\s+model)\s*.*(?:exploit|rce|unsafe|pickle)',
     "LlamaIndex embeddings adapter exploitation (unsafe deserialization)"),
    (r'(?:run.llama|run_llama|llama.index)\s*.*(?:#21465|issue\s+21465)',
     "LlamaIndex run-llama issue #21465: torch.load pickle RCE"),
    (r'(?:pickle\s+(?:rce|code\s+execution|arbitrary\s+code))\s*.*(?:agent|llm|llama|pytorch|embedding)',
     "Pickle deserialization RCE in AI agent / model loading path"),
    (r'(?:opentor|open.?tor)\s*.*(?:agent|skill|claude|opencode|ai)',
     "OpenTor: AI agent dark web browsing skill (Tor network access)"),
    (r'(?:agent|ai\s+agent|claude|opencode)\s*.*(?:tor\s+network|tor\s+browser|\.onion|dark\s*web)',
     "AI agent accessing Tor network / dark web / .onion domains"),
    (r'(?:import|from)\s+(?:stem|torrequest|torpy|socks5|pysocks)\b.*(?:agent|tool|skill|claude)',
     "Agent importing Tor/SOCKS library (stem, torrequest, torpy, pysocks)"),
    (r'(?:\.onion)\s*.*(?:spider|crawl|scrape|extract|enumerate|browse)',
     ".onion domain spidering / dark web enumeration by agent"),
    (r'(?:agent|ai|tool)\s*.*(?:browse|access|connect)\s*.*(?:tor|\.onion|dark\s*web|hidden\s+service)',
     "Agent browsing Tor hidden services / dark web access"),
    (r'(?:ioc|indicator)\s*.*(?:extract|harvest|collect)\s*.*(?:\.onion|dark\s*web|tor)',
     "IOC extraction from dark web / Tor (agent-driven)"),
    (r'(?:darknavy|dark.?navy)\s*.*(?:ai\s+agent|root\s+shell|exploit|privilege\s+escalat)',
     "DARKNAVY: AI agent autonomous exploitation / root shell acquisition"),
    (r'(?:ai\s+agent|autonomous\s+agent)\s*.*(?:root\s+shell|root\s+access|privilege\s+escalat)\s*.*(?:autonom|within\s+\d+\s+hour|zero.?day)',
     "AI agent autonomously obtaining root / privilege escalation"),
    (r'(?:ai\s+agent|autonomous)\s*.*(?:exploit\w*)\s*.*(?:fresh\s+(?:os|release|install)|0.?day|zero.?day|ubuntu|linux)',
     "AI agent autonomously exploiting fresh OS release / zero-day"),
]

CANVAS_AUTH_PATTERNS = [
    (r'(?:canvas)\s*.*(?:auth\s+bypass|authenticat\w*\s+bypass|bypass\s+auth)',
     "CVE-2026-3690: OpenClaw Canvas authentication bypass"),
    (r'CVE.2026.3690',
     "CVE-2026-3690: OpenClaw Canvas authentication bypass signature"),
    (r'(?:canvas)\s*.*(?:path\s+travers|information\s+disclos|sensitive\s+info)',
     "CVE-2026-3689: OpenClaw Canvas path traversal information disclosure"),
    (r'CVE.2026.3689',
     "CVE-2026-3689: OpenClaw Canvas path traversal signature"),
    (r'CVE.2026.3691',
     "CVE-2026-3691: OpenClaw Canvas PKCE verifier information disclosure"),
    (r'(?:openclaw|open.?claw)\s*.*(?:canvas)\s*.*(?:vulnerab|exploit|bypass|travers)',
     "OpenClaw Canvas security vulnerability"),
]

RING0_ESCALATION_PATTERNS = [
    (r'(?:ring.?0|ring\s+zero)\s*.*(?:escalat|privilege|exploit|user.?land)',
     "CVE-2025-8061: Ring-0 privilege escalation from user-land"),
    (r'(?:user.?land|user\s+mode)\s*.*(?:ring.?0|kernel\s+mode|kernel\s+space)\s*.*(?:escalat|privilege)',
     "CVE-2025-8061: user-land to Ring-0 escalation"),
    (r'CVE.2025.8061',
     "CVE-2025-8061: Ring-0 privilege escalation signature"),
    (r'(?:privilege\s+escalat)\s*.*(?:ring.?0|kernel\s+mode|kernel\s+level|ring\s+zero)',
     "Ring-0 / kernel-mode privilege escalation"),
    (r'(?:kernel)\s*.*(?:privilege\s+escalat|priv.?esc)\s*.*(?:user.?land|user\s+mode|local)',
     "Local to kernel privilege escalation"),
]

MEDIA_PARSER_PATTERNS = [
    (r'(?:ffmpeg|mov\.c|libavformat)\s*.*(?:recursive|recursi\w+\s+observ|infinite\s+loop|stack\s+overflow|malform)',
     "FFmpeg mov.c recursive observation vulnerability class"),
    (r'(?:recursive\s+(?:observ|pars|struct))\s*.*(?:ffmpeg|mov\.c|media|video|container)',
     "Recursive media structure exploit (FFmpeg mov.c class)"),
    (r'(?:media|video|container)\s*.*(?:parser|demux)\s*.*(?:recursive|anomalous\s+struct|malform\w+\s+atom)',
     "Malformed media container with anomalous/recursive structure"),
    (r'(?:mov|mp4|m4a|quicktime)\s*.*(?:atom|box)\s*.*(?:recursive|nested|self.?referenc|circular)',
     "Recursive/circular atom structure in MOV/MP4 container"),
    (r'(?:maxkb|max.?kb)\s*.*(?:rce|xss|stored\s+xss|iframe|incomplete\s+fix)',
     "CVE-2026-39417/39426: MaxKB stored XSS / incomplete RCE fix"),
    (r'CVE.2026.3941[67]',
     "CVE-2026-39417: MaxKB incomplete RCE fix signature"),
    (r'CVE.2026.39426',
     "CVE-2026-39426: MaxKB stored XSS signature"),
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
    (r'(?:openclaw)?\s*(?:heartbeat\s+context|heartbeat.md\s+context)\s*.*(?:sandbox\s+bypass|sandbox\s+escape|exec\w+|payload)',
     "CVE-2026-41329: OpenClaw critical 9.9 sandbox bypass via heartbeat context"),
    (r'CVE.2026.41329',
     "CVE-2026-41329: OpenClaw heartbeat sandbox bypass signature (CVSS 9.9)"),
    (r'(?:heartbeat\s+context|heartbeatcontext)\s*.*(?:malicious|inject|escape|carry\s+payload)',
     "Heartbeat context carrying malicious payload (sandbox escape)"),
    (r'CVE.2026.41294',
     "CVE-2026-41294: OpenClaw env var issue signature"),
    (r'(?:openclaw)\s+(?:env\s+var|environment\s+variable)\s*.*(?:leak|expos\w+|inject|misus\w+)',
     "CVE-2026-41294: OpenClaw env var exposure/injection issue"),
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
    (r'(?:cohere)\s*.*(?:terrarium)\s*.*(?:sandbox\s+escape|sandbox\s+bypass|escape|exec\w+)',
     "CVE-2026-5752: Cohere Terrarium sandbox escape"),
    (r'CVE.2026.5752',
     "CVE-2026-5752: Cohere Terrarium sandbox escape signature"),
    (r'(?:terrarium)\s*.*(?:exploit|escape|bypass|payload)',
     "Cohere Terrarium sandbox exploitation"),
    (r'(?:openai\s+)?(?:codex\s+cli|codex.cli)\s*.*(?:sandbox\s+escape|sandbox\s+bypass|escape|exec\w+|exploit)',
     "CVE-2025-59532: OpenAI Codex CLI sandbox escape"),
    (r'CVE.2025.59532',
     "CVE-2025-59532: OpenAI Codex CLI sandbox escape signature"),
    (r'(?:codex\s+cli)\s*.*(?:exploit|escape|bypass|isolation|breakout)',
     "Codex CLI sandbox isolation breakout"),
    (r'(?:cross.workspace|cross.directory)\s+(?:direct\s+)?file\s+read\s*.*(?:bypass|isolat\w+|privacy|workspace)',
     "OpenClaw issue #70573: cross-workspace direct file read bypassing isolation"),
    (r'(?:openclaw)\s*.*(?:workspace|isolation|privacy)\s*.*(?:bypass|escape|cross.workspace|direct\s+(?:file\s+)?read)',
     "OpenClaw workspace isolation bypass via direct file read"),
    (r'(?:memorySearch\.enabled|memory.search.enabled|memory_search)\s*[=:]\s*(?:false|disabled|off)\s*.*(?:bypass|cross.workspace|direct\s+read|file\s+access)',
     "OpenClaw isolation bypass: agent reads cross-workspace files even with memorySearch.enabled=false"),
    (r'(?:disabled\s+memory\s+search|memory\s+search\s+disabled|separate\s+workspace\s+director)\s*.*(?:bypass|read|access|leak)',
     "Privacy isolation bypass despite disabled memory search and separate workspaces"),
    (r'(?:agent|llm)\s*.*(?:bypass|circumvent)\s*.*(?:privacy\s+isolat|workspace\s+isolat|cross.tenant)',
     "Agent privacy/workspace isolation bypass"),
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
    # CVE-2026-41318: AnythingLLM Chartable component XSS via markdown image alt text
    (r'!\[[^\]]*<script[^>]*>[^\]]*\]\([^)]*\)',
     "CVE-2026-41318: AnythingLLM Chartable XSS via <script> in markdown image alt text"),
    (r'!\[[^\]]*on(?:load|error|click|mouseover|focus)\s*=[^\]]*\]\([^)]*\)',
     "CVE-2026-41318: AnythingLLM Chartable XSS via DOM event handler in markdown image alt text"),
    (r'!\[[^\]]*javascript\s*:[^\]]*\]\([^)]*\)',
     "CVE-2026-41318: AnythingLLM Chartable XSS via javascript: URI in markdown image alt text"),
    (r'!\[[^\]]*(?:&lt;|<)\s*(?:img|iframe|svg|object|embed)[^\]]*\]\([^)]*\)',
     "Markdown image alt text containing nested HTML element (XSS attempt)"),
    (r'CVE.2026.41318',
     "CVE-2026-41318: AnythingLLM Chartable markdown alt-text XSS signature"),
    (r'(?:anythingllm|anything.?llm)\s*.*(?:chartable)\s*.*(?:xss|script\s+inject|alt\s+text)',
     "AnythingLLM Chartable component XSS via unsanitized markdown alt text"),
    # Opus 4.7 tokenizer glitch tokens / dead zones (ToxSec 2026-04-24)
    (r'[\U000E0000-\U000E007F]{2,}',
     "Tokenizer glitch payload: Tag Character block (U+E0000-U+E007F) used for invisible prompt injection"),
    (r'[\U000E0100-\U000E01EF]{4,}',
     "Tokenizer glitch payload: Variation Selectors Supplement (U+E0100-U+E01EF) clustered density"),
    (r'[\uFFF0-\uFFFF]{2,}',
     "Tokenizer glitch payload: Specials block (U+FFF0-U+FFFF) clustered density"),
    (r'[\uE000-\uF8FF]{8,}',
     "Tokenizer glitch payload: Private Use Area (U+E000-U+F8FF) clustered density (potential dead-zone glitch token)"),
    (r'(?:opus\s*4\.7|claude\s*opus\s*4\.7)\s*.*(?:tokenizer)\s*.*(?:dead\s+zone|glitch\s+token|unmapped|exploit)',
     "Opus 4.7 tokenizer dead-zone / glitch-token exploit reference (ToxSec)"),
    (r'(?:glitch\s+token|tokenizer\s+(?:dead\s+zone|glitch))\s*.*(?:bypass|exploit|prompt\s+guard|jailbreak)',
     "Tokenizer glitch-token bypass of prompt guards"),
    (r'(?:sour\s+cat)\s*.*(?:jailbreak|bypass|safeguard|technique)',
     "Sour Cat Jailbreak: bypassing AI safeguards by stating harmful intentions openly"),
    (r'(?:jailbreak)\s*.*(?:direct\w*\s+stat\w*|open\w*\s+stat\w*|transparent\w*\s+stat\w*)\s*.*(?:harmful|intent|malicious)',
     "Sour Cat technique: jailbreak via transparent/direct statement of harmful intent"),
    (r'(?:bypass)\s*.*(?:safeguard|safety|guardrail|content\s+filter)\s*.*(?:by\s+)?(?:directly\s+stating|openly\s+stating|transparent)',
     "Jailbreak bypassing safety guardrails via direct/transparent harmful statement"),
    (r'(?:zero.?click)\s*.*(?:data\s+exfiltrat|exfiltrat)',
     "Zero-click data exfiltration via prompt injection"),
    (r'(?:prompt\s+inject\w*)\s*.*(?:zero.?click|without\s+(?:user\s+)?interact|automatic\s+(?:data\s+)?exfiltrat)',
     "Prompt injection enabling zero-click / interaction-free data exfiltration"),
    (r'(?:inject\w*\s+prompt|hidden\s+instruction)\s*.*(?:trigger|exfiltrat|steal|extract)\s*.*(?:without\s+(?:user|click|interact)|automatic)',
     "Hidden instruction triggering automatic data theft without user interaction"),
    (r'(?:markdown\s+image|img\s+src|image\s+tag)\s*.*(?:exfiltrat|leak|steal)\s*.*(?:data|token|key|secret|cookie)',
     "Markdown image / img tag data exfiltration channel"),
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


# ---------------------------------------------------------------------------
# Pre-compile every regex at module load time so parse() never recompiles.
# ---------------------------------------------------------------------------
BLOCKED_IP_PATTERNS = _compile_plain(BLOCKED_IP_PATTERNS)
SUPPLY_CHAIN_PATTERNS = _compile_plain(SUPPLY_CHAIN_PATTERNS)
PRIVILEGE_ESCALATION_PATTERNS = _compile_plain(PRIVILEGE_ESCALATION_PATTERNS)
DANGEROUS_ENVVARS = _compile_plain(DANGEROUS_ENVVARS)

FALSE_COMPLETION_PATTERNS = _compile_patterns(FALSE_COMPLETION_PATTERNS)
OPENCLAW_CVE_PATTERNS = _compile_patterns(OPENCLAW_CVE_PATTERNS)
SHELL_WRAPPER_PATTERNS = _compile_patterns(SHELL_WRAPPER_PATTERNS)
GGUF_OVERFLOW_PATTERNS = _compile_patterns(GGUF_OVERFLOW_PATTERNS)
MCP_HEADER_PATTERNS = _compile_patterns(MCP_HEADER_PATTERNS)
DMPOLICY_OPEN_PATTERNS = _compile_patterns(DMPOLICY_OPEN_PATTERNS)
OPENHANDS_INJECTION_PATTERNS = _compile_patterns(OPENHANDS_INJECTION_PATTERNS)
MULTIMODAL_IMAGE_PATTERNS = _compile_patterns(MULTIMODAL_IMAGE_PATTERNS)
MULTIMODAL_AUDIO_PATTERNS = _compile_patterns(MULTIMODAL_AUDIO_PATTERNS)
MCP_EXPOSURE_PATTERNS = _compile_patterns(MCP_EXPOSURE_PATTERNS)
MCP_STDIO_HIJACK_PATTERNS = _compile_patterns(MCP_STDIO_HIJACK_PATTERNS)
CONFIG_POISONING_PATTERNS = _compile_patterns(CONFIG_POISONING_PATTERNS)
MCP_SERVICE_VULN_PATTERNS = _compile_patterns(MCP_SERVICE_VULN_PATTERNS)
AI_PLATFORM_INJECTION_PATTERNS = _compile_patterns(AI_PLATFORM_INJECTION_PATTERNS)
INFRASTRUCTURE_CVE_PATTERNS = _compile_patterns(INFRASTRUCTURE_CVE_PATTERNS)
LANGCHAIN_PROMPT_PATTERNS = _compile_patterns(LANGCHAIN_PROMPT_PATTERNS)
SLOPSQUATTING_PATTERNS = _compile_patterns(SLOPSQUATTING_PATTERNS)
DENIAL_OF_WALLET_PATTERNS = _compile_patterns(DENIAL_OF_WALLET_PATTERNS)
CLAWHAVOC_IOC_PATTERNS = _compile_patterns(CLAWHAVOC_IOC_PATTERNS)
KERNEL_DRIVER_PATTERNS = _compile_patterns(KERNEL_DRIVER_PATTERNS)
PLUGIN_TRUST_PATTERNS = _compile_patterns(PLUGIN_TRUST_PATTERNS)
PAIRING_AUTH_PATTERNS = _compile_patterns(PAIRING_AUTH_PATTERNS)
INFRA_AUTH_BYPASS_PATTERNS = _compile_patterns(INFRA_AUTH_BYPASS_PATTERNS)
OWASP_AGENTIC_PATTERNS = _compile_patterns(OWASP_AGENTIC_PATTERNS)
AGENT_PLATFORM_PATTERNS = _compile_patterns(AGENT_PLATFORM_PATTERNS)
CANVAS_AUTH_PATTERNS = _compile_patterns(CANVAS_AUTH_PATTERNS)
RING0_ESCALATION_PATTERNS = _compile_patterns(RING0_ESCALATION_PATTERNS)
MEDIA_PARSER_PATTERNS = _compile_patterns(MEDIA_PARSER_PATTERNS)
CICD_POISONING_PATTERNS = _compile_patterns(CICD_POISONING_PATTERNS)
PLATFORM_EXEC_PATTERNS = _compile_patterns(PLATFORM_EXEC_PATTERNS)
WRAPPER_PERSISTENCE_PATTERNS = _compile_patterns(WRAPPER_PERSISTENCE_PATTERNS)
SANDBOX_ESCAPE_PATTERNS = _compile_patterns(SANDBOX_ESCAPE_PATTERNS)
SANDBOX_CONFIG_PATTERNS = _compile_patterns(SANDBOX_CONFIG_PATTERNS)
CONTENT_HIJACK_PATTERNS = _compile_patterns(CONTENT_HIJACK_PATTERNS,
                                            re.IGNORECASE | re.DOTALL)
RAG_POISONING_PATTERNS = _compile_patterns(RAG_POISONING_PATTERNS)


class ToolParser:
    """Intercepts tool results, strips payloads, re-validates before return."""

    DANGEROUS_PATTERNS = _compile_plain([
        r'\[IGNORE\s+ALL\s+PREVIOUS',
        r'\[SYSTEM\s+OVERRIDE\]',
        r'\[NEW\s+INSTRUCTIONS?\]',
        r'IGNORE\s+PREVIOUS\s+INSTRUCTIONS',
        r'YOU\s+ARE\s+NOW\s+(?:A|AN)',
        r'FROM\s+NOW\s+ON\s+(?:YOU|YOUR)',
    ])

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
        self._gguf_overflow_detections = 0
        self._mcp_header_detections = 0
        self._dmpolicy_detections = 0
        self._openhands_detections = 0
        self._multimodal_image_detections = 0
        self._multimodal_audio_detections = 0
        self._mcp_exposure_detections = 0
        self._mcp_stdio_hijack_detections = 0
        self._config_poisoning_detections = 0
        self._mcp_service_vuln_detections = 0
        self._ai_platform_injection_detections = 0
        self._infrastructure_cve_detections = 0
        self._langchain_prompt_detections = 0
        self._clawhavoc_ioc_detections = 0
        self._slopsquatting_detections = 0
        self._denial_of_wallet_detections = 0
        self._kernel_driver_detections = 0
        self._plugin_trust_detections = 0
        self._pairing_auth_detections = 0
        self._infra_auth_bypass_detections = 0
        self._owasp_agentic_detections = 0
        self._agent_platform_detections = 0
        self._canvas_auth_detections = 0
        self._ring0_escalation_detections = 0
        self._media_parser_detections = 0

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

        gguf_hit = self._detect_gguf_overflow(raw_result)
        if gguf_hit:
            self._gguf_overflow_detections += 1
            return (f"[Lionguard] GGUF overflow pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"GGUF overflow (CVE-2026-33298): {gguf_hit}",
                        threat_type="vulnerability",
                        confidence=0.94
                    ))

        mcp_hit = self._detect_mcp_header_bypass(raw_result)
        if mcp_hit:
            self._mcp_header_detections += 1
            return raw_result, ScanResult(
                verdict=Verdict.FLAG,
                reason=f"MCP/OpenClaw 2026.3.7: {mcp_hit}",
                threat_type="vulnerability",
                confidence=0.87
            )

        dmpolicy_hit = self._detect_dmpolicy_open(raw_result)
        if dmpolicy_hit:
            self._dmpolicy_detections += 1
            return (f"[Lionguard] Dangerous dmPolicy configuration stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"dmPolicy exposure: {dmpolicy_hit}",
                        threat_type="misconfiguration",
                        confidence=0.91
                    ))

        openhands_hit = self._detect_openhands_injection(raw_result)
        if openhands_hit:
            self._openhands_detections += 1
            return (f"[Lionguard] Command injection pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Command injection: {openhands_hit}",
                        threat_type="injection",
                        confidence=0.93
                    ))

        mm_image_hit = self._detect_multimodal_image(raw_result)
        if mm_image_hit:
            self._multimodal_image_detections += 1
            return (f"[Lionguard] Multimodal image injection stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Multimodal image injection: {mm_image_hit}",
                        threat_type="multimodal_injection",
                        confidence=0.91
                    ))

        mm_audio_hit = self._detect_multimodal_audio(raw_result)
        if mm_audio_hit:
            self._multimodal_audio_detections += 1
            return (f"[Lionguard] Multimodal audio injection stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Multimodal audio injection: {mm_audio_hit}",
                        threat_type="multimodal_injection",
                        confidence=0.91
                    ))

        mcp_exp_hit = self._detect_mcp_exposure(raw_result)
        if mcp_exp_hit:
            self._mcp_exposure_detections += 1
            return (f"[Lionguard] MCP exposure/key decryption pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"MCP endpoint exposure: {mcp_exp_hit}",
                        threat_type="vulnerability",
                        confidence=0.93
                    ))

        kernel_hit = self._detect_kernel_driver(raw_result)
        if kernel_hit:
            self._kernel_driver_detections += 1
            return (f"[Lionguard] Kernel/driver exploit pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Kernel/driver exploit: {kernel_hit}",
                        threat_type="vulnerability",
                        confidence=0.94
                    ))

        plugin_hit = self._detect_plugin_trust(raw_result)
        if plugin_hit:
            self._plugin_trust_detections += 1
            return (f"[Lionguard] Untrusted plugin loading pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Plugin trust violation: {plugin_hit}",
                        threat_type="vulnerability",
                        confidence=0.92
                    ))

        pairing_hit = self._detect_pairing_auth(raw_result)
        if pairing_hit:
            self._pairing_auth_detections += 1
            return (f"[Lionguard] Pairing authorization bypass stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Pairing auth bypass: {pairing_hit}",
                        threat_type="privilege_escalation",
                        confidence=0.92
                    ))

        infra_hit = self._detect_infra_auth_bypass(raw_result)
        if infra_hit:
            self._infra_auth_bypass_detections += 1
            return (f"[Lionguard] Infrastructure auth bypass stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Infrastructure auth bypass: {infra_hit}",
                        threat_type="vulnerability",
                        confidence=0.93
                    ))

        owasp_hit = self._detect_owasp_agentic(raw_result)
        if owasp_hit:
            self._owasp_agentic_detections += 1
            return (f"[Lionguard] OWASP Agentic attack pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"OWASP Agentic: {owasp_hit}",
                        threat_type="agent_exploitation",
                        confidence=0.91
                    ))

        mcp_stdio_hit = self._detect_mcp_stdio_hijack(raw_result)
        if mcp_stdio_hit:
            self._mcp_stdio_hijack_detections += 1
            return (f"[Lionguard] MCP STDIO config hijack stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"MCP STDIO hijack: {mcp_stdio_hit}",
                        threat_type="vulnerability",
                        confidence=0.95
                    ))

        config_poison_hit = self._detect_config_poisoning(raw_result)
        if config_poison_hit:
            self._config_poisoning_detections += 1
            return (f"[Lionguard] Config file poisoning stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Config poisoning: {config_poison_hit}",
                        threat_type="vulnerability",
                        confidence=0.94
                    ))

        mcp_svc_hit = self._detect_mcp_service_vuln(raw_result)
        if mcp_svc_hit:
            self._mcp_service_vuln_detections += 1
            return (f"[Lionguard] MCP service vulnerability stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"MCP service vuln: {mcp_svc_hit}",
                        threat_type="vulnerability",
                        confidence=0.92
                    ))

        ai_inject_hit = self._detect_ai_platform_injection(raw_result)
        if ai_inject_hit:
            self._ai_platform_injection_detections += 1
            return (f"[Lionguard] AI platform SQL/NoSQL injection stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"AI platform injection: {ai_inject_hit}",
                        threat_type="vulnerability",
                        confidence=0.94
                    ))

        infra_cve_hit = self._detect_infrastructure_cve(raw_result)
        if infra_cve_hit:
            self._infrastructure_cve_detections += 1
            return (f"[Lionguard] Infrastructure CVE pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Infrastructure CVE: {infra_cve_hit}",
                        threat_type="vulnerability",
                        confidence=0.91
                    ))

        langchain_prompt_hit = self._detect_langchain_prompt(raw_result)
        if langchain_prompt_hit:
            self._langchain_prompt_detections += 1
            return (f"[Lionguard] LangChain Prompt Loader exploit stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"LangChain Prompt Loader: {langchain_prompt_hit}",
                        threat_type="vulnerability",
                        confidence=0.93
                    ))

        clawhavoc_hit = self._detect_clawhavoc_ioc(raw_result)
        if clawhavoc_hit:
            self._clawhavoc_ioc_detections += 1
            return (f"[Lionguard] ClawHavoc IOC stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"ClawHavoc IOC: {clawhavoc_hit}",
                        threat_type="malicious_skill",
                        confidence=0.96
                    ))

        slopsquat_hit = self._detect_slopsquatting(raw_result)
        if slopsquat_hit:
            self._slopsquatting_detections += 1
            return (f"[Lionguard] Slopsquatting pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Slopsquatting: {slopsquat_hit}",
                        threat_type="supply_chain",
                        confidence=0.92
                    ))

        dow_hit = self._detect_denial_of_wallet(raw_result)
        if dow_hit:
            self._denial_of_wallet_detections += 1
            return (f"[Lionguard] Denial-of-wallet pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Denial-of-wallet: {dow_hit}",
                        threat_type="resource_exhaustion",
                        confidence=0.91
                    ))

        agent_plat_hit = self._detect_agent_platform(raw_result)
        if agent_plat_hit:
            self._agent_platform_detections += 1
            return (f"[Lionguard] Agent platform vulnerability stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Agent platform vuln: {agent_plat_hit}",
                        threat_type="vulnerability",
                        confidence=0.93
                    ))

        canvas_hit = self._detect_canvas_auth(raw_result)
        if canvas_hit:
            self._canvas_auth_detections += 1
            return (f"[Lionguard] Canvas auth bypass stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Canvas auth: {canvas_hit}",
                        threat_type="authentication_bypass",
                        confidence=0.94
                    ))

        ring0_hit = self._detect_ring0_escalation(raw_result)
        if ring0_hit:
            self._ring0_escalation_detections += 1
            return (f"[Lionguard] Ring-0 escalation pattern stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Ring-0 escalation: {ring0_hit}",
                        threat_type="privilege_escalation",
                        confidence=0.95
                    ))

        media_hit = self._detect_media_parser(raw_result)
        if media_hit:
            self._media_parser_detections += 1
            return (f"[Lionguard] Media parser exploit stripped from '{tool_name}' result.",
                    ScanResult(
                        verdict=Verdict.BLOCK,
                        reason=f"Media parser exploit: {media_hit}",
                        threat_type="vulnerability",
                        confidence=0.92
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
            if pattern.search(claimed_result):
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
            if pattern.search(content):
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
            if pattern.search(content):
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
            cleaned = pattern.sub('[STRIPPED BY LIONGUARD]', cleaned)
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
            if pattern.search(text):
                return f"[Lionguard] SSRF blocked: request targets internal/private address"
        return None

    def _detect_supply_chain_persona(self, text: str) -> str:
        """Detect supply-chain persona adoption attempts."""
        for pattern in SUPPLY_CHAIN_PATTERNS:
            if pattern.search(text):
                text = pattern.sub('[PERSONA ADOPTION ATTEMPT STRIPPED BY LIONGUARD]', text)
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
            match = pattern.search(text)
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
            match = pattern.search(text)
            if match:
                return f"dangerous envvar '{match.group().split('=')[0].split(':')[0].strip()}'"
        return None

    def _check_cve_signatures(self, text: str) -> Optional[str]:
        """Match tool results against known OpenClaw CVE attack signatures."""
        for pattern, description in OPENCLAW_CVE_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_rag_poisoning(self, text: str) -> Optional[str]:
        """Detect knowledge-base poisoning techniques in tool results."""
        for pattern, description in RAG_POISONING_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_cicd_poisoning(self, text: str) -> Optional[str]:
        """Detect CI/CD pipeline poisoning patterns.
        CVE-2026-33075: pull_request_target allows arbitrary code execution
        with write permissions and secret access via malicious PRs."""
        for pattern, description in CICD_POISONING_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_platform_exec(self, text: str) -> Optional[str]:
        """Detect platform-level arbitrary execution and IDOR vulnerabilities.
        Covers FastGPT, Langflow, CKAN, and similar agent-building platforms."""
        for pattern, description in PLATFORM_EXEC_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_wrapper_persistence(self, text: str) -> Optional[str]:
        """CVE-2026-29607: Detect allow-always wrapper persistence attacks.
        After initial approval, attackers swap the payload to something
        malicious that runs without re-approval."""
        for pattern, description in WRAPPER_PERSISTENCE_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_sandbox_escape(self, text: str) -> Optional[str]:
        """CVE-2026-31990: Detect sandbox escape via symlink traversal,
        ZIP race conditions, and other sandbox boundary violations."""
        for pattern, description in SANDBOX_ESCAPE_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_sandbox_config(self, text: str) -> Optional[str]:
        """CVE-2026-32046/32048: Detect improper sandbox configuration and
        sandbox inheritance failures across spawned sessions."""
        for pattern, description in SANDBOX_CONFIG_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_shell_wrapper_injection(self, text: str) -> Optional[str]:
        """CVE-2026-32052: Detect command injection in system.run shell-wrapper
        and group-chat manipulation attacks."""
        for pattern, description in SHELL_WRAPPER_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_dmpolicy_open(self, text: str) -> Optional[str]:
        """Detect dangerous dmPolicy='open' configurations that expose elevated
        tools, runtime, and filesystem access."""
        for pattern, description in DMPOLICY_OPEN_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_openhands_injection(self, text: str) -> Optional[str]:
        """CVE-2026-33718: Detect command injection in OpenHands get_git_diff()
        and related injection vectors (Open WebUI, zero-click XSS)."""
        for pattern, description in OPENHANDS_INJECTION_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_media_parser(self, text: str) -> Optional[str]:
        """Detect media parser exploits including FFmpeg mov.c recursive
        observation vulnerability class and MaxKB XSS/RCE."""
        for pattern, description in MEDIA_PARSER_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_mcp_stdio_hijack(self, text: str) -> Optional[str]:
        """Detect MCP STDIO configuration hijacking attacks where attackers
        modify local MCP config to register malicious STDIO servers.
        CVE-2026-30615 (Windsurf), CVE-2026-30624 (Agent Zero),
        CVE-2026-30616 (Jaaz), CVE-2026-30617 (LangChain-ChatChat)."""
        for pattern, description in MCP_STDIO_HIJACK_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_config_poisoning(self, text: str) -> Optional[str]:
        """CVE-2025-61260: Detect config file auto-loading RCE where malicious
        .env or .codex/config.toml files in cloned repos trigger code execution."""
        for pattern, description in CONFIG_POISONING_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_mcp_service_vuln(self, text: str) -> Optional[str]:
        """Detect vulnerabilities in specific MCP service implementations:
        kubernetes arg injection, SkyWalking SSRF, Splunk token exposure,
        Tolgee file read, mcp-neo4j-cypher APOC bypass (CVE-2026-35402),
        AAP MCP log injection (CVE-2026-6494), mcp-framework DoS
        (CVE-2026-39313)."""
        for pattern, description in MCP_SERVICE_VULN_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_ai_platform_injection(self, text: str) -> Optional[str]:
        """Detect SQL/NoSQL injection in AI agent platforms enabling auth
        bypass and data tampering. Covers FastGPT NoSQL login bypass
        (CVE-2026-40351), FastGPT password change injection (CVE-2026-40352),
        and PraisonAI conversation store SQL injection
        (CVE-2026-40315 / GHSA-rg3h-x3jw-7jm5)."""
        for pattern, description in AI_PLATFORM_INJECTION_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_infrastructure_cve(self, text: str) -> Optional[str]:
        """Detect infrastructure-level CVEs that touch agent host stacks.
        Covers HAProxy HTTP/3 to HTTP/1 cross-protocol desync
        (CVE-2026-33555) and Apache ActiveMQ code injection
        (CVE-2026-34197, CISA KEV listed)."""
        for pattern, description in INFRASTRUCTURE_CVE_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_langchain_prompt(self, text: str) -> Optional[str]:
        """Detect LangChain Prompt Loader symlink-based arbitrary file read
        (relative-path symlink traversal in langchain-core prompt loading)."""
        for pattern, description in LANGCHAIN_PROMPT_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_clawhavoc_ioc(self, text: str) -> Optional[str]:
        """Detect ClawHavoc campaign indicators of compromise. Currently
        targets noreplyboter/polymarket-all-in-one (curl-based reverse
        shell backdoor) and the broader ClawHavoc skill ecosystem."""
        for pattern, description in CLAWHAVOC_IOC_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_slopsquatting(self, text: str) -> Optional[str]:
        """Detect slopsquatting attack vectors: AI-hallucinated package
        names that attackers register on PyPI/npm so an agent that
        auto-runs LLM-suggested pip installs gets compromised. Includes
        the broader Vibe Coding attack chain (slopsquatting + hardcoded
        keys + broken auth via pip install)."""
        for pattern, description in SLOPSQUATTING_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_denial_of_wallet(self, text: str) -> Optional[str]:
        """Detect denial-of-wallet attacks: adversarial prompts crafted
        to drain cloud/LLM budgets via unbounded token consumption,
        evading traditional rate limiting (cost amplification / economic
        denial of service)."""
        for pattern, description in DENIAL_OF_WALLET_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_agent_platform(self, text: str) -> Optional[str]:
        """CVE-2026-39981/40088/40160: Detect vulnerabilities in AI agent
        platforms (AGiXT, PraisonAI) including path traversal, command
        injection, and SSRF."""
        for pattern, description in AGENT_PLATFORM_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_canvas_auth(self, text: str) -> Optional[str]:
        """CVE-2026-3690/3689: Detect OpenClaw Canvas authentication bypass
        and path traversal information disclosure."""
        for pattern, description in CANVAS_AUTH_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_ring0_escalation(self, text: str) -> Optional[str]:
        """CVE-2025-8061: Detect Ring-0 privilege escalation from user-land
        code to kernel mode."""
        for pattern, description in RING0_ESCALATION_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_pairing_auth(self, text: str) -> Optional[str]:
        """CVE-2026-33579: Detect unauthorized pairing approval by
        low-permission users in OpenClaw."""
        for pattern, description in PAIRING_AUTH_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_infra_auth_bypass(self, text: str) -> Optional[str]:
        """Detect authentication bypass in infrastructure management
        controllers (Cisco IMC, BMC, IPMI, etc.)."""
        for pattern, description in INFRA_AUTH_BYPASS_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_owasp_agentic(self, text: str) -> Optional[str]:
        """OWASP Agentic Top 10: Detect tool hijacking, memory poisoning,
        agent goal override, and multi-agent chain exploitation."""
        for pattern, description in OWASP_AGENTIC_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_mcp_exposure(self, text: str) -> Optional[str]:
        """CVE-2026-33032 + CVE-2026-33017: Detect MCP endpoint exposure
        without authentication and API key decryption vectors."""
        for pattern, description in MCP_EXPOSURE_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_kernel_driver(self, text: str) -> Optional[str]:
        """CVE-2026-4747 + VEN0m: Detect kernel-level RCE and BYOVD
        (Bring Your Own Vulnerable Driver) attacks."""
        for pattern, description in KERNEL_DRIVER_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_plugin_trust(self, text: str) -> Optional[str]:
        """CVE-2026-32920: Detect plugin/extension loading without
        trust verification, enabling arbitrary code execution."""
        for pattern, description in PLUGIN_TRUST_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_multimodal_image(self, text: str) -> Optional[str]:
        """Detect image-based injection vectors: steganography, typographic
        injection, adversarial perturbations, and metadata payload attacks."""
        for pattern, description in MULTIMODAL_IMAGE_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_multimodal_audio(self, text: str) -> Optional[str]:
        """Detect audio-based injection vectors: WhisperInject, ultrasonic
        commands, subsonic modulation, adversarial audio perturbations."""
        for pattern, description in MULTIMODAL_AUDIO_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_gguf_overflow(self, text: str) -> Optional[str]:
        """CVE-2026-33298: Detect GGUF tensor integer overflow and malformed
        model file attacks that cause heap buffer overflows."""
        for pattern, description in GGUF_OVERFLOW_PATTERNS:
            if pattern.search(text):
                return description
        return None

    def _detect_mcp_header_bypass(self, text: str) -> Optional[str]:
        """Detect OpenClaw 2026.3.7 batch: shell approval gating bypass,
        /acp spawn escape, header validation bypass, MCP Origin issues."""
        for pattern, description in MCP_HEADER_PATTERNS:
            if pattern.search(text):
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
            "gguf_overflow_detections": self._gguf_overflow_detections,
            "mcp_header_detections": self._mcp_header_detections,
            "dmpolicy_detections": self._dmpolicy_detections,
            "openhands_detections": self._openhands_detections,
            "multimodal_image_detections": self._multimodal_image_detections,
            "multimodal_audio_detections": self._multimodal_audio_detections,
            "mcp_exposure_detections": self._mcp_exposure_detections,
            "mcp_stdio_hijack_detections": self._mcp_stdio_hijack_detections,
            "config_poisoning_detections": self._config_poisoning_detections,
            "mcp_service_vuln_detections": self._mcp_service_vuln_detections,
            "ai_platform_injection_detections": self._ai_platform_injection_detections,
            "infrastructure_cve_detections": self._infrastructure_cve_detections,
            "langchain_prompt_detections": self._langchain_prompt_detections,
            "clawhavoc_ioc_detections": self._clawhavoc_ioc_detections,
            "slopsquatting_detections": self._slopsquatting_detections,
            "denial_of_wallet_detections": self._denial_of_wallet_detections,
            "kernel_driver_detections": self._kernel_driver_detections,
            "plugin_trust_detections": self._plugin_trust_detections,
            "pairing_auth_detections": self._pairing_auth_detections,
            "infra_auth_bypass_detections": self._infra_auth_bypass_detections,
            "owasp_agentic_detections": self._owasp_agentic_detections,
            "agent_platform_detections": self._agent_platform_detections,
            "canvas_auth_detections": self._canvas_auth_detections,
            "ring0_escalation_detections": self._ring0_escalation_detections,
            "media_parser_detections": self._media_parser_detections,
        }
