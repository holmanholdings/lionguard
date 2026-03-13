"""
Tool-Result Parser — The Return Path Guardian
================================================
Strips and re-validates tool responses before they reach the agent.
This is the critical gap nobody else covers — tool results are UNTRUSTED
external data that bypasses input scanning in most frameworks.
"""

import re
import json
from typing import Dict, Optional, Tuple
from .sentinel import Sentinel, ScanResult, Verdict


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

    def parse(self, tool_name: str, raw_result: str) -> Tuple[str, ScanResult]:
        """Parse and sanitize a tool's return value.

        Returns (sanitized_result, scan_result).
        If BLOCK: the sanitized_result is a safe replacement message.
        If PASS/FLAG: the sanitized_result is the cleaned original.
        """
        self._parsed_count += 1

        cleaned = self._strip_injections(raw_result)
        if cleaned != raw_result:
            self._stripped_count += 1

        if self.sentinel:
            scan = self.sentinel.scan_tool_result(tool_name, cleaned)
            if scan.verdict == Verdict.BLOCK:
                safe_msg = f"[Lionguard] Tool '{tool_name}' returned potentially malicious content. Result blocked."
                return safe_msg, scan
            return cleaned, scan

        return cleaned, ScanResult(verdict=Verdict.PASS, reason="No sentinel configured")

    def _strip_injections(self, text: str) -> str:
        """Remove known injection patterns from text."""
        cleaned = text
        for pattern in self.DANGEROUS_PATTERNS:
            cleaned = re.sub(pattern, '[STRIPPED BY LIONGUARD]', cleaned, flags=re.IGNORECASE)

        cleaned = re.sub(r'<!--.*?-->', '', cleaned, flags=re.DOTALL)

        return cleaned

    def get_stats(self) -> Dict:
        return {
            "total_parsed": self._parsed_count,
            "injections_stripped": self._stripped_count,
        }
