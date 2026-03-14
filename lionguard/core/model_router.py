"""
Model Router — Local-First LLM Integration
============================================
Routes Lionguard's security checks to whatever model the user already runs.
Supports Ollama, LM Studio, any OpenAI-compatible endpoint, or cloud APIs.

Default: local Ollama on port 11434. Zero API cost. Zero external calls.
"""

import json
import requests
from dataclasses import dataclass, field
from typing import Optional, Dict


@dataclass
class ModelConfig:
    provider: str = "local"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.1:8b"
    api_key: str = ""
    timeout: int = 30
    temperature: float = 0.1
    max_tokens: int = 1000


class ModelRouter:
    """Routes LLM calls to local or cloud models."""

    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config or ModelConfig()

    def call(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        import os
        if not self.config.api_key:
            self.config.api_key = os.environ.get("XAI_API_KEY", "")

        if self.config.provider == "local":
            return self._call_local(system_prompt, user_prompt)
        elif self.config.provider == "xai":
            return self._call_openai_compat(
                "https://api.x.ai/v1/chat/completions",
                system_prompt, user_prompt
            )
        elif self.config.provider == "openai":
            return self._call_openai_compat(
                "https://api.openai.com/v1/chat/completions",
                system_prompt, user_prompt
            )
        else:
            return self._call_local(system_prompt, user_prompt)

    def _call_local(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call local model via Ollama or any OpenAI-compatible endpoint."""
        base = self.config.base_url.rstrip('/')

        if ":11434" in base and "/v1" not in base:
            return self._call_ollama(system_prompt, user_prompt)

        return self._call_openai_compat(
            f"{base}/chat/completions",
            system_prompt, user_prompt,
            api_key="sk-no-key-required"
        )

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call Ollama's native API."""
        try:
            resp = requests.post(
                f"{self.config.base_url}/api/chat",
                json={
                    "model": self.config.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "num_predict": self.config.max_tokens,
                    }
                },
                timeout=self.config.timeout
            )
            if resp.status_code == 200:
                return resp.json().get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"[Lionguard] Ollama error: {e}")
        return None

    def _call_openai_compat(self, url: str, system_prompt: str,
                            user_prompt: str, api_key: str = None) -> Optional[str]:
        """Call any OpenAI-compatible API (LM Studio, xAI, OpenAI, etc.)."""
        key = api_key or self.config.api_key
        try:
            resp = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.config.model,
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ]
                },
                timeout=self.config.timeout
            )
            if resp.status_code == 200:
                choices = resp.json().get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"[Lionguard] API error: {e}")
        return None
