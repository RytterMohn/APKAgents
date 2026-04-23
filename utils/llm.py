"""
Minimal Anthropic-compatible LLM client.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class LLMError(Exception):
    """Raised when an LLM request fails."""


class LLMClient:
    """Thin client for Anthropic-compatible `/v1/messages` APIs."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.enabled = bool(config.get("enabled", False))
        self.provider = config.get("provider", "anthropic")
        self.base_url = (config.get("base_url") or "https://api.anthropic.com").rstrip("/")
        self.api_key = config.get("api_key") or os.getenv("APKAGENTS_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.model = config.get("model", "claude-sonnet-4-6")
        self.model_fallbacks = list(config.get("model_fallbacks", []))
        self.max_tokens = int(config.get("max_tokens", 2048))
        self.temperature = float(config.get("temperature", 0.2))
        self.timeout = int(config.get("timeout", 60))

    def is_enabled(self) -> bool:
        return self.enabled and bool(self.api_key)

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        if not self.is_enabled():
            raise LLMError("LLM client is not enabled")

        last_error = None
        last_http_error = None
        models = [self.model] + [model for model in self.model_fallbacks if model and model != self.model]

        for model in models:
            payload = {
                "model": model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            }
            request = urllib.request.Request(
                url=f"{self.base_url}/v1/messages",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                    "x-api-key": self.api_key,
                },
                method="POST",
            )

            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                text_parts = [item.get("text", "") for item in body.get("content", []) if item.get("type") == "text"]
                return "\n".join(part for part in text_parts if part).strip()
            except urllib.error.HTTPError as exc:
                details = exc.read().decode("utf-8", errors="ignore")
                last_error = LLMError(f"LLM HTTP error {exc.code} for model {model}: {details}")
                last_http_error = last_error
                if exc.code in {429, 500, 502, 503, 504}:
                    continue
                raise last_error from exc
            except Exception as exc:
                if last_http_error is None:
                    last_error = LLMError(f"LLM request failed for model {model}: {exc}")

        if last_http_error:
            raise last_http_error
        if last_error:
            raise last_error
        raise LLMError("LLM request failed without a detailed error")

    def generate_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        text = self.generate_text(system_prompt, user_prompt)
        cleaned = self._strip_code_fence(text)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise LLMError(f"LLM returned invalid JSON: {text[:500]}") from exc

    @staticmethod
    def _strip_code_fence(text: str) -> str:
        stripped = text.strip()
        if stripped.startswith("```"):
            lines = stripped.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            return "\n".join(lines).strip()
        return stripped
