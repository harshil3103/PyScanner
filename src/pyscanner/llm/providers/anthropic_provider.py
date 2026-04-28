from __future__ import annotations

import re

import httpx


class AnthropicProvider:
    def __init__(self, *, api_key: str, model: str = "claude-3-5-sonnet-20241022") -> None:
        self._api_key = api_key
        self._model = model

    def complete_json(self, system: str, user: str, *, schema_hint: str) -> str:
        _ = schema_hint
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self._model,
            "max_tokens": 1024,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        r = httpx.post(url, headers=headers, json=payload, timeout=120.0)
        r.raise_for_status()
        data = r.json()
        text = "".join(b.get("text", "") for b in data.get("content", []) if isinstance(b, dict))
        m = re.search(r"\{[\s\S]*\}\s*$", text)
        if m:
            return m.group(0)
        return text
