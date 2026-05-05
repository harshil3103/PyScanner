
from __future__ import annotations

import json

import httpx


class OllamaProvider:
    """LLM provider backed by a local Ollama instance (default: http://127.0.0.1:11434)."""

    def __init__(self, *, model: str = "llama3.2", base_url: str = "http://127.0.0.1:11434") -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")

    def complete_json(self, system: str, user: str, *, schema_hint: str) -> str:
        _ = schema_hint
        url = f"{self._base_url}/api/chat"
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
        r = httpx.post(url, json=payload, timeout=180.0)
        r.raise_for_status()
        data = r.json()
        text = data["message"]["content"]
        # Ensure valid JSON is returned
        return json.dumps(json.loads(text))
