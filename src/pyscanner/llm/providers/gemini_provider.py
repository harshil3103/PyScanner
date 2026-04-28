from __future__ import annotations

import json

import httpx


class GeminiProvider:
    def __init__(self, *, api_key: str, model: str = "gemini-1.5-flash") -> None:
        self._api_key = api_key
        self._model = model

    def complete_json(self, system: str, user: str, *, schema_hint: str) -> str:
        _ = schema_hint
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": user}]}],
            "systemInstruction": {"parts": [{"text": system}]},
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
        }
        r = httpx.post(url, params={"key": self._api_key}, json=payload, timeout=120.0)
        r.raise_for_status()
        data = r.json()
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts)
        return json.dumps(json.loads(text))
