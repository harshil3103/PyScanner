from __future__ import annotations

import httpx


class OpenAiProvider:
    def __init__(self, *, api_key: str, model: str = "gpt-4o-mini") -> None:
        self._api_key = api_key
        self._model = model

    def complete_json(self, system: str, user: str, *, schema_hint: str) -> str:
        _ = schema_hint
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        payload = {
            "model": self._model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        r = httpx.post(url, headers=headers, json=payload, timeout=120.0)
        r.raise_for_status()
        data = r.json()
        return str(data["choices"][0]["message"]["content"])
