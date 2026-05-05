from __future__ import annotations

import json
import time

import httpx


_MAX_RETRIES = 5
_BASE_BACKOFF = 5.0  # seconds


class GeminiProvider:
    def __init__(self, *, api_key: str, model: str = "gemini-2.0-flash") -> None:
        self._api_key = api_key
        self._model = model

    def complete_json(self, system: str, user: str, *, schema_hint: str) -> str:
        _ = schema_hint
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model}:generateContent"
        )
        payload = {
            "contents": [{"parts": [{"text": user}]}],
            "systemInstruction": {"parts": [{"text": system}]},
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
        }

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            r = httpx.post(
                url,
                params={"key": self._api_key},
                json=payload,
                timeout=120.0,
            )

            if r.status_code == 429 or r.status_code >= 500:
                # Respect Retry-After header if present, else exponential backoff
                retry_after = r.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else _BASE_BACKOFF * (2 ** attempt)
                last_exc = httpx.HTTPStatusError(
                    f"HTTP {r.status_code}", request=r.request, response=r
                )
                print(
                    f"[gemini] rate-limited (attempt {attempt + 1}/{_MAX_RETRIES}), "
                    f"retrying in {wait:.0f}s…"
                )
                time.sleep(wait)
                continue

            r.raise_for_status()  # surface any other 4xx errors immediately
            data = r.json()
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
            return json.dumps(json.loads(text))

        # All retries exhausted
        raise last_exc  # type: ignore[misc]
