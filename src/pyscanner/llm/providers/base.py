from __future__ import annotations

from typing import Protocol

from pyscanner.config.settings import ScanConfig


class LlmProvider(Protocol):
    def complete_json(self, system: str, user: str, *, schema_hint: str) -> str:
        """Return raw JSON string from the model."""


def get_provider(config: ScanConfig, api_key: str | None) -> LlmProvider | None:
    if not config.enable_llm or config.offline or not config.llm_provider:
        return None
    if config.llm_provider == "openai":
        from pyscanner.llm.providers.openai_provider import OpenAiProvider

        return OpenAiProvider(api_key=api_key or "")
    if config.llm_provider == "anthropic":
        from pyscanner.llm.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=api_key or "")
    if config.llm_provider == "gemini":
        from pyscanner.llm.providers.gemini_provider import GeminiProvider

        return GeminiProvider(api_key=api_key or "")
    if config.llm_provider == "ollama":
        from pyscanner.llm.providers.ollama_provider import OllamaProvider

        return OllamaProvider()  # no API key needed for local Ollama
    return None
