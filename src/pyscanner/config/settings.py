from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanConfig(BaseSettings):
    """Per-scan options (CLI flags + config file)."""

    model_config = SettingsConfigDict(extra="ignore")

    offline: bool = True
    enable_slm: bool = True
    enable_llm: bool = False
    llm_provider: Literal["openai", "anthropic", "gemini", "ollama"] | None = None
    max_llm_calls: int = 50
    slice_token_budget: int = 4000
    rule_packs: list[str] = Field(default_factory=lambda: ["python_security"])

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"


class Settings(BaseSettings):
    """Global settings from environment."""

    model_config = SettingsConfigDict(env_prefix="PYSCANNER_", extra="ignore")

    config_dir: Path = Field(default_factory=lambda: Path.home() / ".config" / "pyscanner")
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".local" / "share" / "pyscanner")


def get_settings() -> Settings:
    return Settings()
