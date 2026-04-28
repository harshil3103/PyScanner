from __future__ import annotations


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token) for budgeting."""
    return max(1, len(text) // 4)


def trim_to_budget(text: str, max_tokens: int) -> str:
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 20] + "\n/* … truncated … */\n"
