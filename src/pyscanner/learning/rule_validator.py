from __future__ import annotations


def validate_shadow_rule_text(text: str) -> tuple[bool, str]:
    """Minimal structural checks before persisting a shadow rule."""
    if "rules:" not in text or "- id:" not in text:
        return False, "missing rules: or id"
    if "pattern" not in text and "pattern-either" not in text:
        return False, "missing pattern"
    return True, "ok"
