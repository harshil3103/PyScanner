from __future__ import annotations

from enum import Enum


class RuleState(str, Enum):
    shadow = "shadow"
    candidate = "candidate"
    active = "active"


class RulePromotionPolicy:
    """Human-in-the-loop default: shadow rules never auto-promote to active."""

    @staticmethod
    def next_state(current: RuleState, *, human_approved: bool) -> RuleState:
        if current == RuleState.shadow and human_approved:
            return RuleState.candidate
        if current == RuleState.candidate and human_approved:
            return RuleState.active
        return current
