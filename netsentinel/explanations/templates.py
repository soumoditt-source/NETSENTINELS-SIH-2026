"""Stable explanation template assembly."""

from typing import Any

from .plain_language import build_plain_explanation
from .technical_language import build_technical_explanation


def build_explanation(result: dict[str, Any], source: str = "this device") -> dict[str, Any]:
    """Return both judge-facing and analyst-facing explanation layers."""

    return {
        "plain": build_plain_explanation(result, source),
        "technical": build_technical_explanation(result),
    }
