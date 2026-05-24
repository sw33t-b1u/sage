"""Spanner-layer constants shared across upsert helpers and tests."""

from __future__ import annotations

# Initiative H (SAGE 1.0.0) removed the HIGH_VALUE_IMPERSONATION_ROLES
# 15-entry frozenset that used to live here as the BEACON 0.12.x role-tag
# fallback for identity_assets without the
# ``is_high_value_impersonation_target`` flag. BEACON 0.13.0+ emits the
# flag directly; ``effective_priority`` now reads only the flag.


def effective_priority(
    confidence: int | None,
    is_high_value_impersonation_target: bool,
) -> int:
    """Compute ``ImpersonatesIdentity.effective_priority`` (flag-driven).

    base = confidence if present, else 50 (ICD 203 "roughly even" default).
    multiplier = 1.5 if ``is_high_value_impersonation_target`` else 1.0.
    Result is capped at 100.
    """
    base = confidence if confidence is not None else 50
    multiplier = 1.5 if is_high_value_impersonation_target else 1.0
    return min(100, int(base * multiplier))
