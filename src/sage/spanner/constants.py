"""Spanner-layer constants shared across upsert helpers and tests."""

from __future__ import annotations

# Role tags that elevate impersonation priority (§6.6 / HLD Initiative C Phase 1).
# 15 entries — do not add or remove without updating the DDL comment and CHANGELOG.
HIGH_VALUE_IMPERSONATION_ROLES: frozenset[str] = frozenset(
    {
        "cfo",
        "ceo",
        "cto",
        "coo",
        "executive",
        "it-admin",
        "domain-admin",
        "security-officer",
        "board",
        "dpo",
        "privacy-officer",
        "auditor",
        "legal-counsel",
        "treasurer",
        "procurement",
    }
)


def roles_boost_multiplier(target_roles: list[str]) -> float:
    """Return 1.5 if any role is a high-value impersonation role, else 1.0."""
    roles_lc = {r.lower() for r in target_roles}
    return 1.5 if roles_lc & HIGH_VALUE_IMPERSONATION_ROLES else 1.0


def effective_priority(confidence: int | None, target_roles: list[str]) -> int:
    """Compute ImpersonatesIdentity.effective_priority.

    base = confidence if present, else 50 (ICD 203 "roughly even" default).
    multiplier = 1.5 when target roles intersect HIGH_VALUE_IMPERSONATION_ROLES.
    Result is capped at 100.
    """
    base = confidence if confidence is not None else 50
    roles_lc = {r.lower() for r in target_roles}
    multiplier = 1.5 if roles_lc & HIGH_VALUE_IMPERSONATION_ROLES else 1.0
    return min(100, int(base * multiplier))
