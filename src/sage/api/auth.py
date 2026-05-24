"""Central Bearer-token auth dependency (Initiative G Phase 1 / Decision 10).

Replaces the inline ``_verify_auth`` previously defined in
``sage.api.app``. Exposes a factory so write routes can require a set
``SAGE_API_AUTH_TOKEN`` (returning 503 when unset — write-API foot-gun
gate) while read routes stay permissive when the token is unset
(backwards-compatible with existing deployments).

Behaviour matrix:

============================  ==========================  ==========================
``enforce_when_unset``        token unset                 token set
============================  ==========================  ==========================
``False`` (GET routes)        pass through (no auth)      Bearer required (401/403)
``True``  (POST routes)       **503** ServiceUnavailable  Bearer required (401/403)
============================  ==========================  ==========================

Initiative G Decision 10 (plan §2.10) extends ``enforce_when_unset=True``
retroactively to ``POST /api/annotate`` (Initiative E) so both write
endpoints share one policy.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable

from fastapi import HTTPException, Request

from sage.config import Config


def verify_auth(*, enforce_when_unset: bool = False) -> Callable[[Request], None]:
    """Return a FastAPI dependency that enforces Bearer auth.

    ``enforce_when_unset`` selects the unset-token behaviour:
      * ``False`` (default, GET routes) — request is allowed through so
        local / pre-prod deployments without a token continue working.
      * ``True`` (write routes) — request is rejected with 503 because
        an unauthenticated write API would accept poisoned data from
        any caller.
    """

    async def _dependency(request: Request) -> None:
        config: Config = request.app.state.config
        token = config.api_auth_token
        if not token:
            if enforce_when_unset:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "SAGE_API_AUTH_TOKEN is not configured; "
                        "write endpoints require a token to accept requests."
                    ),
                )
            return
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header",
            )
        supplied = auth_header[7:]
        if not secrets.compare_digest(supplied, token):
            raise HTTPException(status_code=403, detail="Invalid API token")

    return _dependency
