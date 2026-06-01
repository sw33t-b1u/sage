"""Operator CLI to register an Incident via SAGE's direct-API path.

Initiative G Phase 3. Three operational modes:

* **Interactive** (default) — prompt the analyst for the Diamond Model
  4 quadrants (adversary / capability / infrastructure / victim) one at
  a time. Each prompt carries an example hint. Empty inputs are
  accepted so partial knowledge can still be recorded.
* **--from-file <payload.json>** — non-interactive; the JSON body is
  validated by ``IncidentRequest`` and submitted as-is.
* **--navigator-layer <path>** — pull a TTP sequence out of a MITRE
  ATT&CK Navigator layer JSON file; entry order becomes
  ``sequence_order``. Combinable with the other modes.

Transports:

* Default — HTTP POST to ``--api-url`` (``$SAGE_API_URL`` then
  ``http://localhost:8000``). Bearer token from ``--token`` or
  ``$SAGE_API_AUTH_TOKEN``.
* **--no-api** — bypass the API and call
  ``sage.spanner.incidents.upsert_incident`` directly. Used for
  air-gapped / token-less environments.

Diamond Model methodology — Caltagirone, Pendergast & Betz (2013),
*"The Diamond Model of Intrusion Analysis"*. The paper is "Approved
for public release; distribution is unlimited" so verbatim
quotation of the 4 quadrant definitions is permitted; the prompt hints
below paraphrase the canonical definitions and attribute the model
in the CLI ``--help`` text. See ``ref/diamondmodel.md`` and plan §5.

Exit codes:

* ``0`` — incident accepted (response logged).
* ``2`` — argument / Pydantic / Navigator validation error.
* ``3`` — transport error (HTTP failure or Spanner write exception).

"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import click
import structlog
from pydantic import ValidationError

from sage.cli.navigator_loader import (
    NavigatorEntry,
    NavigatorLayerError,
    load_navigator_layer,
)
from sage.models.incident_request import (
    DIAMOND_MODEL_KEYS,
    IncidentRequest,
    IncidentSeverity,
)

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)


# Severity choice list for click — declared once so --help, prompts, and
# validation stay in sync with ``IncidentSeverity``.
_SEVERITY_CHOICES = [s.value for s in IncidentSeverity]

# Pre-defined namespace UUID for deriving deterministic STIX IDs from
# MITRE ATT&CK technique IDs when a Navigator layer is the only TTP
# input. UUID5 with ``uuid.NAMESPACE_URL`` keeps the mapping
# reproducible across runs (T1078 always derives to the same stix_id).
# Operators whose Spanner TTP rows were loaded with the canonical MITRE
# STIX bundle should use ``--from-file`` with explicit ``ttp_stix_id``
# values; the UUID5 path is for air-gapped / lookup-less workflows.
_MITRE_TECHNIQUE_NS_URL = "https://attack.mitre.org/techniques/"


# Quadrant prompt hints — paraphrased from Caltagirone, Pendergast &
# Betz (2013), "The Diamond Model of Intrusion Analysis" (public
# release; distribution unlimited per the paper's distribution
# statement). Each line is the prompt label; the example is shown
# inline by click's ``prompt`` via the ``show_default`` mechanism.
_DIAMOND_PROMPTS: dict[str, str] = {
    "adversary": (
        "Adversary — the actor / group / org responsible (e.g., APT10, FIN7, Lazarus Group)"
    ),
    "capability": (
        "Capability — tools / techniques / malware used "
        "(e.g., spear-phishing, Cobalt Strike, Mimikatz)"
    ),
    "infrastructure": (
        "Infrastructure — physical / logical resources used "
        "(e.g., C2 domain, fastflux network, mailbox)"
    ),
    "victim": (
        "Victim — target asset / org / persona (e.g., mail relay asset-001, finance team mailboxes)"
    ),
}


def _derive_ttp_stix_id_from_technique(technique_id: str) -> str:
    """Derive a deterministic ``attack-pattern--<uuid5>`` ID from a T-number.

    The MITRE technique catalogue uses STIX IDs assigned by the
    official ATT&CK STIX bundle; these are not directly derivable from
    the technique ID alone. The UUID5 path produces a reproducible
    surrogate so the CLI can populate ``IncidentTTP.ttp_stix_id``
    (Phase 1 model requires a UUID-formatted value). The trade-off:
    these surrogate IDs will NOT join to real ``TTP`` rows unless your
    Spanner load was performed with the same UUID5 scheme. For
    production accuracy, use ``--from-file`` and supply explicit
    ``ttp_stix_id`` values that match your TTP table.
    """
    derived = uuid.uuid5(uuid.NAMESPACE_URL, _MITRE_TECHNIQUE_NS_URL + technique_id)
    return f"attack-pattern--{derived}"


def _navigator_to_payload_blocks(
    entries: list[NavigatorEntry],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert Navigator entries into IncidentRequest payload blocks.

    Returns ``(kill_chain_phases, ttps)``. Both lists share the same
    Navigator-source ordering; ``sequence_order`` on ``ttps`` is the
    list index per plan §2.3 ("orders techniques by Navigator order
    → sequence_order").
    """
    kcps: list[dict[str, Any]] = []
    ttps: list[dict[str, Any]] = []
    for entry in entries:
        stix_id = _derive_ttp_stix_id_from_technique(entry.technique_id)
        kcps.append(
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": entry.tactic,
                "x_ttp_stix_id": stix_id,
            }
        )
        ttps.append(
            {
                "ttp_stix_id": stix_id,
                "sequence_order": entry.sequence_order,
            }
        )
    return kcps, ttps


def _prompt_diamond_model() -> dict[str, str]:
    """Interactively gather the 4 Diamond Model quadrants.

    Empty inputs are accepted so the operator can record an incident
    even when full attribution is not yet available — ``IncidentRequest``
    enforces the full 4-key shape (per plan §2.1), and empty strings
    satisfy the schema.
    """
    quadrants: dict[str, str] = {}
    for key in DIAMOND_MODEL_KEYS:
        prompt_text = _DIAMOND_PROMPTS[key]
        value = click.prompt(prompt_text, default="", show_default=False)
        quadrants[key] = value
    return quadrants


def _build_payload(
    *,
    incident_stix_id: str,
    name: str,
    occurred_at: str,
    severity: str,
    description: str | None,
    diamond_model: dict[str, str] | None,
    navigator_entries: list[NavigatorEntry],
) -> dict[str, Any]:
    """Assemble the IncidentRequest payload dict (pre-Pydantic)."""
    kcps, ttps = _navigator_to_payload_blocks(navigator_entries)
    payload: dict[str, Any] = {
        "incident_stix_id": incident_stix_id,
        "name": name,
        "occurred_at": occurred_at,
        "severity": severity,
        "kill_chain_phases": kcps,
        "ttps": ttps,
    }
    if description is not None:
        payload["description"] = description
    if diamond_model is not None:
        payload["diamond_model"] = diamond_model
    return payload


def _load_payload_from_file(path: Path) -> dict[str, Any]:
    """Read --from-file JSON payload, leaving validation to Pydantic."""
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise click.UsageError(f"failed to read payload file: {exc}") from exc


def _submit_via_api(
    *,
    api_url: str,
    token: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """POST the payload to ``{api_url}/api/incidents`` and return parsed JSON.

    Imported lazily so unit tests that monkey-patch ``requests`` don't
    need to install it (it's already a runtime dep but the lazy import
    keeps the test surface stable).
    """
    import requests  # noqa: PLC0415  -- intentional lazy import

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = api_url.rstrip("/") + "/api/incidents"
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
    except requests.RequestException as exc:
        raise click.ClickException(f"HTTP transport error: {exc}") from exc
    if resp.status_code >= 400:
        raise click.ClickException(
            f"POST /api/incidents failed: HTTP {resp.status_code} — {resp.text[:200]}"
        )
    try:
        return resp.json()
    except ValueError as exc:
        raise click.ClickException(
            f"POST /api/incidents returned non-JSON body: {resp.text[:200]}"
        ) from exc


def _submit_via_spanner(payload: dict[str, Any]) -> dict[str, Any]:
    """Bypass the API and call the Spanner upsert helper directly.

    The Spanner client is constructed via :func:`sage.spanner.client.get_database`
    using the standard ``Config.from_env()`` env vars. Imports are lazy
    so the test suite can monkey-patch ``upsert_incident`` without
    needing real GCP credentials at import time.
    """
    from sage.config import Config  # noqa: PLC0415
    from sage.spanner.client import get_database  # noqa: PLC0415
    from sage.spanner.incidents import upsert_incident  # noqa: PLC0415

    req = IncidentRequest.model_validate(payload)
    config = Config.from_env()
    database = get_database(
        config.gcp_project_id,
        config.spanner_instance_id,
        config.spanner_database_id,
    )
    return upsert_incident(database=database, req=req)


def _default_incident_stix_id() -> str:
    return f"incident--{uuid.uuid4()}"


@click.command(
    help=(
        "Register an Incident with SAGE via the direct-API path (Initiative G).\n\n"
        "Diamond Model methodology: Caltagirone, Pendergast & Betz (2013) — "
        "see docs/dependencies.md and ref/diamondmodel.md."
    ),
)
@click.option(
    "--id",
    "incident_stix_id",
    default=None,
    help="incident_stix_id override (default: incident--<uuid4> auto-generated).",
)
@click.option("--name", default=None, help="Short human-readable incident name.")
@click.option(
    "--occurred-at",
    default=None,
    help="ISO-8601 timestamp the incident occurred (e.g., 2026-05-20T12:34:56Z).",
)
@click.option(
    "--severity",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default=None,
    help="Severity vocab: low / medium / high / critical.",
)
@click.option(
    "--description",
    default=None,
    help="Free-text description (e.g., IR ticket id, 3rd-party source note).",
)
@click.option(
    "--navigator-layer",
    "navigator_layer",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="MITRE Navigator layer JSON; techniques become kill_chain_phases + ttps in order.",
)
@click.option(
    "--diamond",
    "diamond_pairs",
    multiple=True,
    metavar="KEY=VALUE",
    help=(
        "Diamond Model quadrant override (repeatable). KEY must be one of "
        "adversary / capability / infrastructure / victim."
    ),
)
@click.option(
    "--from-file",
    "from_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Read the full IncidentRequest JSON body from this file (skip prompts).",
)
@click.option(
    "--no-api",
    "no_api",
    is_flag=True,
    default=False,
    help="Bypass POST /api/incidents and call the Spanner upsert helper directly.",
)
@click.option(
    "--api-url",
    "api_url",
    default=lambda: os.environ.get("SAGE_API_URL", "http://localhost:8000"),
    show_default="$SAGE_API_URL or http://localhost:8000",
    help="Base URL of the SAGE Analysis API (default reads $SAGE_API_URL).",
)
@click.option(
    "--token",
    default=lambda: os.environ.get("SAGE_API_AUTH_TOKEN", ""),
    show_default="$SAGE_API_AUTH_TOKEN",
    help="Bearer token (default reads $SAGE_API_AUTH_TOKEN).",
)
@click.option(
    "--interactive/--no-interactive",
    "interactive",
    default=True,
    help="Prompt for missing fields when neither --from-file nor full flags are supplied.",
)
def main(
    incident_stix_id: str | None,
    name: str | None,
    occurred_at: str | None,
    severity: str | None,
    description: str | None,
    navigator_layer: Path | None,
    diamond_pairs: tuple[str, ...],
    from_file: Path | None,
    no_api: bool,
    api_url: str,
    token: str,
    interactive: bool,
) -> None:
    """Implements the CLI; see module docstring for behaviour."""
    # ----- Branch 1: --from-file overrides every other input -----
    if from_file is not None:
        payload = _load_payload_from_file(from_file)
        if navigator_layer is not None:
            click.echo(
                "warning: --navigator-layer is ignored when --from-file is supplied",
                err=True,
            )
    else:
        # ----- Branch 2: build payload from flags + prompts + navigator -----
        navigator_entries: list[NavigatorEntry] = []
        if navigator_layer is not None:
            try:
                navigator_entries = load_navigator_layer(navigator_layer)
            except NavigatorLayerError as exc:
                raise click.UsageError(str(exc)) from exc

        # Required fields: prompt if missing AND interactive, else fail
        if name is None:
            name = click.prompt("Incident name", default="").strip() if interactive else ""
        if not name:
            raise click.UsageError("--name is required (or run interactively)")

        if occurred_at is None:
            occurred_at = (
                click.prompt(
                    "occurred_at (ISO-8601, e.g. 2026-05-20T12:34:56Z)",
                    default="",
                ).strip()
                if interactive
                else ""
            )
        if not occurred_at:
            raise click.UsageError("--occurred-at is required (or run interactively)")

        if severity is None:
            severity = (
                click.prompt(
                    "severity",
                    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
                    default="medium",
                )
                if interactive
                else ""
            )
        if not severity:
            raise click.UsageError("--severity is required (or run interactively)")

        # Diamond Model: collect flag overrides first, prompt for missing
        # keys when interactive, otherwise leave None (Pydantic accepts
        # diamond_model=None per plan §2.1).
        diamond: dict[str, str] | None = None
        flag_overrides: dict[str, str] = {}
        for raw in diamond_pairs:
            if "=" not in raw:
                raise click.UsageError(f"--diamond expects KEY=VALUE, got {raw!r}")
            key, _, value = raw.partition("=")
            key = key.strip().lower()
            if key not in DIAMOND_MODEL_KEYS:
                raise click.UsageError(
                    f"--diamond key must be one of {DIAMOND_MODEL_KEYS}, got {key!r}"
                )
            flag_overrides[key] = value

        if flag_overrides or interactive:
            diamond = dict(flag_overrides)
            if interactive:
                prompted = _prompt_diamond_model()
                # Flag overrides win when both are supplied.
                for k, v in prompted.items():
                    diamond.setdefault(k, v)
            missing = [k for k in DIAMOND_MODEL_KEYS if k not in diamond]
            if missing:
                # Fill missing quadrants with empty strings — Pydantic
                # requires all 4 keys present; values may be empty.
                for k in missing:
                    diamond[k] = ""

        if incident_stix_id is None:
            incident_stix_id = _default_incident_stix_id()

        payload = _build_payload(
            incident_stix_id=incident_stix_id,
            name=name,
            occurred_at=occurred_at,
            severity=severity,
            description=description,
            diamond_model=diamond,
            navigator_entries=navigator_entries,
        )

    # ----- Validate against Pydantic before transport -----
    try:
        IncidentRequest.model_validate(payload)
    except ValidationError as exc:
        click.echo("error: payload failed IncidentRequest validation:", err=True)
        click.echo(str(exc), err=True)
        sys.exit(2)

    # ----- Transport -----
    if no_api:
        result = _submit_via_spanner(payload)
    else:
        result = _submit_via_api(api_url=api_url, token=token or None, payload=payload)

    click.echo(json.dumps(result, default=str, indent=2))
