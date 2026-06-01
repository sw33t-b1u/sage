"""Unified ``sage`` CLI entry point (Initiative H Phase 6 — SAGE 1.0.0).

Each subcommand is a thin click wrapper that delegates to the corresponding
``sage/cli/<name>.py`` module's ``main()``. The wrappers exist so the
single committed CLI surface — see ``docs/api-stability.md`` §3.6 —
is owned by one click ``Group``. The legacy
``python cmd/<name>.py`` / ``python -m cmd.<name>`` invocations were
removed in 1.3.0; ``sage <subcommand>`` is the only supported entry.

This module also retains its historical ``cli``-helper purpose:
``sage.cli.navigator_loader`` continues to live alongside the click
group below — both are exposed from this package.

Subcommands fall into two classes:

* **argparse-based wrappers** — most ``sage/cli/*.py`` modules use
  ``argparse`` inside ``main()``. The wrapper rewrites ``sys.argv``
  and calls ``main()`` so ``sage <subcommand> --help`` reaches
  argparse and prints the real argument help.
* **click-based wrappers** — ``sage/cli/register_incident.py`` already
  exposes a ``click.command``; the wrapper invokes it via
  ``main(args=..., standalone_mode=True)`` so ``--help`` is handled
  by click natively.

Both flavours use ``context_settings`` with ``help_option_names=[]``,
``ignore_unknown_options=True``, and ``allow_extra_args=True``
so the parent ``sage`` group does NOT intercept ``--help`` — it falls
through to the wrapped command's own help formatter.

Modules under this package are imported by the operator-facing
commands in ``sage/cli/`` and should not be used by the ETL / API layers.
"""

from __future__ import annotations

import sys

import click

# Context settings applied to every passthrough subcommand.
_PASSTHROUGH_CTX = {
    "ignore_unknown_options": True,
    "allow_extra_args": True,
    "help_option_names": [],
}


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "SAGE — Security Attack Graph Engine.\n\n"
        "Unified entry point for the schema / load / incident / annotation / "
        "query / API workflows. Run 'sage <subcommand> --help' for the "
        "wrapped command's flag reference."
    ),
)
def cli() -> None:
    """SAGE top-level command group."""


# ---------------------------------------------------------------------------
# Subcommand table (docs/api-stability.md §3.6) — verb-noun naming.
# ---------------------------------------------------------------------------


@cli.command(
    "init-schema",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Apply Spanner Graph DDL + create indexes.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def init_schema_cmd(args: tuple[str, ...]) -> None:
    """Apply Spanner Graph DDL + create indexes."""
    import sage.cli.init_schema as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage init-schema", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "load-assets",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Load BEACON assets.json into Spanner.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def load_assets_cmd(args: tuple[str, ...]) -> None:
    """Load BEACON assets.json into Spanner."""
    import sage.cli.load_assets as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage load-assets", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "load-identity-assets",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Load BEACON identity_assets.json into Spanner.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def load_identity_assets_cmd(args: tuple[str, ...]) -> None:
    """Load BEACON identity_assets.json into Spanner."""
    import sage.cli.load_identity_assets as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage load-identity-assets", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "load-user-accounts",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Load BEACON user_accounts.json into Spanner.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def load_user_accounts_cmd(args: tuple[str, ...]) -> None:
    """Load BEACON user_accounts.json into Spanner."""
    import sage.cli.load_user_accounts as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage load-user-accounts", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "incident-register",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Register an Incident via SAGE's direct-API path (Diamond Model CLI).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def incident_register_cmd(args: tuple[str, ...]) -> None:
    """Register an Incident via SAGE's direct-API path (Diamond Model CLI)."""
    from sage.cli.register_incident import main as register_incident_main  # noqa: PLC0415

    register_incident_main(args=list(args), standalone_mode=True)


@cli.command(
    "actor-annotate",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Write an AnnotatesActor row (Initiative E Phase 5).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def actor_annotate_cmd(args: tuple[str, ...]) -> None:
    """Write an AnnotatesActor row (Initiative E Phase 5)."""
    import sage.cli.annotate_actor as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage actor-annotate", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "query-attack-paths",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Query attack paths for a given asset / actor (offline).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def query_attack_paths_cmd(args: tuple[str, ...]) -> None:
    """Query attack paths for a given asset / actor (offline)."""
    import sage.cli.query_attack_paths as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage query-attack-paths", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "ir-template",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Generate an IR onboarding GHE Issue template.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def ir_template_cmd(args: tuple[str, ...]) -> None:
    """Generate an IR onboarding GHE Issue template."""
    import sage.cli.create_ir_template as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage ir-template", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "serve-api",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Start the SAGE Analysis REST API server (uvicorn).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def serve_api_cmd(args: tuple[str, ...]) -> None:
    """Start the SAGE Analysis REST API server (uvicorn)."""
    import sage.cli.analysis_api as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage serve-api", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "run-etl",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Run the ETL pipeline (OpenCTI poll or --input).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def run_etl_cmd(args: tuple[str, ...]) -> None:
    """Run the ETL pipeline (OpenCTI poll or --input)."""
    import sage.cli.run_etl as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage run-etl", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "visualize-graph",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Generate an interactive HTML visualization of the attack graph.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def visualize_graph_cmd(args: tuple[str, ...]) -> None:
    """Generate an interactive HTML visualization of the attack graph."""
    import sage.cli.visualize_graph as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage visualize-graph", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "report-choke-points",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Generate a Markdown choke-point asset report (Blue Team).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def report_choke_points_cmd(args: tuple[str, ...]) -> None:
    """Generate a Markdown choke-point asset report (Blue Team)."""
    import sage.cli.report_choke_points as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage report-choke-points", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "sync-caldera",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Sync actor TTPs to a Caldera adversary profile.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def sync_caldera_cmd(args: tuple[str, ...]) -> None:
    """Sync actor TTPs to a Caldera adversary profile."""
    import sage.cli.sync_caldera as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage sync-caldera", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "visualize-attack-flow",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Generate a weighted Attack Flow HTML visualization.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def visualize_attack_flow_cmd(args: tuple[str, ...]) -> None:
    """Generate a weighted Attack Flow HTML visualization."""
    import sage.cli.visualize_attack_flow as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage visualize-attack-flow", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "visualize-combined",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Generate a combined Attack Graph + Attack Flow HTML visualization.",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def visualize_combined_cmd(args: tuple[str, ...]) -> None:
    """Generate a combined Attack Graph + Attack Flow HTML visualization."""
    import sage.cli.visualize_combined as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage visualize-combined", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


@cli.command(
    "setup-emulator",
    context_settings=_PASSTHROUGH_CTX,
    short_help="Create Spanner emulator instance and database (dev only).",
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def setup_emulator_cmd(args: tuple[str, ...]) -> None:
    """Create Spanner emulator instance and database (dev only)."""
    import sage.cli.setup_emulator as mod  # noqa: PLC0415

    saved_argv = sys.argv
    sys.argv = ["sage setup-emulator", *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


__all__ = ["cli"]
