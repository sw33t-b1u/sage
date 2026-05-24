"""Unified ``sage`` CLI entry point (Initiative H Phase 6 — SAGE 1.0.0).

Each subcommand is a thin click wrapper that delegates to the existing
``cmd/<name>.py`` module's ``main()``. The wrappers exist so the
single committed CLI surface — see ``docs/api-stability.md`` §3.6 —
is owned by one click ``Group``, while the legacy
``python cmd/<name>.py`` / ``python -m cmd.<name>`` invocations stay
functional for the 1.x line (with a deprecation steer).

This module also retains its historical ``cli``-helper purpose:
``sage.cli.navigator_loader`` continues to live alongside the click
group below — both are exposed from this package.

Subcommands fall into two classes:

* **argparse-based wrappers** — most ``cmd/*.py`` modules use
  ``argparse`` inside ``main()``. The wrapper rewrites ``sys.argv``
  and calls ``main()`` so ``sage <subcommand> --help`` reaches
  argparse and prints the real argument help.
* **click-based wrappers** — ``cmd/register_incident.py`` already
  exposes a ``click.command``; the wrapper invokes it via
  ``main(args=..., standalone_mode=True)`` so ``--help`` is handled
  by click natively.

Both flavours use ``context_settings`` with ``help_option_names=[]``
so the parent ``sage`` group does NOT intercept ``--help`` — it falls
through to the wrapped command's own help formatter.

The stdlib ``cmd`` module (a single-file interactive-shell helper)
shadows the project-local ``cmd/`` directory via
``importlib.import_module``, so each wrapper loads its target by file
path through ``importlib.util.spec_from_file_location``. Same fix as
TRACE 1.12.0's ``src/trace_engine/cli/__init__.py``.

Modules under this package are imported by the operator-facing
commands in ``cmd/`` and should not be used by the ETL / API layers.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import click

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CMD_DIR = _PROJECT_ROOT / "cmd"


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


def _load_cmd_module(name: str) -> ModuleType:
    """Load ``cmd/<name>.py`` by file path, bypassing the stdlib ``cmd`` shadow."""
    cache_key = f"_sage_cmd_{name}"
    cached = sys.modules.get(cache_key)
    if cached is not None:
        return cached
    cmd_path = _CMD_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(cache_key, cmd_path)
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"sage CLI: could not locate cmd/{name}.py at {cmd_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


def _delegate_argparse(module: str, prog_name: str, args: list[str]) -> None:
    """Forward ``args`` to an argparse-based ``cmd/<module>.py:main()``.

    Argparse-based ``main()`` functions in this repo read ``sys.argv``
    via ``parser.parse_args()`` (no explicit ``argv=`` argument) OR via
    ``parser.parse_args(argv)`` where the caller passes ``None`` —
    rewriting ``sys.argv`` covers both shapes. A non-zero ``int`` return
    is mapped to ``sys.exit`` so the script-style exit-code contract is
    preserved.
    """
    mod = _load_cmd_module(module)
    saved_argv = sys.argv
    sys.argv = [prog_name, *args]
    try:
        result = mod.main()
    finally:
        sys.argv = saved_argv
    if isinstance(result, int) and result != 0:
        sys.exit(result)


def _delegate_click(module: str, prog_name: str, args: list[str]) -> None:
    """Forward ``args`` to a click-based ``cmd/<module>.py:main`` command."""
    mod = _load_cmd_module(module)
    mod.main(args=args, prog_name=prog_name, standalone_mode=True)


def _register_passthrough(
    cmd_name: str,
    module: str,
    short_help: str,
    *,
    kind: str = "argparse",
) -> None:
    """Register a click subcommand that forwards every flag to ``cmd/<module>.py``.

    ``ignore_unknown_options`` + ``allow_extra_args`` ensure click does
    not parse the wrapped command's flags; ``help_option_names=[]``
    delegates ``--help`` to the wrapped command so the operator sees
    the real argparse / click help output.
    """

    @cli.command(
        cmd_name,
        context_settings={
            "ignore_unknown_options": True,
            "allow_extra_args": True,
            "help_option_names": [],
        },
        short_help=short_help,
    )
    @click.pass_context
    def _wrapper(ctx: click.Context) -> None:
        prog = f"sage {cmd_name}"
        if kind == "click":
            _delegate_click(module, prog, list(ctx.args))
        else:
            _delegate_argparse(module, prog, list(ctx.args))

    _wrapper.__name__ = cmd_name.replace("-", "_")


# ---------------------------------------------------------------------------
# Subcommand table (docs/api-stability.md §3.6) — verb-noun naming.
# ---------------------------------------------------------------------------

_register_passthrough(
    "init-schema",
    "init_schema",
    "Apply Spanner Graph DDL + create indexes.",
)
_register_passthrough(
    "load-assets",
    "load_assets",
    "Load BEACON assets.json into Spanner.",
)
_register_passthrough(
    "load-identity-assets",
    "load_identity_assets",
    "Load BEACON identity_assets.json into Spanner.",
)
_register_passthrough(
    "load-user-accounts",
    "load_user_accounts",
    "Load BEACON user_accounts.json into Spanner.",
)
_register_passthrough(
    "incident-register",
    "register_incident",
    "Register an Incident via SAGE's direct-API path (Diamond Model CLI).",
    kind="click",
)
_register_passthrough(
    "actor-annotate",
    "annotate_actor",
    "Write an AnnotatesActor row (Initiative E Phase 5).",
)
_register_passthrough(
    "query-attack-paths",
    "query_attack_paths",
    "Query attack paths for a given asset / actor (offline).",
)
_register_passthrough(
    "ir-template",
    "create_ir_template",
    "Generate an IR onboarding GHE Issue template.",
)
_register_passthrough(
    "serve-api",
    "analysis_api",
    "Start the SAGE Analysis REST API server (uvicorn).",
)


__all__ = ["cli"]
