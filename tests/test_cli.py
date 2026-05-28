"""Tests for the unified ``sage`` CLI entry point (Initiative H Phase 6).

Scope is intentionally **minimal**: this file verifies that the click
``Group`` registers all 9 verb-noun subcommands per
``docs/api-stability.md`` §3.6 and that the root ``--help`` lists them
all. It does NOT invoke any subcommand.

Why no invocation? Several SAGE ``cmd/*.py`` modules touch live
infrastructure at startup (``init_schema.py`` calls
``Config.from_env()`` + ``spanner.Client(...)``; ``analysis_api.py``
runs uvicorn; the ``load-*`` modules call into ``spanner`` mutations
through ``main()``). Running ``--help`` against the wrapper would
trigger the cmd-module body (and any incidental GCP credential lookups
e.g. ``metadata.google.internal``) — that's both fragile in a sandbox
and out of scope for "is the CLI surface wired up correctly".

Deeper behavioural coverage already exists per-module:

* ``tests/test_register_incident_cli.py`` — ``incident-register``
  (the click-based wrapper), with the network/Spanner mocked.
* The argparse ``main()`` functions in the other 8 modules are
  exercised by the surrounding unit tests for the routines they call.

The standalone ``if __name__ == "__main__":`` blocks were removed from
all ``cmd/<name>.py`` modules in SAGE 1.3.0. The unified ``sage``
entry point is now the only supported invocation form.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sage.cli import cli

SUBCOMMANDS: list[str] = [
    "init-schema",
    "load-assets",
    "load-identity-assets",
    "load-user-accounts",
    "incident-register",
    "actor-annotate",
    "query-attack-paths",
    "ir-template",
    "serve-api",
    "run-etl",
    "visualize-graph",
    "report-choke-points",
    "sync-caldera",
    "visualize-attack-flow",
    "visualize-combined",
    "setup-emulator",
]


def test_root_help_lists_all_subcommands():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0, (
        f"'sage --help' exited {result.exit_code}: out={result.output}, exc={result.exception!r}"
    )
    for sub in SUBCOMMANDS:
        assert sub in result.output, (
            f"subcommand {sub!r} missing from 'sage --help':\n{result.output}"
        )


def test_root_help_advertises_unified_entry():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert "sage <subcommand> --help" in result.output


def test_subcommand_count_matches_api_stability_table():
    """``docs/api-stability.md`` §3.6 freezes exactly 16 subcommands."""
    assert len(cli.commands) == 16, (
        f"Subcommand count drift: registered={sorted(cli.commands.keys())}, "
        f"expected 16 per api-stability.md §3.6"
    )


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_subcommand_is_registered(subcommand: str):
    """Each Phase 6 subcommand must be present in the click group.

    Dict-membership only — no invocation. This protects the committed
    CLI surface against accidental rename / deletion without touching
    any cmd-module body.
    """
    assert subcommand in cli.commands, (
        f"{subcommand!r} is not registered on the sage CLI group; "
        f"registered: {sorted(cli.commands.keys())}"
    )
