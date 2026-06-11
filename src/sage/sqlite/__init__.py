"""sage.sqlite — SQLite-backed mirror of the sage.spanner package.

Module layout mirrors sage.spanner one-to-one so that the sage.db
dispatch layer can route by backend without callers caring which engine
is in use:

    client      connection setup + schema init
    upsert      idempotent writes (INSERT ... ON CONFLICT)
    query       read queries
    incidents   incident read/write helpers
    annotations annotation write helpers

schema/spanner_ddl.sql remains the source of truth for column semantics;
schema/sqlite_ddl.sql is its SQLite-dialect translation (Decision D-3).
"""

from __future__ import annotations
