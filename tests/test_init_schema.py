"""Tests for cmd/init_schema.py::split_ddl_statements.

Regression test for the 0.6.0 HasAccess DDL parse failure: an inline
comment like ``-- 0-100; trace edges typically <50`` contained a
semicolon that the naive splitter treated as a statement terminator,
breaking the surrounding CREATE TABLE into two malformed pieces.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "cmd"))

from init_schema import split_ddl_statements  # noqa: E402


class TestSemicolonInComment:
    def test_inline_comment_with_semicolon_does_not_split(self):
        ddl = """
CREATE TABLE Foo (
  id    STRING(36) NOT NULL,
  bar   INT64,                  -- range 0-100; treat as percent
  baz   STRING(64),
) PRIMARY KEY (id);
"""
        statements = split_ddl_statements(ddl)
        assert len(statements) == 1
        assert "CREATE TABLE Foo" in statements[0]
        # The comment was stripped, so the semicolon is gone.
        assert "0-100;" not in statements[0]
        assert "treat as percent" not in statements[0]

    def test_full_line_comment_still_stripped(self):
        ddl = """
-- This is a header comment
CREATE TABLE Foo (id STRING(36)) PRIMARY KEY (id);
"""
        statements = split_ddl_statements(ddl)
        assert len(statements) == 1
        assert "CREATE TABLE Foo" in statements[0]
        assert "header comment" not in statements[0]

    def test_multiple_statements_split_correctly(self):
        ddl = """
CREATE TABLE A (id STRING(36)) PRIMARY KEY (id);
CREATE TABLE B (id STRING(36)) PRIMARY KEY (id);
"""
        statements = split_ddl_statements(ddl)
        assert len(statements) == 2

    def test_inline_comment_preserves_following_lines(self):
        # Regression: the original bug truncated the table at the
        # `--` and orphaned the rest of the column list as a "next
        # statement". Verify the remaining columns survive.
        ddl = """
CREATE TABLE HasAccess (
  identity_stix_id STRING(128) NOT NULL,
  confidence       INT64,                      -- 0-100; trace <50
  stix_modified    TIMESTAMP NOT NULL,
) PRIMARY KEY (identity_stix_id);
"""
        statements = split_ddl_statements(ddl)
        assert len(statements) == 1
        assert "stix_modified" in statements[0]
        assert "PRIMARY KEY" in statements[0]
