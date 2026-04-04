"""Spanner Graph クライアントのセットアップ。"""

from __future__ import annotations

from google.cloud import spanner
from google.cloud.spanner_v1.database import Database


def get_database(
    project_id: str,
    instance_id: str,
    database_id: str,
) -> Database:
    """Spanner Database オブジェクトを返す。"""
    client = spanner.Client(project=project_id)
    instance = client.instance(instance_id)
    return instance.database(database_id)
