"""STIX 2.1 バンドルのパースと前処理。

stix2 ライブラリでバリデーションを行い、ETL が扱いやすい dict 形式へ変換する。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import stix2
import structlog

logger = structlog.get_logger(__name__)

# ETL で処理するオブジェクトタイプ
SUPPORTED_TYPES = frozenset(
    {
        "threat-actor",
        "intrusion-set",
        "attack-pattern",
        "vulnerability",
        "malware",
        "tool",
        "indicator",
        "relationship",
        "incident",  # IR フィードバック用
        "sighting",  # 将来対応
    }
)


def parse_bundle(bundle_dict: dict[str, Any]) -> list[dict[str, Any]]:
    """STIX 2.1 バンドルをパースし、サポート対象オブジェクトのリストを返す。

    - stix2 ライブラリで各オブジェクトを個別にバリデーション
    - バリデーション失敗オブジェクトはスキップしてログ出力
    - サポート外のタイプはスキップ
    """
    raw_objects = bundle_dict.get("objects", [])
    result: list[dict[str, Any]] = []

    for raw in raw_objects:
        obj_type = raw.get("type", "")
        obj_id = raw.get("id", "unknown")

        if obj_type not in SUPPORTED_TYPES:
            continue

        try:
            parsed = _parse_object(raw)
            result.append(parsed)
        except Exception as exc:
            logger.warning("parse_failed", stix_id=obj_id, error=str(exc))

    logger.info("parsed", total=len(raw_objects), accepted=len(result))
    return result


def load_bundle_from_file(path: Path) -> list[dict[str, Any]]:
    """JSON ファイルからバンドルを読み込んでパースする。"""
    with path.open() as f:
        bundle = json.load(f)
    return parse_bundle(bundle)


def _parse_object(raw: dict[str, Any]) -> dict[str, Any]:
    """stix2 ライブラリでパースして dict を返す。

    stix2 はパース時にバリデーションを行う。
    失敗時は stix2.exceptions.STIXError またはその派生例外を送出する。
    """
    parsed = stix2.parse(json.dumps(raw), allow_custom=True)
    # stix2 オブジェクトを通常の dict として返す（Spanner upsert で扱いやすくするため）
    return json.loads(parsed.serialize())
