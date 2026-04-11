"""IR 記録 GHE Issue テンプレート生成 CLI。

インシデントの基本情報を受け取り、GHE に標準化された IR テンプレート Issue を作成する。
類似インシデント（/similar-incidents API）が提供できる場合は本文に含める。

Usage:
  uv run python -m cmd.create_ir_template \\
    --incident-id incident--xxx \\
    --name "Emotet 感染 #2026-Q2-01" \\
    --severity high \\
    --occurred-at "2026-04-04T09:00:00Z"

環境変数:
  GHE_TOKEN, GHE_REPO が必要。
  SAGE Analysis API (SAGE_API_URL) が設定されていれば類似インシデントを取得する。
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime

import structlog

from sage.notify.github import post_choke_point_issue

logger = structlog.get_logger(__name__)

_TEMPLATE = """\
## インシデント概要

| 項目 | 内容 |
|------|------|
| インシデント ID | `{incident_id}` |
| 名称 | {name} |
| 重大度 | **{severity}** |
| 発生日時 | {occurred_at} |
| 記録作成者 | @{author} |
| ステータス | `open` |

---

## タイムライン

| 時刻 | イベント |
|------|---------|
| {occurred_at} | インシデント検知 |

---

## 影響資産

- （記載してください）

---

## 観測された TTP

- （ATT&CK ID と概要を記載してください）

---

## 暫定対処

- （実施した対処を記載してください）

---

## 類似インシデント（SAGE 参考情報）

{similar_section}

---

## 根本原因分析（RCA）

（調査完了後に記載）

---

## 再発防止策

（調査完了後に記載）

---
*このテンプレートは SAGE `cmd/create_ir_template.py` により生成されました。*
"""

_NO_SIMILAR = "（類似インシデントなし、または SAGE API 未設定）"


def _fetch_similar(incident_id: str) -> str:
    """SAGE API から類似インシデントを取得してテキスト化する。

    SAGE_API_URL が未設定の場合は空文字を返す。
    """
    api_url = os.environ.get("SAGE_API_URL", "")
    if not api_url:
        return ""

    try:
        import requests  # noqa: PLC0415

        resp = requests.get(
            f"{api_url.rstrip('/')}/similar-incidents",
            params={"incident_id": incident_id, "top_k": 3},
            timeout=10,
        )
        resp.raise_for_status()
        items = resp.json()
    except Exception as exc:
        logger.warning("create_ir_template_similar_failed", error=str(exc))
        return ""

    if not items:
        return ""

    lines = ["| インシデント ID | スコア | 共通 TTP 数 |", "|---|---|---|"]
    for item in items:
        shared = len(item.get("shared_ttps", []))
        lines.append(f"| `{item['incident_id']}` | {item['hybrid_score']:.3f} | {shared} |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create IR template Issue on GHE")
    parser.add_argument("--incident-id", required=True, help="Incident STIX ID")
    parser.add_argument("--name", required=True, help="Incident name")
    parser.add_argument("--severity", choices=["low", "medium", "high", "critical"], required=True)
    parser.add_argument(
        "--occurred-at",
        default=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        help="Occurrence datetime in ISO 8601 (default: now)",
    )
    parser.add_argument("--author", default="sage-bot", help="Author name for the template")
    parser.add_argument("--dry-run", action="store_true", help="Print Issue body without posting")
    args = parser.parse_args()

    ghe_token = os.environ.get("GHE_TOKEN", "")
    ghe_repo = os.environ.get("GHE_REPO", "")
    ghe_api_base = os.environ.get("GHE_API_BASE", "https://api.github.com")

    if not args.dry_run and (not ghe_token or not ghe_repo):
        print("Error: GHE_TOKEN and GHE_REPO must be set (or use --dry-run).", file=sys.stderr)
        sys.exit(1)

    similar_text = _fetch_similar(args.incident_id)
    similar_section = similar_text if similar_text else _NO_SIMILAR

    body = _TEMPLATE.format(
        incident_id=args.incident_id,
        name=args.name,
        severity=args.severity,
        occurred_at=args.occurred_at,
        author=args.author,
        similar_section=similar_section,
    )

    title = f"[IR] {args.name}"

    if args.dry_run:
        print(f"# {title}\n")
        print(body)
        return

    result = post_choke_point_issue(
        token=ghe_token,
        repo=ghe_repo,
        title=title,
        body=body,
        api_base=ghe_api_base,
    )

    if result:
        print(f"Issue created/updated: {result.get('html_url', '(unknown)')}")
        logger.info(
            "create_ir_template_done",
            incident_id=args.incident_id,
            url=result.get("html_url"),
        )
    else:
        print("Failed to create Issue.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
