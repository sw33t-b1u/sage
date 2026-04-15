"""FollowedBy 重み付き Attack Flow をインタラクティブ HTML で可視化するスクリプト。

FollowedBy エッジの weight をエッジ幅・色グラデーションで表現し、
アクターごとの攻撃フロー（TTP 遷移）を直感的に把握できる。

全グラフ可視化（visualize_graph.py）との違い:
  - Attack Flow（TTP ノード + FollowedBy/Uses エッジ）に特化
  - エッジ幅 = weight × 8（太いほど遷移確率が高い）
  - エッジ色 = weight に応じた赤→黄→緑グラデーション
  - source="ir_feedback" のエッジは破線で表示

使用方法:
    uv run python cmd/visualize_attack_flow.py
    uv run python cmd/visualize_attack_flow.py --actor-id intrusion-set--apt99
    uv run python cmd/visualize_attack_flow.py --output /tmp/flow.html --no-open
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

import structlog
from google.cloud import spanner
from pyvis.network import Network

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sage.config import Config
from sage.spanner.query import load_pir_edges, load_pirs

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger(__name__)

# ノード色
_ACTOR_COLOR = "#e74c3c"  # 赤: ThreatActor
_TTP_COLOR = "#e67e22"  # オレンジ: TTP
_MALWARE_COLOR = "#9b59b6"  # 紫: MalwareTool

# FollowedBy source ごとのエッジスタイル
_SOURCE_DASH: dict[str, bool] = {
    "threat_intel": False,  # 実線
    "ir_feedback": True,  # 破線（自社IR実績）
    "manual_analysis": True,  # 破線
}


def _weight_to_color(weight: float) -> str:
    """weight (0.0-1.0) を赤→黄→緑のカラーコードに変換する。"""
    w = max(0.0, min(1.0, weight))
    if w < 0.5:
        # 赤 → 黄 (0.0-0.5)
        r, g, b = 220, int(w * 2 * 200), 30
    else:
        # 黄 → 緑 (0.5-1.0)
        r, g, b = int((1.0 - w) * 2 * 220), 200, 30
    return f"#{r:02x}{g:02x}{b:02x}"


def fetch_ttp_nodes(
    database: spanner.Database,
    actor_stix_id: str | None,
    limit: int,
) -> dict[str, dict]:
    """TTP ノードを取得する。actor_stix_id 指定時はそのアクターが使う TTP に絞る。"""
    if actor_stix_id:
        sql = """
        SELECT t.stix_id, t.name, t.tactic
        FROM TTP t
        JOIN Uses u ON u.ttp_stix_id = t.stix_id
        WHERE u.actor_stix_id = @actor_id
        LIMIT @limit
        """
        params = {"actor_id": actor_stix_id, "limit": limit}
        param_types = {
            "actor_id": spanner.param_types.STRING,
            "limit": spanner.param_types.INT64,
        }
    else:
        sql = "SELECT stix_id, name, tactic FROM TTP LIMIT @limit"
        params = {"limit": limit}
        param_types = {"limit": spanner.param_types.INT64}

    nodes: dict[str, dict] = {}
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=param_types):
            stix_id, name, tactic = row[0], row[1], row[2]
            label = (name or stix_id)[:35]
            nodes[stix_id] = {
                "label": label,
                "title": f"[TTP] {name}\ntactic: {tactic or '—'}",
                "color": _TTP_COLOR,
                "node_type": "TTP",
            }
    return nodes


def fetch_actor_nodes(
    database: spanner.Database,
    actor_stix_id: str | None,
    ttp_ids: set[str],
    limit: int,
) -> dict[str, dict]:
    """Uses エッジ経由で TTP に紐づくアクターを取得する。"""
    if not ttp_ids:
        return {}

    if actor_stix_id:
        sql = """
        SELECT stix_id, name FROM ThreatActor
        WHERE stix_id = @actor_id
        LIMIT 1
        """
        params: dict = {"actor_id": actor_stix_id}
        param_types = {"actor_id": spanner.param_types.STRING}
    else:
        sql = """
        SELECT DISTINCT a.stix_id, a.name
        FROM ThreatActor a
        JOIN Uses u ON u.actor_stix_id = a.stix_id
        LIMIT @limit
        """
        params = {"limit": limit}
        param_types = {"limit": spanner.param_types.INT64}

    nodes: dict[str, dict] = {}
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=param_types):
            stix_id, name = row[0], row[1]
            nodes[stix_id] = {
                "label": (name or stix_id)[:35],
                "title": f"[ThreatActor] {name}",
                "color": _ACTOR_COLOR,
                "node_type": "ThreatActor",
            }
    return nodes


def fetch_malware_nodes(
    database: spanner.Database,
    ttp_ids: set[str],
    limit: int,
) -> dict[str, dict]:
    """MalwareUsesTTP 経由で TTP に紐づく MalwareTool を取得する。"""
    if not ttp_ids:
        return {}

    sql = """
    SELECT DISTINCT m.stix_id, m.name, m.stix_type
    FROM MalwareTool m
    JOIN MalwareUsesTTP mu ON mu.malware_stix_id = m.stix_id
    LIMIT @limit
    """
    params = {"limit": limit}
    param_types = {"limit": spanner.param_types.INT64}

    nodes: dict[str, dict] = {}
    with database.snapshot() as snap:
        try:
            for row in snap.execute_sql(sql, params=params, param_types=param_types):
                stix_id, name, stix_type = row[0], row[1], row[2]
                nodes[stix_id] = {
                    "label": (name or stix_id)[:35],
                    "title": f"[{stix_type}] {name}",
                    "color": _MALWARE_COLOR,
                    "node_type": "MalwareTool",
                }
        except Exception as exc:
            logger.warning("malware_nodes_skip", error=str(exc))
    return nodes


def fetch_followed_by_edges(
    database: spanner.Database,
    ttp_ids: set[str],
    limit: int,
) -> list[dict]:
    """FollowedBy エッジを取得する（weight・source 付き）。"""
    if not ttp_ids:
        return []

    sql = """
    SELECT src_ttp_stix_id, dst_ttp_stix_id, weight, source
    FROM FollowedBy
    LIMIT @limit
    """
    params = {"limit": limit}
    param_types = {"limit": spanner.param_types.INT64}

    edges = []
    with database.snapshot() as snap:
        for row in snap.execute_sql(sql, params=params, param_types=param_types):
            src, dst, weight, source = row[0], row[1], row[2] or 0.0, row[3] or "threat_intel"
            if src in ttp_ids and dst in ttp_ids:
                edges.append({"src": src, "dst": dst, "weight": weight, "source": source})
    return edges


def fetch_uses_edges(
    database: spanner.Database,
    actor_ids: set[str],
    ttp_ids: set[str],
    limit: int,
) -> list[dict]:
    """Uses / MalwareUsesTTP エッジを取得する。"""
    edges = []

    if actor_ids and ttp_ids:
        sql = "SELECT actor_stix_id, ttp_stix_id FROM Uses LIMIT @limit"
        params = {"limit": limit}
        param_types = {"limit": spanner.param_types.INT64}
        with database.snapshot() as snap:
            for row in snap.execute_sql(sql, params=params, param_types=param_types):
                src, dst = row[0], row[1]
                if src in actor_ids and dst in ttp_ids:
                    edges.append({"src": src, "dst": dst, "weight": None, "source": "uses"})

    if ttp_ids:
        sql = "SELECT malware_stix_id, ttp_stix_id FROM MalwareUsesTTP LIMIT @limit"
        params = {"limit": limit}
        param_types = {"limit": spanner.param_types.INT64}
        with database.snapshot() as snap:
            try:
                for row in snap.execute_sql(sql, params=params, param_types=param_types):
                    src, dst = row[0], row[1]
                    if dst in ttp_ids:
                        edges.append({"src": src, "dst": dst, "weight": None, "source": "uses"})
            except Exception as exc:
                logger.warning("malware_uses_ttp_skip", error=str(exc))

    return edges


def build_network(
    all_nodes: dict[str, dict],
    followed_by_edges: list[dict],
    uses_edges: list[dict],
    pirs: list[dict] | None = None,
    pir_ttp_edges: list[dict] | None = None,
) -> Network:
    """pyvis Network を構築する。"""
    net = Network(
        height="920px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#ffffff",
        directed=True,
    )
    net.barnes_hut(gravity=-6000, central_gravity=0.2, spring_length=180)

    for node_id, attrs in all_nodes.items():
        size = 28 if attrs["node_type"] == "ThreatActor" else 20
        net.add_node(
            node_id,
            label=attrs["label"],
            title=attrs["title"],
            color=attrs["color"],
            size=size,
        )

    # FollowedBy エッジ: 重みをエッジ幅・色で表現
    for e in followed_by_edges:
        weight = e["weight"]
        width = max(1.0, weight * 8)
        color = _weight_to_color(weight)
        dashes = _SOURCE_DASH.get(e["source"], False)
        label = f"{weight:.2f}"
        net.add_edge(
            e["src"],
            e["dst"],
            label=label,
            color=color,
            width=width,
            dashes=dashes,
            title=f"weight={weight:.3f}  source={e['source']}",
            arrows="to",
        )

    # Uses エッジ: 細いグレー実線
    for e in uses_edges:
        net.add_edge(
            e["src"],
            e["dst"],
            label="uses",
            color="#666666",
            width=1.0,
            arrows="to",
        )

    for pir in pirs or []:
        decision = pir.get("decision_point") or pir["pir_id"]
        net.add_node(
            pir["pir_id"],
            label=str(decision)[:35],
            title=f"[PIR] {pir['pir_id']}\n{decision}",
            color="#f5b301",
            size=30,
            shape="hexagon",
        )

    known = set(all_nodes.keys()) | {p["pir_id"] for p in (pirs or [])}
    for e in pir_ttp_edges or []:
        if e["pir_id"] in known and e["ttp_stix_id"] in known:
            net.add_edge(
                e["pir_id"],
                e["ttp_stix_id"],
                label="PTTP",
                color="#d4a017",
                width=1.0,
                dashes=[2, 6],
                arrows="to",
                title="PirPrioritizesTTP",
            )

    return net


def add_legend_html(html_path: Path) -> None:
    """凡例 HTML を挿入する。"""
    legend_html = """
<div id="legend" style="
  position:fixed;top:10px;left:10px;
  background:rgba(0,0,0,0.78);
  color:#fff;padding:12px 16px;
  border-radius:8px;font-family:sans-serif;font-size:12px;
  z-index:9999;line-height:1.8">
  <b>Attack Flow</b><br>
  <div style="display:flex;align-items:center;margin:4px 0">
    <div style="width:14px;height:14px;border-radius:50%;background:#e74c3c;margin-right:8px"></div>
    ThreatActor
  </div>
  <div style="display:flex;align-items:center;margin:4px 0">
    <div style="width:14px;height:14px;border-radius:50%;background:#e67e22;margin-right:8px"></div>
    TTP
  </div>
  <div style="display:flex;align-items:center;margin:4px 0">
    <div style="width:14px;height:14px;border-radius:50%;background:#9b59b6;margin-right:8px"></div>
    MalwareTool
  </div>
  <hr style="border-color:#555;margin:8px 0">
  <b>FollowedBy エッジ</b><br>
  <div style="margin:4px 0">&#9473; 実線 = threat_intel</div>
  <div style="margin:4px 0">&#9476; 破線 = ir_feedback</div>
  <div style="margin:4px 0">幅・色 = weight (低→高: 赤→緑)</div>
  <hr style="border-color:#555;margin:8px 0">
  <b>PIR</b><br>
  <div style="margin:4px 0">&#11042; 金六角形 = PIR (Strategic)</div>
  <div style="margin:4px 0">… 金点線 = PTTP (PIR→TTP)</div>
</div>
"""
    content = html_path.read_text()
    content = content.replace("</body>", legend_html + "</body>")
    html_path.write_text(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Attack Flow 重み付き可視化")
    parser.add_argument(
        "--actor-id",
        default=None,
        help="特定アクターの攻撃フローのみ表示（省略時は全アクター）",
    )
    parser.add_argument(
        "--output",
        default="tests/output/attack_flow.html",
        help="出力HTMLファイルパス",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=300,
        help="テーブルごとの取得上限行数（デフォルト: 300）",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="ブラウザを自動で開かない",
    )
    parser.add_argument("--pir-id", default=None, help="特定 PIR にスコープしたサブグラフのみ表示")
    args = parser.parse_args()

    config = Config.from_env()
    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    try:
        pirs = load_pirs(database)
        pir_edges_all = load_pir_edges(database)
    except Exception as exc:
        logger.warning("pir_load_skip", error=str(exc))
        pirs, pir_edges_all = [], {"PirPrioritizesTTP": [], "PirPrioritizesActor": []}

    if args.pir_id:
        pirs = [p for p in pirs if p["pir_id"] == args.pir_id]
        pir_ttp_edges = [
            e for e in pir_edges_all["PirPrioritizesTTP"] if e["pir_id"] == args.pir_id
        ]
        scoped_ttp_ids = {e["ttp_stix_id"] for e in pir_ttp_edges}
    else:
        pir_ttp_edges = pir_edges_all["PirPrioritizesTTP"]
        scoped_ttp_ids = set()

    ttp_nodes = fetch_ttp_nodes(database, args.actor_id, args.limit)
    if not ttp_nodes and not pirs:
        logger.error("no_ttps_found", hint="ETL を先に実行してください")
        sys.exit(1)

    if scoped_ttp_ids:
        ttp_nodes = {nid: a for nid, a in ttp_nodes.items() if nid in scoped_ttp_ids}

    ttp_ids = set(ttp_nodes.keys())
    actor_nodes = fetch_actor_nodes(database, args.actor_id, ttp_ids, args.limit)
    malware_nodes = fetch_malware_nodes(database, ttp_ids, args.limit)

    all_nodes = {**ttp_nodes, **actor_nodes, **malware_nodes}

    followed_by_edges = fetch_followed_by_edges(database, ttp_ids, args.limit)
    uses_edges = fetch_uses_edges(database, set(actor_nodes.keys()), ttp_ids, args.limit)

    net = build_network(
        all_nodes, followed_by_edges, uses_edges, pirs=pirs, pir_ttp_edges=pir_ttp_edges
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(output_path))
    add_legend_html(output_path)

    logger.info(
        "attack_flow_written",
        path=str(output_path),
        nodes=len(all_nodes),
        followed_by=len(followed_by_edges),
        uses=len(uses_edges),
    )

    if not args.no_open:
        webbrowser.open(output_path.resolve().as_uri())


if __name__ == "__main__":
    main()
