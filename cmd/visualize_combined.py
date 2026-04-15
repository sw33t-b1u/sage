"""Attack Graph + Attack Flow 統合可視化スクリプト。

全ノード種別（ThreatActor, TTP, Asset, Vulnerability 等）と全エッジを
1つの HTML に描画する。Attack Flow（FollowedBy）は重み付き表示で、
Attack Graph（Targets, HasVulnerability 等）と合わせて
ThreatActor → TTP → Vulnerability → Asset のパスが直感的に見える。

- FollowedBy エッジ: 重みに応じた幅・色グラデーション（赤→黄→緑）
- ir_feedback / manual_analysis エッジ: 破線
- 通常エッジ: 薄いグレー実線（種別ラベル付き）

使用方法:
    uv run python cmd/visualize_combined.py
    uv run python cmd/visualize_combined.py --actor-id intrusion-set--apt99
    uv run python cmd/visualize_combined.py --output /tmp/combined.html --no-open
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

# ノード種別ごとの色・サイズ定義
_NODE_STYLE: dict[str, dict] = {
    "ThreatActor": {"color": "#e74c3c", "size": 30},  # 赤
    "TTP": {"color": "#e67e22", "size": 20},  # オレンジ
    "Vulnerability": {"color": "#f1c40f", "size": 18},  # 黄
    "MalwareTool": {"color": "#9b59b6", "size": 20},  # 紫
    "Observable": {"color": "#1abc9c", "size": 16},  # ターコイズ
    "Incident": {"color": "#e91e63", "size": 22},  # ピンク
    "Asset": {"color": "#3498db", "size": 26},  # 青
    "SecurityControl": {"color": "#95a5a6", "size": 16},  # グレー
    "PIR": {"color": "#f5b301", "size": 32, "shape": "hexagon"},  # 金（六角形）
}

# ノードテーブル定義: (テーブル名, IDカラム, 表示名カラム)
_NODE_TABLES = [
    ("ThreatActor", "stix_id", "name"),
    ("TTP", "stix_id", "name"),
    ("Vulnerability", "stix_id", "cve_id"),
    ("MalwareTool", "stix_id", "name"),
    ("Observable", "stix_id", "value"),
    ("Incident", "stix_id", "name"),
    ("Asset", "id", "name"),
    ("SecurityControl", "id", "name"),
]

# エッジテーブル定義: (テーブル名, ソースキー列, 宛先キー列, ラベル)
# FollowedBy は特殊処理するためここには含めない
_EDGE_TABLES = [
    ("Uses", "actor_stix_id", "ttp_stix_id", "USES"),
    ("UsesTool", "actor_stix_id", "tool_stix_id", "USES_TOOL"),
    ("MalwareUsesTTP", "malware_stix_id", "ttp_stix_id", "MALWARE_USES"),
    ("Exploits", "ttp_stix_id", "vuln_stix_id", "EXPLOITS"),
    ("Targets", "actor_stix_id", "asset_id", "TARGETS"),
    ("HasVulnerability", "asset_id", "vuln_stix_id", "HAS_VULN"),
    ("ConnectedTo", "src_asset_id", "dst_asset_id", "CONNECTED_TO"),
    ("ProtectedBy", "asset_id", "control_id", "PROTECTED_BY"),
    ("IndicatesTTP", "observable_stix_id", "ttp_stix_id", "INDICATES"),
    ("IndicatesActor", "observable_stix_id", "actor_stix_id", "INDICATES"),
    ("IncidentUsesTTP", "incident_stix_id", "ttp_stix_id", "INCIDENT_USES"),
]

# FollowedBy source ごとの破線スタイル
_SOURCE_DASH: dict[str, bool] = {
    "threat_intel": False,
    "ir_feedback": True,
    "manual_analysis": True,
}


def _weight_to_color(weight: float) -> str:
    """weight (0.0-1.0) を赤→黄→緑のカラーコードに変換する。"""
    w = max(0.0, min(1.0, weight))
    if w < 0.5:
        r, g, b = 220, int(w * 2 * 200), 30
    else:
        r, g, b = int((1.0 - w) * 2 * 220), 200, 30
    return f"#{r:02x}{g:02x}{b:02x}"


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------


def fetch_pir_data(
    database: spanner.Database,
    pir_id_filter: str | None,
) -> tuple[list[dict], dict[str, list[dict]], set[str], set[str], set[str]]:
    """Return (pirs, edges_by_table, scoped_actor_ids, scoped_ttp_ids, scoped_asset_ids).

    When pir_id_filter is set, the scoped sets are non-empty and contain the
    actor / TTP / asset stix_ids reachable from that PIR via cascade edges.
    Otherwise all sets are empty and downstream code skips PIR-based scoping.
    """
    try:
        pirs = load_pirs(database)
        edges = load_pir_edges(database)
    except Exception as exc:
        logger.warning("pir_load_skip", error=str(exc))
        return (
            [],
            {"PirPrioritizesActor": [], "PirPrioritizesTTP": [], "PirWeightsAsset": []},
            set(),
            set(),
            set(),
        )

    if pir_id_filter is None:
        return pirs, edges, set(), set(), set()

    pirs = [p for p in pirs if p["pir_id"] == pir_id_filter]
    actor_ids = {
        e["actor_stix_id"] for e in edges["PirPrioritizesActor"] if e["pir_id"] == pir_id_filter
    }
    ttp_ids = {e["ttp_stix_id"] for e in edges["PirPrioritizesTTP"] if e["pir_id"] == pir_id_filter}
    asset_ids = {e["asset_id"] for e in edges["PirWeightsAsset"] if e["pir_id"] == pir_id_filter}
    edges = {k: [e for e in v if e["pir_id"] == pir_id_filter] for k, v in edges.items()}
    return pirs, edges, actor_ids, ttp_ids, asset_ids


def fetch_nodes(
    database: spanner.Database,
    actor_stix_id: str | None,
    limit: int,
    scoped_actor_ids: set[str] | None = None,
    scoped_ttp_ids: set[str] | None = None,
    scoped_asset_ids: set[str] | None = None,
) -> dict[str, dict]:
    """全ノードテーブルを読み込み {node_id: {label, title, color, size, node_type}} を返す。

    actor_stix_id 指定時は、そのアクターと関連する TTP / MalwareTool に加え、
    全 Asset / Vulnerability / SecurityControl を返す。
    """
    nodes: dict[str, dict] = {}

    for table, id_col, name_col in _NODE_TABLES:
        if actor_stix_id and table == "ThreatActor":
            sql = f"SELECT {id_col}, {name_col} FROM {table} WHERE {id_col} = @actor_id"
            params: dict = {"actor_id": actor_stix_id}
            param_types = {"actor_id": spanner.param_types.STRING}
        elif actor_stix_id and table == "TTP":
            sql = (
                f"SELECT t.{id_col}, t.{name_col} FROM {table} t "
                f"JOIN Uses u ON u.ttp_stix_id = t.stix_id "
                f"WHERE u.actor_stix_id = @actor_id LIMIT @limit"
            )
            params = {"actor_id": actor_stix_id, "limit": limit}
            param_types = {
                "actor_id": spanner.param_types.STRING,
                "limit": spanner.param_types.INT64,
            }
        elif actor_stix_id and table == "MalwareTool":
            sql = (
                f"SELECT m.{id_col}, m.{name_col} FROM {table} m "
                f"JOIN UsesTool ut ON ut.tool_stix_id = m.stix_id "
                f"WHERE ut.actor_stix_id = @actor_id LIMIT @limit"
            )
            params = {"actor_id": actor_stix_id, "limit": limit}
            param_types = {
                "actor_id": spanner.param_types.STRING,
                "limit": spanner.param_types.INT64,
            }
        else:
            sql = f"SELECT {id_col}, {name_col} FROM {table} LIMIT @limit"
            params = {"limit": limit}
            param_types = {"limit": spanner.param_types.INT64}

        style = _NODE_STYLE[table]
        with database.snapshot() as snap:
            try:
                for row in snap.execute_sql(sql, params=params, param_types=param_types):
                    node_id, display = row[0], row[1]
                    if node_id is None:
                        continue
                    label = str(display or node_id)[:40]
                    nodes[node_id] = {
                        "label": label,
                        "title": f"[{table}] {label}",
                        "color": style["color"],
                        "size": style["size"],
                        "node_type": table,
                    }
            except Exception as exc:
                logger.warning("node_table_skip", table=table, error=str(exc))

    # PIR scoping: drop actors / TTPs / assets not reachable from the chosen PIR
    if scoped_actor_ids or scoped_ttp_ids or scoped_asset_ids:
        kept: dict[str, dict] = {}
        for nid, attrs in nodes.items():
            t = attrs["node_type"]
            if t == "ThreatActor" and nid not in scoped_actor_ids:
                continue
            if t == "TTP" and nid not in scoped_ttp_ids:
                continue
            if t == "Asset" and nid not in scoped_asset_ids:
                continue
            kept[nid] = attrs
        nodes = kept

    logger.info("nodes_fetched", count=len(nodes))
    return nodes


def fetch_followed_by_edges(
    database: spanner.Database,
    node_ids: set[str],
    limit: int,
) -> list[dict]:
    """FollowedBy エッジを取得する（weight・source 付き）。"""
    sql = "SELECT src_ttp_stix_id, dst_ttp_stix_id, weight, source FROM FollowedBy LIMIT @limit"
    params = {"limit": limit}
    param_types = {"limit": spanner.param_types.INT64}

    edges = []
    with database.snapshot() as snap:
        try:
            for row in snap.execute_sql(sql, params=params, param_types=param_types):
                src, dst = row[0], row[1]
                weight, source = row[2] or 0.0, row[3] or "threat_intel"
                if src in node_ids and dst in node_ids:
                    edges.append({"src": src, "dst": dst, "weight": weight, "source": source})
        except Exception as exc:
            logger.warning("followed_by_skip", error=str(exc))
    return edges


def fetch_standard_edges(
    database: spanner.Database,
    node_ids: set[str],
    limit: int,
) -> list[tuple[str, str, str]]:
    """FollowedBy 以外の全エッジテーブルを読み込む。"""
    edges: list[tuple[str, str, str]] = []

    for table, src_col, dst_col, edge_label in _EDGE_TABLES:
        sql = f"SELECT {src_col}, {dst_col} FROM {table} LIMIT @limit"
        params = {"limit": limit}
        param_types = {"limit": spanner.param_types.INT64}
        with database.snapshot() as snap:
            try:
                for row in snap.execute_sql(sql, params=params, param_types=param_types):
                    src, dst = row[0], row[1]
                    if src in node_ids and dst in node_ids:
                        edges.append((src, dst, edge_label))
            except Exception as exc:
                logger.warning("edge_table_skip", table=table, error=str(exc))

    logger.info("standard_edges_fetched", count=len(edges))
    return edges


# ---------------------------------------------------------------------------
# Network builder
# ---------------------------------------------------------------------------


def build_network(
    nodes: dict[str, dict],
    followed_by_edges: list[dict],
    standard_edges: list[tuple[str, str, str]],
    pirs: list[dict] | None = None,
    pir_edges: dict[str, list[dict]] | None = None,
) -> Network:
    """pyvis Network オブジェクトを構築する。"""
    net = Network(
        height="920px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#ffffff",
        directed=True,
    )
    net.barnes_hut(gravity=-8000, central_gravity=0.25, spring_length=160)

    for node_id, attrs in nodes.items():
        kwargs = {
            "label": attrs["label"],
            "title": attrs["title"],
            "color": attrs["color"],
            "size": attrs["size"],
        }
        if attrs.get("shape"):
            kwargs["shape"] = attrs["shape"]
        net.add_node(node_id, **kwargs)

    # PIR nodes (gold hexagon)
    pir_style = _NODE_STYLE["PIR"]
    for pir in pirs or []:
        decision = pir.get("decision_point") or pir["pir_id"]
        title_lines = [f"[PIR] {pir['pir_id']}", decision]
        if pir.get("recommended_action"):
            title_lines.append(f"Action: {pir['recommended_action']}")
        net.add_node(
            pir["pir_id"],
            label=str(decision)[:40],
            title="\n".join(title_lines),
            color=pir_style["color"],
            size=pir_style["size"],
            shape=pir_style["shape"],
        )

    # PIR cascade edges
    pir_edges = pir_edges or {}
    node_ids = set(nodes.keys()) | {p["pir_id"] for p in (pirs or [])}
    for e in pir_edges.get("PirPrioritizesActor", []):
        if e["pir_id"] in node_ids and e["actor_stix_id"] in node_ids:
            net.add_edge(
                e["pir_id"],
                e["actor_stix_id"],
                label="TAP",
                color="#f5b301",
                width=2.0,
                dashes=True,
                arrows="to",
                title=f"PirPrioritizesActor overlap={e.get('overlap_ratio')}",
            )
    for e in pir_edges.get("PirPrioritizesTTP", []):
        if e["pir_id"] in node_ids and e["ttp_stix_id"] in node_ids:
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
    for e in pir_edges.get("PirWeightsAsset", []):
        if e["pir_id"] in node_ids and e["asset_id"] in node_ids:
            net.add_edge(
                e["pir_id"],
                e["asset_id"],
                label=f"×{e.get('criticality_multiplier')}",
                color="#e09f00",
                width=2.0,
                dashes=True,
                arrows="to",
                title=f"PirWeightsAsset tag={e.get('matched_tag')}",
            )

    # FollowedBy: 重み付きエッジ（幅・色・破線）
    for e in followed_by_edges:
        weight = e["weight"]
        width = max(1.0, weight * 8)
        color = _weight_to_color(weight)
        dashes = _SOURCE_DASH.get(e["source"], False)
        net.add_edge(
            e["src"],
            e["dst"],
            label=f"{weight:.2f}",
            color=color,
            width=width,
            dashes=dashes,
            title=f"FOLLOWED_BY  weight={weight:.3f}  source={e['source']}",
            arrows="to",
        )

    # 通常エッジ: 薄いグレー（種別ごとに色分け）
    _edge_colors = {
        "USES": "#888888",
        "USES_TOOL": "#888888",
        "MALWARE_USES": "#9b59b6",
        "EXPLOITS": "#f1c40f",
        "TARGETS": "#e74c3c",
        "HAS_VULN": "#f39c12",
        "CONNECTED_TO": "#3498db",
        "PROTECTED_BY": "#95a5a6",
        "INDICATES": "#1abc9c",
        "INCIDENT_USES": "#e91e63",
    }
    for src, dst, label in standard_edges:
        net.add_edge(
            src,
            dst,
            label=label,
            color=_edge_colors.get(label, "#666666"),
            width=1.2,
            arrows="to",
        )

    return net


def add_legend_html(html_path: Path, present_types: set[str]) -> None:
    """凡例 HTML を挿入する。"""
    node_items = "".join(
        f'<div style="display:flex;align-items:center;margin:3px 0">'
        f'<div style="width:12px;height:12px;border-radius:50%'
        f';background:{style["color"]};margin-right:8px"></div>'
        f"<span>{name}</span></div>"
        for name, style in _NODE_STYLE.items()
        if name in present_types
    )
    legend_html = f"""
<div id="legend" style="
  position:fixed;top:10px;left:10px;
  background:rgba(0,0,0,0.78);
  color:#fff;padding:12px 16px;
  border-radius:8px;font-family:sans-serif;font-size:12px;
  z-index:9999;line-height:1.7;max-height:90vh;overflow-y:auto">
  <b>Node Types</b><br>
  {node_items}
  <hr style="border-color:#555;margin:8px 0">
  <b>FollowedBy</b><br>
  <div style="margin:3px 0">&#9473; 実線 = threat_intel</div>
  <div style="margin:3px 0">&#9476; 破線 = ir_feedback</div>
  <div style="margin:3px 0">幅・色 = weight (低→高: 赤→緑)</div>
  <hr style="border-color:#555;margin:8px 0">
  <b>PIR Cascade</b><br>
  <div style="margin:3px 0">&#11042; 金六角形 = PIR (Strategic)</div>
  <div style="margin:3px 0">&#9476; 金破線 = TAP (PIR→Actor)</div>
  <div style="margin:3px 0">… 金点線 = PTTP (PIR→TTP)</div>
  <div style="margin:3px 0">&#9476; 橙破線 = WeightsAsset (PIR→Asset)</div>
</div>
"""
    content = html_path.read_text()
    content = content.replace("</body>", legend_html + "</body>")
    html_path.write_text(content)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SAGE 統合グラフ可視化 (Attack Graph + Attack Flow)"
    )
    parser.add_argument(
        "--actor-id",
        default=None,
        help="特定アクターに関連するノードのみ表示（省略時は全データ）",
    )
    parser.add_argument(
        "--output",
        default="output/attack_graph.html",
        help="出力HTMLファイルパス（デフォルト: output/attack_graph.html）",
    )
    parser.add_argument("--limit", type=int, default=500, help="テーブルごとの取得上限行数")
    parser.add_argument("--no-open", action="store_true", help="ブラウザを自動で開かない")
    parser.add_argument(
        "--pir-id",
        default=None,
        help="特定 PIR にスコープしたサブグラフのみ表示（PIR と関連 actor/TTP/asset）",
    )
    args = parser.parse_args()

    config = Config.from_env()
    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    pirs, pir_edges, scoped_actors, scoped_ttps, scoped_assets = fetch_pir_data(
        database, args.pir_id
    )
    nodes = fetch_nodes(
        database,
        args.actor_id,
        args.limit,
        scoped_actor_ids=scoped_actors,
        scoped_ttp_ids=scoped_ttps,
        scoped_asset_ids=scoped_assets,
    )
    if not nodes and not pirs:
        logger.error("no_nodes_found", hint="ETL を先に実行してください")
        sys.exit(1)

    node_ids = set(nodes.keys())
    followed_by_edges = fetch_followed_by_edges(database, node_ids, args.limit)
    standard_edges = fetch_standard_edges(database, node_ids, args.limit)

    net = build_network(nodes, followed_by_edges, standard_edges, pirs=pirs, pir_edges=pir_edges)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(output_path))

    present_types = {attrs["node_type"] for attrs in nodes.values()}
    if pirs:
        present_types.add("PIR")
    add_legend_html(output_path, present_types)

    logger.info(
        "combined_graph_written",
        path=str(output_path),
        nodes=len(nodes),
        followed_by=len(followed_by_edges),
        standard_edges=len(standard_edges),
    )

    if not args.no_open:
        webbrowser.open(output_path.resolve().as_uri())


if __name__ == "__main__":
    main()
