"""Spanner グラフデータをpyvisでインタラクティブHTMLとして可視化するスクリプト。

各ノードテーブルとエッジテーブルを直接クエリしてグラフを構築する。
出力ファイルをブラウザで自動的に開く。

使用方法:
    export SPANNER_EMULATOR_HOST=localhost:9010  # エミュレーター使用時
    uv run python cmd/visualize_graph.py
    uv run python cmd/visualize_graph.py --output /tmp/graph.html
    uv run python cmd/visualize_graph.py --limit 200
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

# ノード種別ごとの色定義
_NODE_COLORS: dict[str, str] = {
    "ThreatActor": "#e74c3c",  # 赤
    "TTP": "#e67e22",  # オレンジ
    "Vulnerability": "#f1c40f",  # 黄
    "MalwareTool": "#9b59b6",  # 紫
    "Observable": "#1abc9c",  # ターコイズ
    "Incident": "#e91e63",  # ピンク
    "Asset": "#3498db",  # 青
    "SecurityControl": "#95a5a6",  # グレー
    "PIR": "#f5b301",  # 金
}

# エッジテーブル定義: (テーブル名, ソースキー列, 宛先キー列, ラベル)
_EDGE_TABLES = [
    ("Uses", "actor_stix_id", "ttp_stix_id", "USES"),
    ("UsesTool", "actor_stix_id", "tool_stix_id", "USES_TOOL"),
    ("Exploits", "ttp_stix_id", "vuln_stix_id", "EXPLOITS"),
    ("FollowedBy", "src_ttp_stix_id", "dst_ttp_stix_id", "FOLLOWED_BY"),
    ("Targets", "actor_stix_id", "asset_id", "TARGETS"),
    ("TargetsAsset", "ttp_stix_id", "asset_id", "TARGETS_ASSET"),
    ("HasVulnerability", "asset_id", "vuln_stix_id", "HAS_VULN"),
    ("ConnectedTo", "src_asset_id", "dst_asset_id", "CONNECTED_TO"),
    ("ProtectedBy", "asset_id", "control_id", "PROTECTED_BY"),
    ("IndicatesTTP", "observable_stix_id", "ttp_stix_id", "INDICATES"),
    ("IndicatesActor", "observable_stix_id", "actor_stix_id", "INDICATES"),
    ("IncidentUsesTTP", "incident_stix_id", "ttp_stix_id", "INCIDENT_USES"),
]

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


def fetch_nodes(
    database: spanner.Database,
    limit: int,
) -> dict[str, dict]:
    """全ノードテーブルを読み込み {node_id: {label, title, color}} を返す。"""
    nodes: dict[str, dict] = {}

    for table, id_col, name_col in _NODE_TABLES:
        # name_col が stix_id と同じ場合（Vulnerability の cve_id は NULL の可能性あり）は fallback
        sql = (
            f"SELECT {id_col}, {name_col} FROM {table} LIMIT {limit}"
            if name_col != id_col
            else f"SELECT {id_col}, {id_col} FROM {table} LIMIT {limit}"
        )
        with database.snapshot() as snap:
            rows = snap.execute_sql(sql)
            for row in rows:
                node_id, display = row[0], row[1]
                if node_id is None:
                    continue
                label = str(display or node_id)[:40]  # 長すぎるラベルを切り詰め
                nodes[node_id] = {
                    "label": label,
                    "title": f"[{table}] {label}",
                    "color": _NODE_COLORS[table],
                    "node_type": table,
                }

    logger.info("nodes_fetched", count=len(nodes))
    return nodes


def fetch_edges(
    database: spanner.Database,
    node_ids: set[str],
    limit: int,
) -> list[tuple[str, str, str]]:
    """全エッジテーブルを読み込み [(src_id, dst_id, label)] を返す。"""
    edges: list[tuple[str, str, str]] = []

    for table, src_col, dst_col, edge_label in _EDGE_TABLES:
        sql = f"SELECT {src_col}, {dst_col} FROM {table} LIMIT {limit}"
        with database.snapshot() as snap:
            try:
                rows = snap.execute_sql(sql)
                for row in rows:
                    src, dst = row[0], row[1]
                    # 両端ノードが存在する場合のみ追加
                    if src in node_ids and dst in node_ids:
                        edges.append((src, dst, edge_label))
            except Exception as exc:
                logger.warning("edge_table_skip", table=table, error=str(exc))

    logger.info("edges_fetched", count=len(edges))
    return edges


def build_network(
    nodes: dict[str, dict],
    edges: list[tuple[str, str, str]],
    pirs: list[dict] | None = None,
    pir_edges: dict[str, list[dict]] | None = None,
) -> Network:
    """pyvis Network オブジェクトを構築して返す。"""
    net = Network(
        height="900px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#ffffff",
        directed=True,
    )
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=150)

    for node_id, attrs in nodes.items():
        net.add_node(
            node_id,
            label=attrs["label"],
            title=attrs["title"],
            color=attrs["color"],
            size=20,
        )

    for src, dst, label in edges:
        net.add_edge(src, dst, label=label, color="#aaaaaa", arrows="to")

    for pir in pirs or []:
        decision = pir.get("decision_point") or pir["pir_id"]
        net.add_node(
            pir["pir_id"],
            label=str(decision)[:40],
            title=f"[PIR] {pir['pir_id']}\n{decision}",
            color=_NODE_COLORS["PIR"],
            size=28,
            shape="hexagon",
        )

    pir_edges = pir_edges or {}
    known = set(nodes.keys()) | {p["pir_id"] for p in (pirs or [])}
    for e in pir_edges.get("PirPrioritizesActor", []):
        if e["pir_id"] in known and e["actor_stix_id"] in known:
            net.add_edge(
                e["pir_id"],
                e["actor_stix_id"],
                label="TAP",
                color="#f5b301",
                dashes=True,
                arrows="to",
            )
    for e in pir_edges.get("PirPrioritizesTTP", []):
        if e["pir_id"] in known and e["ttp_stix_id"] in known:
            net.add_edge(
                e["pir_id"],
                e["ttp_stix_id"],
                label="PTTP",
                color="#d4a017",
                dashes=[2, 6],
                arrows="to",
            )
    for e in pir_edges.get("PirWeightsAsset", []):
        if e["pir_id"] in known and e["asset_id"] in known:
            net.add_edge(
                e["pir_id"],
                e["asset_id"],
                label=f"×{e.get('criticality_multiplier')}",
                color="#e09f00",
                dashes=True,
                arrows="to",
            )

    return net


def add_legend_html(html_path: Path, nodes: dict[str, dict]) -> None:
    """出力HTMLにノード種別の凡例を追加する。"""
    # 実際に存在するノード種別のみ凡例に表示
    present_types = {attrs["node_type"] for attrs in nodes.values()}
    legend_items = "".join(
        f'<div style="display:flex;align-items:center;margin:4px 0">'
        f'<div style="width:14px;height:14px;border-radius:50%'
        f';background:{color};margin-right:8px"></div>'
        f"<span>{label}</span></div>"
        for label, color in _NODE_COLORS.items()
        if label in present_types
    )
    legend_html = f"""
<div id="legend" style="
  position:fixed;top:10px;left:10px;
  background:rgba(0,0,0,0.75);
  color:#fff;padding:12px 16px;
  border-radius:8px;font-family:sans-serif;font-size:13px;
  z-index:9999">
  <b>Node Types</b><br><br>
  {legend_items}
</div>
"""
    content = html_path.read_text()
    content = content.replace("</body>", legend_html + "</body>")
    html_path.write_text(content)


def main() -> None:
    parser = argparse.ArgumentParser(description="SAGE グラフ可視化")
    parser.add_argument("--output", default="tests/output/graph.html", help="出力HTMLファイルパス")
    parser.add_argument("--limit", type=int, default=500, help="テーブルごとの取得上限行数")
    parser.add_argument("--no-open", action="store_true", help="ブラウザを自動で開かない")
    parser.add_argument("--pir-id", default=None, help="特定 PIR にスコープしたサブグラフのみ表示")
    args = parser.parse_args()

    config = Config.from_env()
    spanner_client = spanner.Client(project=config.gcp_project_id)
    instance = spanner_client.instance(config.spanner_instance_id)
    database = instance.database(config.spanner_database_id)

    try:
        pirs = load_pirs(database)
        pir_edges = load_pir_edges(database)
    except Exception as exc:
        logger.warning("pir_load_skip", error=str(exc))
        pirs, pir_edges = (
            [],
            {
                "PirPrioritizesActor": [],
                "PirPrioritizesTTP": [],
                "PirWeightsAsset": [],
            },
        )

    if args.pir_id:
        pirs = [p for p in pirs if p["pir_id"] == args.pir_id]
        pir_edges = {k: [e for e in v if e["pir_id"] == args.pir_id] for k, v in pir_edges.items()}
        scoped_actors = {e["actor_stix_id"] for e in pir_edges["PirPrioritizesActor"]}
        scoped_ttps = {e["ttp_stix_id"] for e in pir_edges["PirPrioritizesTTP"]}
        scoped_assets = {e["asset_id"] for e in pir_edges["PirWeightsAsset"]}
    else:
        scoped_actors = scoped_ttps = scoped_assets = set()

    nodes = fetch_nodes(database, args.limit)
    if not nodes and not pirs:
        logger.error("no_nodes_found", message="データが存在しません。ETLを先に実行してください。")
        sys.exit(1)

    if scoped_actors or scoped_ttps or scoped_assets:
        nodes = {
            nid: a
            for nid, a in nodes.items()
            if (a["node_type"] == "ThreatActor" and nid in scoped_actors)
            or (a["node_type"] == "TTP" and nid in scoped_ttps)
            or (a["node_type"] == "Asset" and nid in scoped_assets)
            or a["node_type"] not in {"ThreatActor", "TTP", "Asset"}
        }

    edges = fetch_edges(database, set(nodes.keys()), args.limit)

    net = build_network(nodes, edges, pirs=pirs, pir_edges=pir_edges)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.write_html(str(output_path))
    if pirs:
        nodes_for_legend = {**nodes, "__pir__": {"node_type": "PIR"}}
    else:
        nodes_for_legend = nodes
    add_legend_html(output_path, nodes_for_legend)

    logger.info(
        "graph_written",
        path=str(output_path),
        nodes=len(nodes),
        edges=len(edges),
    )

    if not args.no_open:
        webbrowser.open(output_path.resolve().as_uri())


if __name__ == "__main__":
    main()
