# SAGE — Local Testing

## Unit tests (no GCP required)

```sh
make test
```

Uses fixture files under `tests/fixtures/`. No GCP credentials or network access needed.

For coverage report:
```sh
uv run pytest --cov=src/sage --cov-report=term-missing
```

---

## Full local test with Spanner emulator

Covers the complete workflow: Attack Flow (STIX threat intel) + Attack Graph (internal assets).

**Requires Docker or Podman.**

```sh
# 1. Start the Spanner emulator
docker run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# 2. Create instance, database, and schema
uv run python cmd/setup_emulator.py
make init-schema

# 3. Load threat intelligence (Attack Flow)
# NOTE: external or hand-authored bundles must be enriched first so PIR filtering retains actors:
#   cd ../TRACE && uv run python cmd/enrich_bundle.py --input <bundle.json> --output enriched.json && cd ../SAGE
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_mirrorface.json
uv run python cmd/run_etl.py --manual-bundle tests/fixtures/sample_bundle_inc.json

# 4. Load internal assets (Attack Graph)
make load-assets

# 5. Visualize — generates tests/output/graph.html and opens in browser
make visualize

# 6. Stop and remove the emulator when done
docker stop spanner-emulator && docker rm spanner-emulator
```

### Using Podman instead of Docker

Podman is a drop-in replacement — every `docker` subcommand above works identically with `podman`. No flags or image name changes.

On macOS, Podman requires a VM (one-time setup):

```sh
podman machine init
podman machine start
```

Then substitute `podman` for `docker` in steps 1 and 6:

```sh
# Step 1
podman run -d --name spanner-emulator -p 9010:9010 -p 9020:9020 \
  gcr.io/cloud-spanner-emulator/emulator
export SPANNER_EMULATOR_HOST=localhost:9010

# Step 6
podman stop spanner-emulator && podman rm spanner-emulator
```

Steps 2–5 (uv and `make` commands) are unchanged.

---

## Graph visualization

`make visualize` generates `tests/output/graph.html` (git-ignored) and opens it in your browser. Nodes are color-coded by type, draggable, and zoomable.

| Node type | Color | Connects to |
|-----------|-------|-------------|
| ThreatActor | Red | TTP (USES), MalwareTool (USES_TOOL), Asset (TARGETS) |
| TTP | Orange | Vulnerability (EXPLOITS), TTP (FOLLOWED_BY) |
| Vulnerability | Yellow | — |
| MalwareTool | Purple | TTP (MALWARE_USES_TTP) |
| Observable | Teal | TTP (INDICATES_TTP), ThreatActor (INDICATES_ACTOR) |
| Incident | Pink | TTP (INCIDENT_USES_TTP) |
| Asset | Blue | Vulnerability (HAS_VULN), Asset (CONNECTED_TO), SecurityControl (PROTECTED_BY) |
| SecurityControl | Gray | — |

Options:
```sh
uv run python cmd/visualize_combined.py --no-open   # combined view, suppress auto-open
uv run python cmd/visualize_combined.py --limit 200 # cap rows per table
uv run python cmd/visualize_graph.py --no-open      # attack graph only
uv run python cmd/visualize_attack_flow.py --no-open # attack flow only
```

---

## Sample fixtures

| File | Description |
|------|-------------|
| `sample_bundle_mirrorface.json` | MirrorFace / Earth Kasha APT (targets Japan, 2024–2025). TTPs: T1190, T1566.001, T1574.002, T1071.001, T1083, T1041. CVE-2023-28461, CVE-2024-21412. LODEINFO backdoor + C2 IoCs. |
| `sample_bundle_inc.json` | INC Ransomware (active 2023–, targets healthcare/manufacturing). TTPs: T1190, T1078, T1003.001, T1021.002, T1048.002, T1486. CVE-2023-3519, CVE-2023-4966 (Citrix). Tools: Cobalt Strike, AnyDesk, MegaSync. |
| `sample_assets.json` | Japanese manufacturing enterprise: Citrix NetScaler ADC, Active Directory, File Server, Backup Server, ERP (SAP), Factory PLC, Workstations. |
| `sample_pir.json` | Minimal PIR for unit tests. |
