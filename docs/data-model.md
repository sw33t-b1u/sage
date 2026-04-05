# SAGE — Data Model

## Graph overview

The Spanner Graph (`ThreatIntelGraph`) contains two co-existing sub-graphs:

- **Attack Flow** — TTP time-series transitions derived from STIX threat intel
- **Attack Graph** — Internal asset connectivity and vulnerability exposure

Cross-domain join: `Targets` edge links ThreatActor → Asset.

---

## Nodes

| Node | Description |
|------|-------------|
| `ThreatActor` | Threat actor groups and individuals (STIX identity, tags for PIR matching) |
| `TTP` | ATT&CK techniques/sub-techniques with detection difficulty level |
| `Vulnerability` | CVEs with CVSS score, EPSS score, and affected platforms |
| `MalwareTool` | Malware families and attacker tools |
| `Asset` | Internal assets (server, endpoint, SaaS, storage, network device) with PIR-adjusted criticality. Network segment info (name, CIDR, zone) stored as properties. |
| `SecurityControl` | Defensive controls: EDR, WAF, SIEM, firewall, IAM |
| `Observable` | IoCs — IPs, domains, hashes, emails, URLs with TLP and confidence |
| `Incident` | IR incidents including diamond model and kill chain phases |

## Edges

| Edge | Source → Destination | Description |
|------|----------------------|-------------|
| `Uses` | ThreatActor → TTP | Actor uses a technique |
| `MalwareUsesTTP` | MalwareTool → TTP | Malware/tool uses a technique |
| `UsesTool` | ThreatActor → MalwareTool | Actor uses a malware or tool |
| `Exploits` | TTP → Vulnerability | Technique exploits a CVE |
| `FollowedBy` | TTP → TTP | TTP time-series transition with probability weight |
| `IncidentUsesTTP` | Incident → TTP | IR incident observed using a technique |
| `Targets` | ThreatActor → Asset | Actor targets an internal asset (auto-generated via PIR tag matching) |
| `HasVulnerability` | Asset → Vulnerability | Asset has an unpatched CVE |
| `ConnectedTo` | Asset ↔ Asset | Network reachability between assets |
| `ProtectedBy` | Asset → SecurityControl | Asset is covered by a control |
| `IndicatesTTP` | Observable → TTP | IoC is attributed to a TTP |
| `IndicatesActor` | Observable → ThreatActor | IoC is attributed to a threat actor |

---

## PIR-based asset weighting

Priority Intelligence Requirements (PIRs) drive dynamic asset criticality adjustments at ETL time.

> **Generating PIRs:** Use [BEACON](https://github.com/sw33t-b1u/beacon) to automatically generate PIR JSON from your organization's business context. BEACON produces SAGE-compatible `pir_output.json` ready to place at `PIR_FILE_PATH`.

### PIR JSON format

```json
{
  "pir_id": "PIR-2026-001",
  "description": "Supply chain attack via vendor systems",
  "threat_actor_tags": ["supply-chain", "apt-naver-linked"],
  "asset_weight_rules": [
    { "tag": "authentication",    "criticality_multiplier": 3.0 },
    { "tag": "shared-infra",      "criticality_multiplier": 2.5 }
  ],
  "valid_from": "2026-01-01",
  "valid_until": "2026-12-31"
}
```

### Criticality formula

```
pir_adjusted_criticality =
  base_criticality
  × MAX(matching asset_weight_rules[].criticality_multiplier)
  × 1.5  (if a Targets edge exists: actor.tags ∩ PIR.threat_actor_tags ≠ ∅)
  capped at 10.0
```

---

## FollowedBy weight calculation

`FollowedBy.weight` represents the transition probability between two TTPs:

```
weight(src_ttp → dst_ttp) =
  base_prob       ×   -- transition frequency in ATT&CK kill chain
  activity_score  ×   -- OpenCTI observation count in last N days (0.0–2.0)
  exploit_ease    ×   -- CVSSv3 Exploitability + EPSS (where applicable)
  ir_multiplier       -- adjustment from internal IR incident records
```

Weights from `ir_feedback` and `manual_analysis` sources are stored as separate records and can be queried or aggregated independently.

---

## ETL schedule

| Trigger | Scope | Latency target |
|---------|-------|----------------|
| Cloud Scheduler (daily 03:00 JST) | Full weight recalculation | Within 2 hours |
| Manual (`run_etl.py`) | Incremental update for added data | Within 5 minutes |
| IR Feedback | Incident + IncidentUsesTTP + FollowedBy ir_feedback | Within 30 minutes |
