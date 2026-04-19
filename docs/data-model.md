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
| `PIR` | Priority Intelligence Requirement — one decision point per node (Strategic layer of the intel cascade) |

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
| `PirPrioritizesActor` | PIR → ThreatActor | TAP — actor matches a PIR's `threat_actor_tags` (carries `overlap_ratio`) |
| `PirPrioritizesTTP` | PIR → TTP | PTTP — derived transitively via `Uses` from prioritized actors |
| `PirWeightsAsset` | PIR → Asset | Asset matches a PIR's `asset_weight_rules` (carries `matched_tag` + max `criticality_multiplier`) |

PIR cascade edges are built at ETL time from the loaded PIR JSON together
with the actor / asset / `Uses` rows. They materialize the
Strategic (PIR) → Operational (TAP) → Tactical (PTTP) cascade so analysts
can scope a subgraph to a single PIR.

---

## PIR-based asset weighting

Priority Intelligence Requirements (PIRs) drive dynamic asset criticality adjustments at ETL time.

> **Generating PIRs:** Use [BEACON](https://github.com/sw33t-b1u/beacon) to automatically generate PIR JSON from your organization's business context. BEACON produces SAGE-compatible `pir_output.json` ready to place at `PIR_FILE_PATH`.

### PIR JSON format

BEACON generates the following structure. SAGE processes the fields marked **[used by SAGE]**; remaining fields are metadata stored as-is.

```json
{
  "pir_id": "PIR-2026-001",
  "intelligence_level": "strategic",
  "description": "Strengthen defenses against nation-state actors targeting PLM systems",
  "rationale": "Likelihood=5, Impact=5 — state_sponsored.China / OT connectivity risk",
  "threat_actor_tags": ["apt-china", "espionage"],
  "asset_weight_rules": [
    { "tag": "plm",  "criticality_multiplier": 2.5 },
    { "tag": "ot",   "criticality_multiplier": 2.0 }
  ],
  "collection_focus": [
    "Monitor new TTPs and infrastructure changes: MirrorFace / Salt Typhoon",
    "Vulnerability exploitation targeting OT/ICS environments"
  ],
  "valid_from": "2026-04-11",
  "valid_until": "2027-04-11",
  "risk_score": { "likelihood": 5, "impact": 5, "composite": 25 }
}
```

Fields used by SAGE ETL: `pir_id`, `threat_actor_tags`, `asset_weight_rules`, `valid_from`, `valid_until`.
Remaining fields (`intelligence_level`, `description`, `rationale`, `collection_focus`, `risk_score`) are BEACON metadata passed through without modification.

### Available threat_actor_tags

The vocabulary is derived from MITRE ATT&CK + MISP Galaxy `threat-actor` cluster and is the exhaustive set BEACON currently emits. Exact contents evolve with upstream feeds; regenerate `BEACON/schema/threat_taxonomy.json` to refresh.

| Category | Tags |
|----------|------|
| Nation-state | `apt-<country-slug>` — one per MISP `cfr-suspected-state-sponsor` bucket (e.g., `apt-china`, `apt-russia`, `apt-north-korea`, `apt-iran`, `apt-india`, `apt-south-korea`, `apt-vietnam`, `apt-united-states`, `apt-israel`, `apt-pakistan`, `apt-lebanon`, `apt-france`, `apt-spain`, `apt-belarus`, `apt-palestine`, `apt-united-arab-emirates`) |
| Non-state motivation | `espionage`, `financial-crime`, `sabotage`, `subversion` — from MISP `cfr-type-of-incident` |
| Crime | `cybercriminal` |

**Removed in BEACON 0.8 (Phase 7)**: `ip-theft`, `financially-motivated`, `destructive`, `hacktivism`, `bec`, `fraud`, `double-extortion`, `insider-threat`, `ot-targeting`, `critical-infrastructure`, `cloud-targeting`, `supply-chain-attack`, `phi-targeting`, `erp-targeting`, `msp-targeting`, `software-supply-chain`, `source-code-theft`, `research-theft`, `targets-*`, `ransomware`, `raas`, `initial-access-broker`. SAGE's PIR filter is tag-vocabulary-agnostic (pure set intersection), so older PIRs containing these tags still load, but no new PIRs will produce them.

### Available asset_weight_rules tags

| Tag | Typical multiplier | Asset type |
|-----|--------------------|-----------|
| `plm` | 2.5 | PLM / product lifecycle |
| `ot` | 2.0 | OT / ICS / SCADA |
| `erp` | 2.0 | ERP systems |
| `authentication` | 2.5 | IAM / SSO / directory services |
| `domain_controller` | 2.5 | Active Directory / LDAP |
| `cloud` | 1.5 | Cloud infrastructure |
| `devops_cicd` | 2.0 | DevOps / CI-CD toolchain |
| `siem` | 2.0 | SIEM / security monitoring |
| `pki` | 2.0 | PKI / certificate authority |
| `database` | 1.8 | Database servers |
| `email_gateway` | 1.5 | Email gateway / MTA |
| `vpn_remote_access` | 1.5 | VPN / remote access |
| `firewall_ngfw` | 1.5 | Firewall / NGFW |
| `api_gateway` | 1.5 | API gateway |
| `file_server` | 1.3 | File servers |
| `external-facing` | 1.5 | DMZ / internet-exposed assets |

Full tag definitions and multipliers: `BEACON/schema/asset_tags.json`

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
