-- Migration: 20260522_120000_actor_rationale
-- SAGE 0.10.0 / BEACON 0.15.0 actor_triage integration (plan §7 Phase 6)
-- Paired release: BEACON 0.15.0 + TRACE 1.8.0 + SAGE 0.10.0
--
-- Apply (Cloud Spanner — run each statement separately via gcloud spanner
-- databases ddl update or the Spanner Admin API):

-- 1. Add BEACON actor_triage columns to PirPrioritizesActor.
--    NULL OK — legacy rows that predate BEACON 0.15.0 will have NULL in both
--    new columns; they remain valid and queryable.
ALTER TABLE PirPrioritizesActor ADD COLUMN likelihood FLOAT64;
ALTER TABLE PirPrioritizesActor ADD COLUMN rationale_json STRING(MAX);

-- 2. Create AnnotatesActor edge table.
--    Write path is operator out-of-band (SAGE ETL provides read-side only
--    in 0.10.0). See SAGE HLD §9.3 for the full design.
CREATE TABLE AnnotatesActor (
  annotator_id    STRING(128) NOT NULL,
  actor_stix_id   STRING(128) NOT NULL,
  annotation_type STRING(64),
  payload_json    STRING(MAX),
  created_at      TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  evidence_url    STRING(512),
) PRIMARY KEY (annotator_id, actor_stix_id, created_at);

-- Downgrade (Spanner does not support automatic rollback; apply manually):
-- DROP TABLE AnnotatesActor;
-- ALTER TABLE PirPrioritizesActor DROP COLUMN rationale_json;
-- ALTER TABLE PirPrioritizesActor DROP COLUMN likelihood;
