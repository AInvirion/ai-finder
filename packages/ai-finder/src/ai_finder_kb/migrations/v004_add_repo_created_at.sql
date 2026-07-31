-- Migration v4: HF repo registration date on models, for the oldest-candidate
-- pick on multi-model file hashes.
--
-- A file hash claimed by several models cannot be resolved by content alone
-- (a base model and its quantization legitimately share untouched shards).
-- The seed path's policy is to assert the EARLIEST-REGISTERED repo — the
-- presumed original that was later forked or re-uploaded — and disclose the
-- alternates; exact identification through transformation is the
-- fingerprinting surface, not this one.
--
-- Named repo_created_at, NOT created_at: models.created_at already exists as
-- the row-insertion audit stamp, and reusing the name would silently compare
-- registration dates against insertion times. Values are the seed's canonical
-- whole-second UTC form ('YYYY-MM-DDTHH:MM:SSZ') or NULL; the exporter
-- enforces that shape so lexicographic ORDER BY is chronological ORDER BY.

ALTER TABLE models ADD COLUMN repo_created_at TEXT;

-- Update schema version. OR IGNORE to match schema.sql's stamp of the same
-- row. The ALTER above is single-shot (SQLite has no IF NOT EXISTS for
-- columns) — like v002's ALTERs, it relies on the version-gated runner in
-- Database._run_migrations applying each migration exactly once.
INSERT OR IGNORE INTO schema_version (version) VALUES (4);
