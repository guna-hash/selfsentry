-- schema.sql
-- ------------
-- PostgreSQL schema draft for ContainerGuard AI.
-- STATUS: DRAFT — not yet executed against a real database (Phase 8).
-- Refine column types/constraints once backend-api/models/db_models.py
-- (SQLAlchemy) is actually implemented in Phase 8.

-- Phase 1/2 support
CREATE TABLE IF NOT EXISTS containers (
    id              SERIAL PRIMARY KEY,
    container_id    VARCHAR(128) UNIQUE NOT NULL,
    image_name      VARCHAR(256) NOT NULL,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_results (
    id                      SERIAL PRIMARY KEY,
    image_name              VARCHAR(256) NOT NULL,
    critical_count           INTEGER DEFAULT 0,
    high_count                INTEGER DEFAULT 0,
    total_vulnerabilities      INTEGER DEFAULT 0,
    secrets_found               INTEGER DEFAULT 0,
    misconfigurations_found      INTEGER DEFAULT 0,
    raw_json                      JSONB,
    scanned_at                     TIMESTAMP DEFAULT NOW()
);

-- Phase 5 support
CREATE TABLE IF NOT EXISTS incidents (
    id              SERIAL PRIMARY KEY,
    container_id    VARCHAR(128) REFERENCES containers(container_id),
    risk_score      FLOAT NOT NULL,
    confidence      VARCHAR(16),  -- low / medium / high
    falco_alert     JSONB,
    anomaly_features JSONB,
    ai_summary      JSONB,        -- Phase 7 output, advisory only
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Phase 6 support (core novelty - Rule Synthesis Engine)
CREATE TABLE IF NOT EXISTS confirmed_incidents (
    id              SERIAL PRIMARY KEY,
    incident_id     INTEGER REFERENCES incidents(id),
    confirmed_by    VARCHAR(128) NOT NULL,
    confirmed_at    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS generated_rules (
    id                  SERIAL PRIMARY KEY,
    confirmed_incident_id INTEGER REFERENCES confirmed_incidents(id),
    rule_yaml            TEXT NOT NULL,
    status                VARCHAR(32) DEFAULT 'pending_review', -- pending_review / approved / rejected / deployed / retired
    backtested_fp_rate     FLOAT,
    created_at              TIMESTAMP DEFAULT NOW(),
    reviewed_by              VARCHAR(128),
    reviewed_at               TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rule_performance (
    id              SERIAL PRIMARY KEY,
    rule_id         INTEGER REFERENCES generated_rules(id),
    true_positives  INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    last_updated    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS deployments (
    id                SERIAL PRIMARY KEY,
    container_name    VARCHAR(256) NOT NULL,
    container_id      VARCHAR(128),
    image_name        VARCHAR(256) NOT NULL,
    decision          VARCHAR(16) NOT NULL,  -- allowed / blocked / overridden
    override_reason   VARCHAR(512),
    requested_by      VARCHAR(128),
    scan_result_id    INTEGER REFERENCES scan_results(id),
    policy_summary    JSON,
    policy_violations JSON,
    created_at        TIMESTAMP DEFAULT NOW()
);
