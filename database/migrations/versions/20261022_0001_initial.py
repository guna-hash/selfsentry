"""Freeze the backend schema at the reviewed audit baseline; no data conversion."""

from alembic import context, op
import sqlalchemy as sa

revision = "20261022_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    if not context.is_offline_mode():
        existing = set(sa.inspect(op.get_bind()).get_table_names()) - {"alembic_version"}
        if existing:
            raise RuntimeError(
                "Initial migration requires an empty database; compare an existing schema "
                "and explicitly stamp only after backup and operator review"
            )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_key", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("container_name", sa.String(length=256), nullable=True),
        sa.Column("image_name", sa.String(length=256), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_key"),
    )
    op.create_table(
        "containers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=False),
        sa.Column("image_name", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("container_id"),
    )
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("falco_alert", sa.JSON(), nullable=True),
        sa.Column("anomaly_features", sa.JSON(), nullable=True),
        sa.Column("ai_summary", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scan_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("image_name", sa.String(length=256), nullable=False),
        sa.Column("critical_count", sa.Integer(), nullable=True),
        sa.Column("high_count", sa.Integer(), nullable=True),
        sa.Column("total_vulnerabilities", sa.Integer(), nullable=True),
        sa.Column("secrets_found", sa.Integer(), nullable=True),
        sa.Column("misconfigurations_found", sa.Integer(), nullable=True),
        sa.Column("raw_json", sa.JSON(), nullable=True),
        sa.Column("scanned_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "confirmed_incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("confirmed_by", sa.String(length=128), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "deployments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("container_name", sa.String(length=256), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("image_name", sa.String(length=256), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("override_reason", sa.String(length=512), nullable=True),
        sa.Column("requested_by", sa.String(length=128), nullable=True),
        sa.Column("scan_result_id", sa.Integer(), nullable=True),
        sa.Column("policy_summary", sa.JSON(), nullable=True),
        sa.Column("policy_violations", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_result_id"],
            ["scan_results.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "monitor_incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_key", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("workflow", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_key"),
        sa.UniqueConstraint("incident_id"),
    )
    op.create_table(
        "generated_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("confirmed_incident_id", sa.Integer(), nullable=True),
        sa.Column("rule_yaml", sa.String(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=True),
        sa.Column("backtested_fp_rate", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["confirmed_incident_id"],
            ["confirmed_incidents.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "rule_performance",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=True),
        sa.Column("true_positives", sa.Integer(), nullable=True),
        sa.Column("false_positives", sa.Integer(), nullable=True),
        sa.Column("last_updated", sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["generated_rules.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    if context.get_x_argument(as_dictionary=True).get("allow_destructive_downgrade") != "true":
        raise RuntimeError("Downgrade drops all application tables; explicit opt-in required")
    op.drop_table("rule_performance")
    op.drop_table("generated_rules")
    op.drop_table("monitor_incidents")
    op.drop_table("deployments")
    op.drop_table("confirmed_incidents")
    op.drop_table("scan_results")
    op.drop_table("incidents")
    op.drop_table("containers")
    op.drop_table("audit_events")
