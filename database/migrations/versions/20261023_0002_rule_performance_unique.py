"""Keep one performance row per rule, matching the Phase 6 database fix."""

from alembic import context, op
import sqlalchemy as sa

revision = "20261023_0002"
down_revision = "20261022_0001"
branch_labels = None
depends_on = None

CONSTRAINT = "uq_rule_performance_rule_id"


def upgrade() -> None:
    if not context.is_offline_mode():
        duplicate = op.get_bind().execute(sa.text(
            "SELECT rule_id FROM rule_performance WHERE rule_id IS NOT NULL "
            "GROUP BY rule_id HAVING COUNT(*) > 1 LIMIT 1"
        )).first()
        if duplicate is not None:
            raise RuntimeError(
                "Duplicate rule performance rows require operator review; no data changed"
            )
    with op.batch_alter_table("rule_performance") as batch:
        batch.create_unique_constraint(CONSTRAINT, ["rule_id"])


def downgrade() -> None:
    with op.batch_alter_table("rule_performance") as batch:
        batch.drop_constraint(CONSTRAINT, type_="unique")
