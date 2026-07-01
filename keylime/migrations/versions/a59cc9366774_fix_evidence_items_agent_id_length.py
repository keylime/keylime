"""Fix evidence_items.agent_id column length for PostgreSQL, MySQL and MariaDB

Revision ID: a59cc9366774
Revises: 5a8b2c3d4e6f
Create Date: 2026-06-29 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a59cc9366774"
down_revision = "5a8b2c3d4e6f"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    pass


def downgrade_registrar():
    pass


def upgrade_cloud_verifier():
    bind = op.get_bind()
    if bind.dialect.name == "mysql":
        # MySQL and MariaDB both block ALTER COLUMN on FK-referenced columns
        # (error 1832), and batch recreate fails too because FK names must be
        # unique database-wide (error 121). The portable fix is to drop the FK,
        # widen the column, then restore the FK. The FK name is looked up from
        # information_schema rather than hardcoded.
        result = bind.execute(
            sa.text(
                "SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE"
                " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'evidence_items'"
                " AND COLUMN_NAME = 'agent_id' AND REFERENCED_TABLE_NAME IS NOT NULL"
                " LIMIT 1"
            )
        )
        fk_name = result.scalar()
        if fk_name:
            bind.execute(sa.text(f"ALTER TABLE evidence_items DROP FOREIGN KEY `{fk_name}`"))
        bind.execute(sa.text("ALTER TABLE evidence_items MODIFY agent_id VARCHAR(80) NOT NULL"))
        if fk_name:
            bind.execute(
                sa.text(
                    f"ALTER TABLE evidence_items ADD CONSTRAINT `{fk_name}`"
                    " FOREIGN KEY (agent_id, attestation_index)"
                    " REFERENCES attestations (agent_id, `index`)"
                )
            )
    else:
        with op.batch_alter_table("evidence_items") as batch_op:
            batch_op.alter_column(
                "agent_id", existing_type=sa.String(length=20), type_=sa.String(length=80), existing_nullable=False
            )


def downgrade_cloud_verifier():
    pass
