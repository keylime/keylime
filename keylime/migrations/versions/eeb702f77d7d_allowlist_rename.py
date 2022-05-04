"""allowlist rename

Revision ID: eeb702f77d7d
Revises: 8a44a4364f5a
Create Date: 2020-10-15 13:29:38.853574

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "eeb702f77d7d"
down_revision = "8a44a4364f5a"
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
    # need to use batch_alter_table since SQLite <3.25.0 doesn't do RENAME COLUMN
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "ima_whitelist", new_column_name="allowlist", existing_type=sa.Text(), existing_nullable=True
        )


def downgrade_cloud_verifier():
    # need to use batch_alter_table since SQLite <3.25.0 doesn't do RENAME COLUMN
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "allowlist", new_column_name="ima_whitelist", existing_type=sa.Text(), existing_nullable=True
        )
