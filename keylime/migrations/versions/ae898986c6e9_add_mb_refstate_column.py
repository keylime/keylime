"""add_mb_refstate_column

Revision ID: ae898986c6e9
Revises: cc2630851a1f
Create Date: 2021-03-03 11:49:00.860132

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "ae898986c6e9"
down_revision = "cc2630851a1f"
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
    op.add_column("verifiermain", sa.Column("mb_refstate", sa.String(1000)))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "mb_refstate")
