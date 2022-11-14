"""add_checksum_and_generator_to_allowlist

Revision ID: 2fbc0fb8fa4d
Revises: a09cc94177f0
Create Date: 2022-11-14 13:21:47.555834

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "2fbc0fb8fa4d"
down_revision = "a09cc94177f0"
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
    op.add_column("allowlists", sa.Column("checksum", sa.String(128), index=True))


def downgrade_cloud_verifier():
    op.drop_column("allowlists", "checksum")
