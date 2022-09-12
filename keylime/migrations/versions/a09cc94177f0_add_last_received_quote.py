"""add_last_received_quote

Revision ID: a09cc94177f0
Revises: 4089e1c79be9
Create Date: 2022-08-30 12:16:37.506940

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a09cc94177f0"
down_revision = "4089e1c79be9"
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
    op.add_column("verifiermain", sa.Column("last_received_quote", sa.Integer(), nullable=True))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "last_received_quote")
