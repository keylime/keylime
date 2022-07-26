"""add_attestation_count_column

Revision ID: bf48e0c4751d
Revises: bc3b6b551b0a
Create Date: 2022-07-12 12:00:55.599169

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "bf48e0c4751d"
down_revision = "bc3b6b551b0a"
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
    op.add_column("verifiermain", sa.Column("attestation_count", sa.Integer))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "attestation_count")
