"""add_total_attestation_failures_column

Revision ID: b4928a5f4548
Revises: a59cc9366774
Create Date: 2026-11-28 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b4928a5f4548"
down_revision = "a59cc9366774"
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
    op.add_column("verifiermain", sa.Column("total_attestation_failures", sa.Integer, nullable=True))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "total_attestation_failures")
