"""add_consecutive_attestation_failures_column

Revision ID: 517a2d6b5cd3
Revises: 460d7adda633
Create Date: 2025-11-09 10:30:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "517a2d6b5cd3"
down_revision = "460d7adda633"
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
    op.add_column("verifiermain", sa.Column("consecutive_attestation_failures", sa.Integer, nullable=True))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "consecutive_attestation_failures")
