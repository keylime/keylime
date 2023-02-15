"""add last_successful_attestation

Revision ID: f838d3cdeead
Revises: 8c0f8ded1f90
Create Date: 2023-02-15 10:51:25.948918

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f838d3cdeead"
down_revision = "8c0f8ded1f90"
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
    op.add_column("verifiermain", sa.Column("last_successful_attestation", sa.Integer(), nullable=True))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "last_successful_attestation")
