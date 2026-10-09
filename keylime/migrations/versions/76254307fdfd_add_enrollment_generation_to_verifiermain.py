"""add enrollment_generation to verifiermain

Revision ID: 76254307fdfd
Revises: a59cc9366774
Create Date: 2026-10-06 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "76254307fdfd"
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
    op.add_column("verifiermain", sa.Column("enrollment_generation", sa.Integer(), nullable=False, server_default="0"))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "enrollment_generation")
