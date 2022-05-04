"""Add ima_sign_verification_keys column

Revision ID: a09a40352c32
Revises: eeb702f77d7d
Create Date: 2020-11-18 10:37:58.244212

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a7a64155ab3a"
down_revision = "8da20383f6e1"
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
    op.add_column("verifiermain", sa.Column("ima_sign_verification_keys", sa.String(1000)))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "ima_sign_verification_keys")
