"""add mtls_cert and AK to verifier DB

Revision ID: 63c30820fdc1
Revises: 9169f80345ed
Create Date: 2022-01-16 19:33:27.122196

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "63c30820fdc1"
down_revision = "9169f80345ed"
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
    op.add_column("verifiermain", sa.Column("ak_tpm", sa.String(500)))
    op.add_column("verifiermain", sa.Column("mtls_cert", sa.String(2084)))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "ak_tpm")
    op.drop_column("verifiermain", "mtls_cert")
