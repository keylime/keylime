"""add_tpm_clockinfo

Revision ID: 4089e1c79be9
Revises: 4329e2d14944
Create Date: 2022-08-08 16:29:41.784890

"""
import sqlalchemy as sa
from alembic import op

import keylime

# revision identifiers, used by Alembic.
revision = "4089e1c79be9"
down_revision = "4329e2d14944"
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
    op.add_column("verifiermain", sa.Column("tpm_clockinfo", keylime.db.verifier_db.JSONPickleType(), nullable=True))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "tpm_clockinfo")
