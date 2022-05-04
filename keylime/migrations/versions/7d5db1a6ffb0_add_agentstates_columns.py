"""Add agentstates columns

Revision ID: 7d5db1a6ffb0
Revises: f82c4252bc4f
Create Date: 2021-07-16 10:31:26.693430

"""
import sqlalchemy as sa
from alembic import op

import keylime

# revision identifiers, used by Alembic.
revision = "7d5db1a6ffb0"
down_revision = "f82c4252bc4f"
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
    op.add_column("verifiermain", sa.Column("boottime", sa.Integer(), nullable=True))
    op.add_column("verifiermain", sa.Column("ima_pcrs", keylime.db.verifier_db.JSONPickleType(), nullable=True))
    op.add_column("verifiermain", sa.Column("pcr10", sa.LargeBinary(), nullable=True))
    op.add_column("verifiermain", sa.Column("next_ima_ml_entry", sa.Integer(), nullable=True))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "boottime")
    op.drop_column("verifiermain", "ima_pcrs")
    op.drop_column("verifiermain", "pcr10")
    op.drop_column("verifiermain", "next_ima_ml_entry")
