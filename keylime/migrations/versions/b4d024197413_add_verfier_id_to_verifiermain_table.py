"""add_verfier_id_to_verifiermain_table

Revision ID: b4d024197413
Revises: eb869a77abd1
Create Date: 2021-05-06 18:06:47.637118

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b4d024197413"
down_revision = "eb869a77abd1"
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
    op.add_column("verifiermain", sa.Column("verifier_id", sa.String(100)))
    op.add_column("verifiermain", sa.Column("verifier_ip", sa.String(20)))
    op.add_column("verifiermain", sa.Column("verifier_port", sa.Integer))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "verifier_id")
    op.drop_column("verifiermain", "verifier_ip")
    op.drop_column("verifiermain", "verifier_port")
