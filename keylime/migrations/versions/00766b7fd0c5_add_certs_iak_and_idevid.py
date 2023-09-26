"""Add IAK and IDevID certificates

Revision ID: 00766b7fd0c5
Revises: 21b5cb88fcdb
Create Date: 2023-09-27 16:39:53.308687

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "00766b7fd0c5"
down_revision = "21b5cb88fcdb"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.add_column(sa.Column("iak_cert", sa.String(length=2048), nullable=True))
        batch_op.add_column(sa.Column("idevid_cert", sa.String(length=2048), nullable=True))


def downgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.drop_column("iak_cert")
        batch_op.drop_column("idevid_cert")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
