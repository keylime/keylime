"""Add IDevID and IAK

Revision ID: 21b5cb88fcdb
Revises: 039322ea079b
Create Date: 2023-02-15 15:07:53.049485

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "21b5cb88fcdb"
down_revision = "f838d3cdeead"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.add_column(sa.Column("iak_tpm", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("idevid_tpm", sa.String(length=500), nullable=True))


def downgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.drop_column("iak_tpm")
        batch_op.drop_column("idevid_tpm")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
