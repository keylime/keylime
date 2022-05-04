"""receive the aik_tpm from the agent

Revision ID: cc2630851a1f
Revises: a7a64155ab3a
Create Date: 2021-02-08 18:06:26.520283

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "cc2630851a1f"
down_revision = "a7a64155ab3a"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.drop_column("aik")
        batch_op.drop_column("ek")

    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.add_column(sa.Column("aik_tpm", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("ek_tpm", sa.String(length=500), nullable=True))


def downgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.add_column(sa.Column("ek", sa.VARCHAR(length=500), nullable=True))
        batch_op.add_column(sa.Column("aik", sa.VARCHAR(length=500), nullable=True))

    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.drop_column("ek_tpm")
        batch_op.drop_column("aik_tpm")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
