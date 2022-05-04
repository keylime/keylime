"""Add ip and port to registrar

Revision ID: f82c4252bc4f
Revises: b4d024197413
Create Date: 2021-06-25 14:38:05.498971

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f82c4252bc4f"
down_revision = "b4d024197413"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.add_column(sa.Column("ip", sa.String(length=15), nullable=True))
        batch_op.add_column(sa.Column("port", sa.Integer(), nullable=True))


def downgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.drop_column("ip")
        batch_op.drop_column("port")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
