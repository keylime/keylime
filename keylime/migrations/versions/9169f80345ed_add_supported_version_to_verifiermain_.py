"""add supported_version to verifiermain table

Revision ID: 9169f80345ed
Revises: a79c27ec1054
Create Date: 2022-01-11 20:54:00.299250

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "9169f80345ed"
down_revision = "a79c27ec1054"
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
    with op.batch_alter_table("verifiermain") as batch_op:
        # Using server_default to assign old rows a valid value
        batch_op.add_column(sa.Column("supported_version", sa.String(length=50), nullable=False, default="1.0"))
        batch_op.alter_column("supported_version", server_default=None)


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "supported_version")
