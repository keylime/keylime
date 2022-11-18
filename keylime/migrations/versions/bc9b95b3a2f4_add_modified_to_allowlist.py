"""empty message

Revision ID: bc9b95b3a2f4
Revises: 039322ea079b
Create Date: 2022-11-23 08:37:37.600030

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "bc9b95b3a2f4"
down_revision = "039322ea079b"
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
    op.add_column(
        "allowlists",
        sa.Column("modified", sa.TIMESTAMP, nullable=False, server_default="2000-01-01 00:00:00"),
    )


def downgrade_cloud_verifier():
    op.drop_column("allowlists", "modified")
