"""Add fields for revocation context to verifier

Revision ID: 257fe0f0c039
Revises: f35cdd35eb83
Create Date: 2021-08-20 12:42:30.427138

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "257fe0f0c039"
down_revision = "f35cdd35eb83"
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
    op.add_column("verifiermain", sa.Column("severity_level", sa.Integer))
    op.add_column("verifiermain", sa.Column("last_event_id", sa.String(100)))


def downgrade_cloud_verifier():
    op.drop_column("verifiermain", "severity_level")
    op.drop_column("verifiermain", sa.Column("last_event_id", sa.Integer))
