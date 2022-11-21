"""add_generator_column

Revision ID: 039322ea079b
Revises: 2fbc0fb8fa4d
Create Date: 2022-11-17 10:19:25.183759

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "039322ea079b"
down_revision = "2fbc0fb8fa4d"
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
    op.add_column("allowlists", sa.Column("generator", sa.Integer))


def downgrade_cloud_verifier():
    op.drop_column("allowlists", "generator")
