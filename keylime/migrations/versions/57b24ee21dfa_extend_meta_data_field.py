"""Extend meta_data field

Revision ID: 57b24ee21dfa
Revises: 330024be7bef
Create Date: 2025-03-19 11:30:04.556745

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "57b24ee21dfa"
down_revision = "330024be7bef"
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
        batch_op.alter_column(
            "meta_data",
            existing_type=sa.String(length=200),
            type_=sa.Text().with_variant(sa.Text(length=429400000), "mysql"),
            existing_nullable=True,
        )


def downgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "meta_data",
            existing_type=sa.Text().with_variant(sa.Text(length=429400000), "mysql"),
            type_=sa.String(length=200),
            existing_nullable=True,
        )
