"""Fix MB and IMA column types

Revision ID: 1ac1513ef2a1
Revises: 63c30820fdc1
Create Date: 2022-01-31 17:46:59.288333

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "1ac1513ef2a1"
down_revision = "63c30820fdc1"
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
            "allowlist",
            existing_type=sa.Text(),
            type_=sa.Text().with_variant(sa.Text(429400000), "mysql"),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "mb_refstate",
            existing_type=sa.String(1000),
            type_=sa.Text().with_variant(sa.Text(429400000), "mysql"),
            existing_nullable=True,
        )


def downgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "allowlist",
            type_=sa.Text(),
            existing_type=sa.Text().with_variant(sa.Text(429400000), "mysql"),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "mb_refstate",
            type_=sa.String(1000),
            existing_type_=sa.Text().with_variant(sa.Text(429400000), "mysql"),
            existing_nullable=True,
        )
