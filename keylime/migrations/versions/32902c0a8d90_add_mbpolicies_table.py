"""add mbpolicies table

Revision ID: 32902c0a8d90
Revises: 160f932fde5b
Create Date: 2024-02-08 04:16:14.830358

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = "32902c0a8d90"
down_revision = "160f932fde5b"
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
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    tables = inspector.get_table_names()
    if "mbpolicies" not in tables:
        op.create_table(
            "mbpolicies",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("mb_policy", sa.Text().with_variant(sa.Text(length=429400000), "mysql"), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name", name="uniq_mbpolicies_name"),
            mysql_engine="InnoDB",
            mysql_charset="UTF8",
        )


def downgrade_cloud_verifier():
    op.drop_table("mbpolicies")
