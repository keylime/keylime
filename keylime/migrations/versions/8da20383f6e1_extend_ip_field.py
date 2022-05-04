"""extend_ip_field

Revision ID: 8da20383f6e1
Revises: eeb702f77d7d
Create Date: 2021-01-14 10:50:56.275257

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "8da20383f6e1"
down_revision = "eeb702f77d7d"
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
            "ip", existing_type=sa.String(length=15), type_=sa.String(length=255), existing_nullable=True
        )


def downgrade_cloud_verifier():
    pass
