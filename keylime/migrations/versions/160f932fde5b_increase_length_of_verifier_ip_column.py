"""increase length of verifier_ip column

Revision ID: 160f932fde5b
Revises: 00766b7fd0c5
Create Date: 2024-01-26 10:48:38.790381

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "160f932fde5b"
down_revision = "00766b7fd0c5"
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
            "verifier_ip", existing_type=sa.String(length=15), type_=sa.String(length=255), existing_nullable=True
        )


def downgrade_cloud_verifier():
    pass
