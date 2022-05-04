"""Add mTLS cert field to registrar

Revision ID: a79c27ec1054
Revises: c3842cc9ee69
Create Date: 2021-11-29 09:50:46.701369

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a79c27ec1054"
down_revision = "c3842cc9ee69"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    op.add_column("registrarmain", sa.Column("mtls_cert", sa.String(length=2048), nullable=True))


def downgrade_registrar():
    op.drop_column("registrarmain", "mtls_cert")


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
