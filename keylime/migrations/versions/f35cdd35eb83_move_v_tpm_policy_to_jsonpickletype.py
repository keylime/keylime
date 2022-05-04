"""Move (v)tpm_policy to JSONPickleType

Revision ID: f35cdd35eb83
Revises: 7d5db1a6ffb0
Create Date: 2021-08-02 15:26:34.427156

"""
import sqlalchemy as sa
from alembic import op

import keylime

# revision identifiers, used by Alembic.
revision = "f35cdd35eb83"
down_revision = "7d5db1a6ffb0"
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
            "tpm_policy",
            existing_type=sa.String(1000),
            type_=keylime.db.verifier_db.JSONPickleType(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "vtpm_policy",
            existing_type=sa.String(1000),
            type_=keylime.db.verifier_db.JSONPickleType(),
            existing_nullable=True,
        )


def downgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "tpm_policy",
            type_=sa.String(1000),
            existing_type=keylime.db.verifier_db.JSONPickleType(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "vtpm_policy",
            type_=sa.String(1000),
            existing_type=keylime.db.verifier_db.JSONPickleType(),
            existing_nullable=True,
        )
