"""Drop vTPM colums

Revision ID: bc3b6b551b0a
Revises: 1ac1513ef2a1
Create Date: 2022-04-11 10:14:20.242578

"""
import sqlalchemy as sa
from alembic import op

import keylime

# revision identifiers, used by Alembic.
revision = "bc3b6b551b0a"
down_revision = "1ac1513ef2a1"
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
        batch_op.drop_column("vtpm_policy")
    with op.batch_alter_table("allowlists") as batch_op:
        batch_op.drop_column("vtpm_policy")


def downgrade_cloud_verifier():
    op.add_column("verifiermain", sa.Column(keylime.db.verifier_db.JSONPickleType()))
    op.add_column("allowlists", sa.Column(sa.Text()))
