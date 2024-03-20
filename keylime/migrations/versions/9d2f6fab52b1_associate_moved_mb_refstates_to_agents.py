"""associate moved mb_refstates to agents

Revision ID: 9d2f6fab52b1
Revises: f4196d13fe45
Create Date: 2024-02-08 04:16:28.521778

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "9d2f6fab52b1"
down_revision = "f4196d13fe45"
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
    # get existing table metadata
    conn = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("verifiermain",))
    verifiermain = meta.tables["verifiermain"]

    # Get id and name from mbpolicies
    res = conn.execute(sa.text("SELECT id, name FROM mbpolicies"))
    results = res.fetchall()

    # Update new foreign key column with associated items in the "mbpolicies" table
    for mbpolicies_id, name in results:
        conn.execute(
            verifiermain.update().where(verifiermain.c.agent_id == name).values(**{"mb_policy_id": mbpolicies_id})
        )


def downgrade_cloud_verifier():
    pass
