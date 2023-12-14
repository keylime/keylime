"""migrate mb_refstates to mbpolicies

Revision ID: f4196d13fe45
Revises: 32902c0a8d90
Create Date: 2024-02-08 04:16:21.554062

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f4196d13fe45"
down_revision = "32902c0a8d90"
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
    # Migrate existing agent info to the mbpolicies table.
    conn = op.get_bind()

    res = conn.execute(sa.text("SELECT agent_id, mb_refstate FROM verifiermain"))
    results = res.fetchall()
    old_policy = [{"name": r[0], "mb_policy": r[1]} for r in results]

    # get existing table metadata
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("mbpolicies",))
    mbpolicies = meta.tables["mbpolicies"]

    # Insert the existing MB policies to the mbpolicies table
    op.bulk_insert(mbpolicies, old_policy)

    # Modify verifiermain table (i.e. add mb_policy_id and remove mb_refstate)
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.add_column(
            sa.Column("mb_policy_id", sa.Integer(), sa.ForeignKey("mbpolicies.id", name="fk_verifiermain_mbpolicies"))
        )
        batch_op.drop_column("mb_refstate")


def downgrade_cloud_verifier():
    # Migrate existing agent info back to the mb_refstate column in verifiermain.
    conn = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("verifiermain", "mbpolicies"))
    verifiermain = meta.tables["verifiermain"]
    mbpolicies = meta.tables["mbpolicies"]

    # Get name and mb_policy from mbpolicies
    res = conn.execute(sa.text("SELECT name, mb_policy FROM mbpolicies"))
    results = res.fetchall()

    # Add mb_refstate column back to verifiermain
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.add_column(
            sa.Column("mb_refstate", sa.Text().with_variant(sa.Text(length=429400000), "mysql"), nullable=True)
        )

    # Put mb_refstate back to "verifiermain" and delete its entry from the "mbpolicies"
    for name, mb_policy in results:
        conn.execute(verifiermain.update().where(verifiermain.c.agent_id == name).values(**{"mb_refstate": mb_policy}))
        conn.execute(mbpolicies.delete().where(mbpolicies.c.name == name))

    # Drop mb_policy_id column from "verifiermain"
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.drop_column("mb_policy_id")
