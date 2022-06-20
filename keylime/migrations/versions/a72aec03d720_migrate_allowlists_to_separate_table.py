"""Migrate allowlists to dedicated table (1/2)

Revision ID: a72aec03d720
Revises: bc3b6b551b0a
Create Date: 2022-07-21 12:17:17.779159

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "a72aec03d720"
down_revision = "bf48e0c4751d"
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

    # Migrate existing agent info to the allowlists table.
    conn = op.get_bind()

    res = conn.execute("SELECT agent_id, tpm_policy, allowlist FROM verifiermain")
    results = res.fetchall()
    old_policy = [{"name": r[0], "tpm_policy": r[1], "ima_policy": r[2]} for r in results]

    # get existing table metadata
    meta = sa.MetaData(bind=conn)
    meta.reflect(only=("allowlists",))
    allowlists = meta.tables["allowlists"]

    op.bulk_insert(allowlists, old_policy)

    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.add_column(
            sa.Column("ima_policy_id", sa.Integer(), sa.ForeignKey("allowlists.id", name="fk_verifiermain_allowlists"))
        )
        batch_op.drop_column("allowlist")


def downgrade_cloud_verifier():
    # Migrate existing agent info to the allowlist column in verifiermain.
    conn = op.get_bind()
    meta = sa.MetaData(bind=conn)
    meta.reflect(only=("verifiermain", "allowlists"))
    verifiermain = meta.tables["verifiermain"]
    allowlists = meta.tables["allowlists"]

    res = conn.execute("SELECT name, ima_policy FROM allowlists")
    results = res.fetchall()

    # Put allowlists back into the "allowlist" column, and delete from the "allowlists" database
    for name, ima_policy in results:
        conn.execute(verifiermain.update().where(verifiermain.c.agent_id == name).values(**{"allowlist": ima_policy}))
        conn.execute(allowlists.delete().where(allowlists.c.name == name))

    # Drop the foreign key table
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.drop_column("ima_policy_id")
