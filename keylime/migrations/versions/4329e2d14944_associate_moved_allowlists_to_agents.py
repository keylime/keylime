"""Associate moved allowlists to agents (2/2)

Revision ID: 4329e2d14944
Revises: a72aec03d720
Create Date: 2022-08-03 10:29:14.858393

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "4329e2d14944"
down_revision = "a72aec03d720"
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
    meta = sa.MetaData(bind=conn)
    meta.reflect(only=("verifiermain",))
    verifiermain = meta.tables["verifiermain"]

    res = conn.execute("SELECT id, name FROM allowlists")
    results = res.fetchall()

    # Update new foreign key column with associated items in the "allowlists" table
    for allowlist_id, name in results:
        conn.execute(
            verifiermain.update().where(verifiermain.c.agent_id == name).values(**{"ima_policy_id": allowlist_id})
        )


def downgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.add_column(
            sa.Column("allowlist", sa.Text().with_variant(sa.Text(length=429400000), "mysql"), nullable=True)
        )
