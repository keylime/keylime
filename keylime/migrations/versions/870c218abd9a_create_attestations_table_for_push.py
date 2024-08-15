"""create_attestations_table_for_push

Revision ID: 870c218abd9a
Revises: 330024be7bef
Create Date: 2024-02-23 00:02:34.715180

"""
from alembic import op
import sqlalchemy as sa

from keylime.attestationstatus import AttestationStatusEnum


# revision identifiers, used by Alembic.
revision = '870c218abd9a'
down_revision = '330024be7bef'
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
    op.create_table(
        "attestations",
        sa.Column("agent_id", sa.String(80), sa.ForeignKey("verifiermain.agent_id", name="fk_attestation_verifiermain")),
        sa.Column("nonce", sa.String(20)),
        sa.Column("nonce_created", sa.Integer()),
        sa.Column("nonce_expires", sa.Integer()),
        sa.Column("status", sa.Enum(AttestationStatusEnum), server_default=AttestationStatusEnum.WAITING.value),
        sa.Column("quote", sa.Text()),
        sa.Column("quote_received", sa.Integer()),
        sa.Column("pcrs", sa.Text),
        sa.Column("next_ima_offset", sa.Integer()),
        sa.Column("hash_alg", sa.String(length=10), nullable=True),
        sa.Column("enc_alg", sa.String(length=10), nullable=True),
        sa.Column("sign_alg", sa.String(length=10), nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="UTF8",
    )
    op.add_column("verifiermain", sa.Column("attestation_details", sa.String()))

    # Migrate existing agent info to the new attestation table.
    conn = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("verifiermain","attestations"))
    attestations = meta.tables["attestations"]

    results = conn.execute(sa.text("SELECT agent_id, hash_alg, enc_alg, sign_alg, next_ima_ml_entry, last_received_quote FROM verifiermain")).fetchall()

    for agent_id, hash_alg, enc_alg, sign_alg, next_ima_ml_entry, last_received_quote in results:
        conn.execute(attestations.insert().values(**{"agent_id": agent_id}))
        conn.execute(attestations.update().where(attestations.c.agent_id == agent_id).values(**{"hash_alg": hash_alg}))
        conn.execute(attestations.update().where(attestations.c.agent_id == agent_id).values(**{"enc_alg": enc_alg}))
        conn.execute(attestations.update().where(attestations.c.agent_id == agent_id).values(**{"sign_alg": sign_alg}))
        conn.execute(attestations.update().where(attestations.c.agent_id == agent_id).values(**{"next_ima_offset": next_ima_ml_entry}))
        conn.execute(attestations.update().where(attestations.c.agent_id == agent_id).values(**{"quote_received": last_received_quote}))

    """ with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.drop_column("hash_alg")
        batch_op.drop_column("enc_alg")
        batch_op.drop_column("sign_alg") """


def downgrade_cloud_verifier():
    op.drop_table("attestations")
    op.drop_column("verifiermain", "attestation_details")
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.add_column("hash_alg", sa.String(length=10), nullable=True)
        batch_op.add_column("enc_alg", sa.String(length=10), nullable=True)
        batch_op.add_column("sign_alg", sa.String(length=10), nullable=True)
