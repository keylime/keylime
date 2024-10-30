"""create_attestations_table_for_push

Revision ID: 870c218abd9a
Revises: 330024be7bef
Create Date: 2024-02-23 00:02:34.715180

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "870c218abd9a"
down_revision = "330024be7bef"
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
        sa.Column(
            "agent_id", sa.String(80), sa.ForeignKey("verifiermain.agent_id", name="fk_attestation_verifiermain")
        ),
        sa.Column("nonce", sa.LargeBinary()),
        sa.Column("nonce_created_at", sa.Integer()),
        sa.Column("nonce_expires_at", sa.Integer()),
        sa.Column("status", sa.String(), server_default="waiting"),
        sa.Column("tpm_quote", sa.Text()),
        sa.Column("evidence_received_at", sa.Integer(), server_default=0),
        sa.Column("tpm_pcrs", sa.Text),
        sa.Column("hash_alg", sa.String(length=10), nullable=True),
        sa.Column("enc_alg", sa.String(length=10), nullable=True),
        sa.Column("sign_alg", sa.String(length=10), nullable=True),
        sa.Column("starting_ima_offset", sa.Integer()),
        sa.Column("ima_entries", sa.Text()),
        sa.Column("ima_count", sa.Integer()),
        sa.Column("mb_entries", sa.Text()),
        mysql_engine="InnoDB",
        mysql_charset="UTF8",
    )
    op.add_column("verifiermain", sa.Column("accept_attestations", sa.Boolean()))


def downgrade_cloud_verifier():
    op.drop_table("attestations")
    op.drop_column("verifiermain", "accept_attestations")
