"""add sessions table

Revision ID: 460d7adda633
Revises: 870c218abd9a
Create Date: 2025-01-30 15:41:24.600850

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "460d7adda633"
down_revision = "870c218abd9a"
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
        "sessions",
        sa.Column("token", sa.String(64), primary_key=True),  # secrets.token_urlsafe(32) generates ~43 char tokens
        sa.Column(
            "agent_id", sa.String(80)
        ),  # No FK constraint - sessions persist through agent deletion/re-enrollment
        sa.Column("active", sa.Boolean()),
        sa.Column("nonce", sa.LargeBinary(128)),
        sa.Column("hash_algorithm", sa.String(15)),
        sa.Column("signing_scheme", sa.String(15)),
        sa.Column("ak_attest", sa.LargeBinary(512)),  # TPM attestation structures can exceed 128 bytes
        sa.Column("ak_sign", sa.LargeBinary(512)),  # TPM signature structures can exceed 128 bytes
        # ISO8601 datetimes with microsecond precision in the UTC timezone are never more than 32 characters
        sa.Column("nonce_created_at", sa.String(32)),
        sa.Column("nonce_expires_at", sa.String(32)),
        sa.Column("pop_received_at", sa.String(32)),
        sa.Column("token_expires_at", sa.String(32)),
    )


def downgrade_cloud_verifier():
    op.drop_table("sessions")
