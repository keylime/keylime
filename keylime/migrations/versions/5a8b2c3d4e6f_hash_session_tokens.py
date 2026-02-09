"""hash session tokens for secure storage with PBKDF2

Revision ID: 5a8b2c3d4e6f
Revises: 517a2d6b5cd3
Create Date: 2025-01-29 12:00:00.000000

Security fix: Store hashed tokens with per-token salts instead of plaintext.

Schema changes:
- Add 'session_id' column (UUID) as primary key for clean URLs
- Add 'token_salt' column for per-token PBKDF2 salt
- Rename 'token' to 'token_hash' for PBKDF2 hash storage

Security rationale (OWASP 2023 / FIPS-140 compliant):
- Token format embeds session_id for O(1) lookup by primary key
- Per-token random salt prevents rainbow table attacks
- PBKDF2 with HMAC-SHA-256 (600k iterations) adds computational cost

Note: Existing sessions are invalidated by this migration since plaintext
tokens cannot be retroactively hashed. All sessions are deleted during both
upgrade and downgrade. Agents will need to re-authenticate.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "5a8b2c3d4e6f"
down_revision = "517a2d6b5cd3"
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
    # Drop the sessions table entirely and recreate with the new schema.
    # Existing sessions are invalidated by this migration since plaintext
    # tokens cannot be retroactively hashed with PBKDF2.
    # Dropping and recreating avoids issues with ALTER PRIMARY KEY which
    # is not supported consistently across database backends (e.g. MySQL
    # rejects making a PRIMARY KEY column nullable during column rename).
    #
    # Check if the table exists before dropping to handle the case where
    # a previous migration attempt was interrupted between drop and create.
    bind = op.get_bind()
    inspector = inspect(bind)
    if "sessions" in inspector.get_table_names():
        op.drop_table("sessions")

    op.create_table(
        "sessions",
        sa.Column("session_id", sa.String(36), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_salt", sa.String(32), nullable=False),
        sa.Column("agent_id", sa.String(80), index=True),
        sa.Column("active", sa.Boolean()),
        sa.Column("nonce", sa.LargeBinary(128)),
        sa.Column("hash_algorithm", sa.String(15)),
        sa.Column("signing_scheme", sa.String(15)),
        sa.Column("ak_attest", sa.LargeBinary(512)),
        sa.Column("ak_sign", sa.LargeBinary(512)),
        sa.Column("nonce_created_at", sa.String(32)),
        sa.Column("nonce_expires_at", sa.String(32)),
        sa.Column("pop_received_at", sa.String(32)),
        sa.Column("token_expires_at", sa.String(32)),
    )


def downgrade_cloud_verifier():
    # Drop the sessions table entirely and recreate with the original schema.
    # Sessions are invalidated by the downgrade since hashed tokens cannot be
    # converted back to plaintext.
    #
    # Check if the table exists before dropping to handle the case where
    # a previous migration attempt was interrupted between drop and create.
    bind = op.get_bind()
    inspector = inspect(bind)
    if "sessions" in inspector.get_table_names():
        op.drop_table("sessions")

    op.create_table(
        "sessions",
        sa.Column("token", sa.String(64), primary_key=True),
        sa.Column("agent_id", sa.String(80), index=True),
        sa.Column("active", sa.Boolean()),
        sa.Column("nonce", sa.LargeBinary(128)),
        sa.Column("hash_algorithm", sa.String(15)),
        sa.Column("signing_scheme", sa.String(15)),
        sa.Column("ak_attest", sa.LargeBinary(512)),
        sa.Column("ak_sign", sa.LargeBinary(512)),
        sa.Column("nonce_created_at", sa.String(32)),
        sa.Column("nonce_expires_at", sa.String(32)),
        sa.Column("pop_received_at", sa.String(32)),
        sa.Column("token_expires_at", sa.String(32)),
    )
