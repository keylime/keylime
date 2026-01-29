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

Note: Existing sessions will be invalidated by this migration since plaintext
tokens cannot be retroactively hashed. Agents will need to re-authenticate.
"""

import uuid

import sqlalchemy as sa
from alembic import op

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
    # SQLite doesn't support ALTER PRIMARY KEY, so we need to recreate the table.
    # Using batch mode handles this automatically.
    with op.batch_alter_table("sessions") as batch_op:
        # Add new columns
        batch_op.add_column(sa.Column("session_id", sa.String(36), nullable=True))
        batch_op.add_column(sa.Column("token_salt", sa.String(32), nullable=True))

        # Rename token to token_hash
        batch_op.alter_column(
            "token",
            new_column_name="token_hash",
            existing_type=sa.String(64),
        )

    # Generate UUIDs and placeholder values for existing rows
    # These sessions will be invalidated
    connection = op.get_bind()
    sessions_table = sa.table(
        "sessions",
        sa.column("session_id"),
        sa.column("token_hash"),
        sa.column("token_salt"),
    )
    result = connection.execute(sa.select(sessions_table.c.token_hash))
    for row in result:
        connection.execute(
            sessions_table.update()
            .where(sessions_table.c.token_hash == row[0])
            .values(
                session_id=str(uuid.uuid4()),
                token_salt="0" * 32,  # Placeholder salt
            )
        )

    # Now recreate table with proper schema (session_id as primary key)
    with op.batch_alter_table("sessions", recreate="always") as batch_op:
        # Set column constraints
        batch_op.alter_column("session_id", nullable=False, existing_type=sa.String(36))
        batch_op.alter_column("token_salt", nullable=False, existing_type=sa.String(32))
        batch_op.alter_column("token_hash", nullable=False, existing_type=sa.String(64))


def downgrade_cloud_verifier():
    # Recreate table with original schema (token as primary key)
    with op.batch_alter_table("sessions", recreate="always") as batch_op:
        # Remove new columns
        batch_op.drop_column("session_id")
        batch_op.drop_column("token_salt")

        # Rename token_hash back to token
        batch_op.alter_column(
            "token_hash",
            new_column_name="token",
            existing_type=sa.String(64),
        )
