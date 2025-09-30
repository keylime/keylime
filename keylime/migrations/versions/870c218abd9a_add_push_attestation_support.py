"""Changes for agent-driven (push) attestation support

Revision ID: 870c218abd9a
Revises: 57b24ee21dfa
Create Date: 2024-02-23 00:02:34.715180

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "870c218abd9a"
down_revision = "57b24ee21dfa"
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
        batch_op.add_column(sa.Column("accept_attestations", sa.Boolean, nullable=False, server_default=sa.true()))
        batch_op.alter_column("supported_version", nullable=True, existing_type=sa.String(length=50))

    op.create_table(
        "attestations",
        sa.Column("agent_id", sa.String(80), sa.ForeignKey("verifiermain.agent_id"), nullable=False),
        sa.Column("index", sa.Integer, nullable=False),
        sa.Column("stage", sa.String(25), server_default="awaiting_evidence", nullable=False),
        sa.Column("evaluation", sa.String(10), server_default="pending", nullable=False),
        sa.Column("failure_reason", sa.String(25)),
        # ISO8601 datetimes with microsecond precision in the UTC timezone are never more than 32 characters
        sa.Column("system_info__boot_time", sa.String(32), nullable=False),
        sa.Column("capabilities_received_at", sa.String(32), nullable=False),
        sa.Column("challenges_expire_at", sa.String(32)),
        sa.Column("evidence_received_at", sa.String(32)),
        sa.Column("verification_completed_at", sa.String(32)),
        sa.PrimaryKeyConstraint("agent_id", "index"),
    )

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Integer, nullable=False),
        sa.Column("agent_id", sa.String(20), nullable=False),
        sa.Column("attestation_index", sa.Integer, nullable=False),
        sa.Column("evidence_class", sa.String(20), nullable=False),
        sa.Column("evidence_type", sa.String(30), nullable=False),
        sa.Column("capabilities__component_version", sa.String(20)),
        sa.Column("capabilities__evidence_version", sa.String(20)),
        sa.Column("capabilities__signature_schemes", sa.Text),
        sa.Column("capabilities__hash_algorithms", sa.Text),
        sa.Column("capabilities__available_subjects", sa.Text),
        sa.Column("capabilities__certification_keys", sa.Text),
        sa.Column("capabilities__entry_count", sa.Integer),
        sa.Column("capabilities__supports_partial_access", sa.Boolean),
        sa.Column("capabilities__appendable", sa.Boolean),
        sa.Column("capabilities__formats", sa.Text),
        sa.Column("capabilities__meta", sa.Text),
        sa.Column("chosen_parameters__challenge", sa.LargeBinary),
        sa.Column("chosen_parameters__signature_scheme", sa.String(20)),
        sa.Column("chosen_parameters__hash_algorithm", sa.String(20)),
        sa.Column("chosen_parameters__selected_subjects", sa.Text),
        sa.Column("chosen_parameters__certification_key", sa.Text),
        sa.Column("chosen_parameters__starting_offset", sa.Integer),
        sa.Column("chosen_parameters__entry_count", sa.Integer),
        sa.Column("chosen_parameters__format", sa.String(255)), # RFC 4288 length
        sa.Column("chosen_parameters__meta", sa.Text),
        sa.Column("data__subject_data", sa.Text),
        sa.Column("data__message", sa.LargeBinary),
        sa.Column("data__signature", sa.LargeBinary),
        sa.Column("data__entry_count", sa.Integer),
        sa.Column("data__entries", sa.Text),
        sa.Column("data__meta", sa.Text),
        sa.Column("results__certified_entry_count", sa.Integer),
        sa.Column("results__meta", sa.Text),
        sa.ForeignKeyConstraint(["agent_id", "attestation_index"], ["attestations.agent_id", "attestations.index"]),
        sa.PrimaryKeyConstraint("id")
    )


def downgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.drop_column("verifiermain", "accept_attestations")
        batch_op.alter_column("supported_version", nullable=False, existing_type=sa.String(length=50))

    op.drop_table("attestations")
    op.drop_table("evidence_items")
