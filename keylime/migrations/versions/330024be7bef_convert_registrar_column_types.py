"""Convert registrar column types 

Revision ID: 330024be7bef
Revises: 9d2f6fab52b1
Create Date: 2024-02-15 11:48:41.458971

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "330024be7bef"
down_revision = "9d2f6fab52b1"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        # SQLite, MySQL and MariaDB do not have a native BOOLEAN datatype but Postgres does. In the former engines, True
        # and False are automatically translated to 1 and 0 respectively. In Postgres, attempting to set an INTEGER
        # column to True/False results in an error. To ensure consistent behaviour across engines, convert the relevant
        # columns to the SQLAlchemy "Boolean" datatype which will automatically use the appropriate engine-native
        # datatype (INTEGER for SQLite, TINYINT for MySQL/MariaDB and BOOLEAN for Postgres).
        batch_op.alter_column(
            "active",
            existing_type=sa.Integer,
            type_=sa.Boolean,
            existing_nullable=True,
            postgresql_using="active::boolean",
        )
        batch_op.alter_column(
            "virtual",
            existing_type=sa.Integer,
            type_=sa.Boolean,
            existing_nullable=True,
            postgresql_using="virtual::boolean",
        )
        # Certificates can easily be more than 2048 characters when Base64 encoded. SQLite does not enforce length
        # restrictions (VARCHAR(2048) = TEXT) which may have prevented this from being a problem in the past.
        # The other engines do enforce these restrictions, so it is better to treat certificates as TEXT columns.
        batch_op.alter_column(
            "ekcert",
            existing_type=sa.String(2048),
            type_=sa.Text,
            existing_nullable=True,
        )
        batch_op.alter_column(
            "mtls_cert",
            existing_type=sa.String(2048),
            type_=sa.Text,
            existing_nullable=True,
        )


def downgrade_registrar():
    with op.batch_alter_table("registrarmain") as batch_op:
        batch_op.alter_column(
            "active",
            existing_type=sa.Boolean,
            type_=sa.Integer,
            existing_nullable=True,
            postgresql_using="active::integer",
        )
        batch_op.alter_column(
            "virtual",
            existing_type=sa.Boolean,
            type_=sa.Integer,
            existing_nullable=True,
            postgresql_using="virtual::integer",
        )
        batch_op.alter_column(
            "ekcert",
            existing_type=sa.Text,
            type_=sa.String(2048),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "mtls_cert",
            existing_type=sa.Text,
            type_=sa.String(2048),
            existing_nullable=True,
        )


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
