"""convert ekcert from DER to PEM format

Revision ID: fb6107fbeb30
Revises: 330024be7bef
Create Date: 2024-10-16 09:02:09.982335

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fb6107fbeb30'
down_revision = '330024be7bef'
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    conn = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("registrarmain",))
    registrarmain = meta.tables["registrarmain"]
    results = conn.execute(sa.text("SELECT agent_id, ekcert FROM registrarmain")).fetchall()
    for agent_id, ekcert in results:
        if len(ekcert.strip()) <= 0:
            continue

        pem_string = f"-----BEGIN CERTIFICATE-----\n"
        for i in range(0, len(ekcert), 64):
            pem_string += ekcert[i:i+64] + '\n'
        pem_string += f"-----END CERTIFICATE-----"

        conn.execute(registrarmain.update().where(registrarmain.c.agent_id == agent_id).values(ekcert=pem_string))


def downgrade_registrar():
    conn = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("registrarmain",))
    registrarmain = meta.tables["registrarmain"]
    results = conn.execute(sa.text("SELECT agent_id, ekcert FROM registrarmain")).fetchall()
    for agent_id, pem_string in results:
        if not pem_string:
            continue

        pem_lines = pem_string.strip().splitlines()

        ekcert_lines = []
        # Last certificate in the chain will be the original ekcert
        if pem_lines[-1] != "-----END CERTIFICATE-----":
            raise Exception("Invalid format for ekcert/chain (Missing '-----END CERTIFICATE-----' at end).")

        pem_lines.pop()

        found_start = False
        for line in pem_lines[::-1]:
            # Skip empty lines
            if len(line.strip()) == 0:
                continue

            if line == f"-----BEGIN CERTIFICATE-----":
                found_start = True
                break
            if line == f"-----END CERTIFICATE-----":
                break

            ekcert_lines.insert(0, line)

        if not found_start:
            raise Exception("Invalid format for ekcert/chain (Failed to find '-----START CERTIFICATE-----' before other certificate begins).")

        if len(ekcert_lines) <= 0:
            raise Exception("Empty ekcert/chain")

        ekcert = ''.join(ekcert_lines)
        conn.execute(registrarmain.update().where(registrarmain.c.agent_id == agent_id).values(ekcert=ekcert))


def upgrade_cloud_verifier():
    pass


def downgrade_cloud_verifier():
    pass
