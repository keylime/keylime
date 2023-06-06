"""convert allowlists to IMA policies

Revision ID: 8c0f8ded1f90
Revises: 039322ea079b
Create Date: 2022-10-27 18:18:31.674283

"""
import copy
import datetime
import json

import sqlalchemy as sa
from alembic import op

from keylime import keylime_logging
from keylime.ima import ima

logger = keylime_logging.init_logging("db_migrations")


# revision identifiers, used by Alembic.
revision = "8c0f8ded1f90"
down_revision = "039322ea079b"
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
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("allowlists",))
    allowlists = meta.tables["allowlists"]
    results = conn.execute(sa.text("SELECT id, ima_policy FROM allowlists")).fetchall()

    # Update allowlist entries with converted IMA policies
    for old_ima_policy_id, old_ima_policy in results:
        try:
            old_ima_policy = json.loads(old_ima_policy)
        except Exception as e:
            message = "Error loading JSON-formatted Keylime policy: %s", repr(e)
            logger.error(message)
            raise e

        alist_json = old_ima_policy["allowlist"]
        new_ima_policy = copy.deepcopy(ima.EMPTY_RUNTIME_POLICY)
        new_ima_policy["meta"]["timestamp"] = str(datetime.datetime.now())
        new_ima_policy["meta"]["generator"] = ima.RUNTIME_POLICY_GENERATOR.LegacyAllowList
        for key in new_ima_policy.keys():
            if key == "digests":
                digests = alist_json.get("hashes")
                if not digests:
                    message = "Allowlist %s does not have a valid hash list!", old_ima_policy_id
                    logger.error(message)
                    raise Exception(message)
                new_ima_policy[key] = alist_json["hashes"]
            elif key == "excludes":
                new_ima_policy["excludes"] = old_ima_policy["exclude"]
            elif key == "meta":
                # Skip old metadata
                continue
            else:
                to_migrate = alist_json.get(key, None)
                if to_migrate is None:
                    logger.info("Runtime policy field '%s' not found in existing allowlist; using default value", key)
                else:
                    new_ima_policy[key] = alist_json[key]
        new_ima_policy = json.dumps(new_ima_policy)

        conn.execute(allowlists.update().where(allowlists.c.id == old_ima_policy_id).values(ima_policy=new_ima_policy))


def downgrade_cloud_verifier():
    # get existing table metadata
    conn = op.get_bind()
    meta = sa.MetaData()
    meta.reflect(bind=conn, only=("allowlists",))
    allowlists = meta.tables["allowlists"]
    results = conn.execute(sa.text("SELECT id, ima_policy FROM allowlists")).fetchall()

    # Update allowlist entries with converted IMA policies
    for ima_policy_id, ima_policy in results:
        try:
            ima_policy = json.loads(ima_policy)
        except Exception as e:
            message = "Error loading JSON-formatted Keylime policy: %s", repr(e)
            logger.error(message)
            raise e

        allowlist = {
            "meta": {
                "version": 5,
                "generator": ima.RUNTIME_POLICY_GENERATOR.CompatibleAllowList,
                "checksum": "",
            },
            "release": 0,
            "hashes": {},
            "keyrings": {},
            "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1"},
        }
        allowlist["meta"]["timestamp"] = str(datetime.datetime.now())
        for key in allowlist.keys():  # pylint: disable=consider-iterating-dictionary
            if key == "hashes":
                digests = ima_policy.get("digests")
                if not digests:
                    message = "Runtime policy %s does not have a valid hash list!", ima_policy_id
                    logger.error(message)
                    raise Exception(message)
                allowlist[key] = ima_policy["digests"]
            elif key == "meta":
                # Skip old metadata
                continue
            else:
                to_migrate = ima_policy.get(key, None)
                if to_migrate is None:
                    logger.info("Allowlist field '%s' not found in existing IMA policy; using default value", key)
                else:
                    allowlist[key] = ima_policy[key]
        downgraded_policy = {}
        downgraded_policy["allowlist"] = allowlist
        downgraded_policy["exclude"] = ima_policy["excludes"]
        downgraded_policy = json.dumps(downgraded_policy)

        conn.execute(allowlists.update().where(allowlists.c.id == ima_policy_id).values(ima_policy=downgraded_policy))
