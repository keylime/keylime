"""Database migration

"""

import logging
import re
import sys

from alembic import context

from keylime.db.keylime_db import DBEngineManager
from keylime.db.registrar_db import Base as RegistrarBase
from keylime.db.verifier_db import Base as VerifierBase

sys.path.append("..")

USE_TWOPHASE = False

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

logger = logging.getLogger("alembic.env")

# gather section names referring to different
# databases.  These are named "engine1", "engine2"
# in the sample .ini file.
db_names = ""
db_names_ = context.get_x_argument(as_dictionary=True).get("db")
if db_names_:
    db_names = db_names_
else:
    db_names_ = config.get_main_option("databases")
    if db_names_:
        db_names = db_names_

# add your model's MetaData objects here
# for 'autogenerate' support.  These must be set
# up to hold just those tables targeting a
# particular database. table.tometadata() may be
# helpful here in case a "copy" of
# a MetaData is needed.
# from myapp import mymodel
# target_metadata = {
#       'engine1':mymodel.metadata1,
#       'engine2':mymodel.metadata2
# }
target_metadata = {"registrar": RegistrarBase.metadata, "cloud_verifier": VerifierBase.metadata}

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    # for the --sql use case, run migrations for each URL into
    # individual files.

    for name in re.split(r",\s*", db_names):

        logger.info("Migrating database %s", name)
        file_ = f"{name}.sql"
        logger.info("Writing output to %s", file_)

        with open(file_, "w", encoding="utf-8") as buffer:
            engine = DBEngineManager().make_engine(name)
            connection = engine.connect()
            context.configure(
                connection=connection,
                output_buffer=buffer,
                target_metadata=target_metadata.get(name),
                literal_binds=True,
                dialect_opts={"paramstyle": "named"},
                version_table="alembic_version_" + name,
            )
            with context.begin_transaction():
                context.run_migrations(engine_name=name)


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # for the direct-to-DB use case, start a transaction on all
    # engines, then run all migrations, then commit all transactions.

    engines = {}
    for name in re.split(r",\s*", db_names):
        engines[name] = rec = {}
        rec["engine"] = DBEngineManager().make_engine(name)

    for name, rec in engines.items():
        engine = rec["engine"]
        rec["connection"] = conn = engine.connect()

        if USE_TWOPHASE:
            rec["transaction"] = conn.begin_twophase()
        else:
            rec["transaction"] = conn.begin()

    try:
        for name, rec in engines.items():
            logger.info("Migrating database %s", name)
            context.configure(
                connection=rec["connection"],
                upgrade_token=f"{name}_upgrades",
                downgrade_token=f"{name}_downgrades",
                target_metadata=target_metadata.get(name),
                version_table=f"alembic_version_{name}",
            )
            context.run_migrations(engine_name=name)

        if USE_TWOPHASE:
            for rec in engines.values():
                rec["transaction"].prepare()

        for rec in engines.values():
            rec["transaction"].commit()
    except Exception:
        for rec in engines.values():
            rec["transaction"].rollback()
        raise
    finally:
        for rec in engines.values():
            rec["connection"].close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
