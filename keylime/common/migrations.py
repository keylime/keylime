import os
from typing import Optional

import alembic.config


def apply(db_name: Optional[str]) -> None:
    # set a conservative general umask
    os.umask(0o077)

    here = os.path.dirname(os.path.abspath(__file__))

    # the config file for alembic is in the migrations directory
    alembic_args = ["-c", os.path.join(here, "..", "migrations", "alembic.ini")]

    # if we are restricting it to a single db, add that to the custom args (-x)
    if db_name:
        alembic_args.extend(["-x", "db=" + db_name])

    alembic_args.extend(["upgrade", "head"])

    alembic.config.main(argv=alembic_args)  # type: ignore
