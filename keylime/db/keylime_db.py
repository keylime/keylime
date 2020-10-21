'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine.url import URL

from keylime import common
from keylime import keylime_logging

class DBEngineManager:
    def make_engine(self, service):
        """
        To use: engine = self.make_engine('cloud_verifier')
        """
        self.service = service

        config = common.get_config()
        drivername = config.get(service, 'drivername')

        if drivername == 'sqlite':
            database = "%s/%s" % (common.WORK_DIR,
                                  config.get(service, 'database'))
            # Create the path to where the sqlite database will be store with a perm umask of 077
            os.umask(0o077)
            kl_dir = os.path.dirname(os.path.abspath(database))
            if not os.path.exists(kl_dir):
                os.makedirs(kl_dir, 0o700)

            url = URL(
                drivername=drivername,
                username=None,
                password=None,
                host=None,
                database=(database)
            )
            engine = create_engine(url, connect_args={'check_same_thread': False},)
        else:
            url = URL(
                drivername=drivername,
                username=config.get(service, 'username'),
                password=config.get(service, 'password'),
                host=config.get(service, 'host'),
                database=config.get(service, 'database')
            )
            engine = create_engine(url)

        return engine


class SessionManager:
    def make_session(self, engine):
        """
        To use: session = self.make_session(engine)
        """
        self.engine = engine
        try:
            Session = scoped_session(sessionmaker())
            Session.configure(bind=self.engine)
        except SQLAlchemyError as e:
            logger = keylime_logging.init_logging('sql_session_manager')
            logger.error(f'Error creating SQL session manager {e}')
        return Session()

