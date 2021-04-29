'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.engine.url import URL

from keylime import config
from keylime import keylime_logging

logger = keylime_logging.init_logging('keylime_db')

class DBEngineManager:

    def __init__(self):
        self.service = None

    def make_engine(self, service):
        """
        To use: engine = self.make_engine('cloud_verifier')
        """
        self.service = service

        p_sz, m_ovfl = config.get(service, 'database_pool_sz_ovfl').split(',')
        engine_args = {}

        url = config.get(service, 'database_url')
        if url:
            logger.info('database_url is set, using it for establishing database connection')
            engine_args['pool_size'] = int(p_sz)
            engine_args['max_overflow'] = int(m_ovfl)

        else :
            logger.info('database_url is not set, using multi-parameter database configuration options')

            drivername = config.get(service, 'database_drivername')
            if drivername == 'sqlite':
                database = "%s/%s" % (config.WORK_DIR,
                                    config.get(service, 'database_name'))
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
                engine_args['connect_args'] = {'check_same_thread': False}

            else:
                url = URL(
                    drivername=drivername,
                    username=config.get(service, 'database_username'),
                    password=config.get(service, 'database_password'),
                    host=config.get(service, 'database_host'),
                    database=config.get(service, 'database_name')
                )
                engine_args['pool_size'] = int(p_sz)
                engine_args['max_overflow'] = int(m_ovfl)

        engine = create_engine(url, **engine_args)

        return engine

class SessionManager:
    def __init__(self):
        self.engine = None

    def make_session(self, engine):
        """
        To use: session = self.make_session(engine)
        """
        self.engine = engine
        try:
            Session = scoped_session(sessionmaker())
            Session.configure(bind=self.engine)
        except SQLAlchemyError as e:
            logger.error('Error creating SQL session manager %s', e)
        return Session()
