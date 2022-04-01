'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

import os
from configparser import NoOptionError

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

        try :
            p_sz_m_ovfl = config.get(service, 'database_pool_sz_ovfl')
            p_sz, m_ovfl = p_sz_m_ovfl.split(',')
        except NoOptionError:
            p_sz = 5
            m_ovfl = 10

        engine_args = {}

        url = config.get(service, 'database_url')
        if url:
            logger.info('database_url is set, using it to establish database connection')
            if not url.count('sqlite:') :
                engine_args['pool_size'] = int(p_sz)
                engine_args['max_overflow'] = int(m_ovfl)

        else :
            logger.info('database_url is not set, using multi-parameter database configuration options')

            # This code shall be removed once we fully deprecate the old format
            try :
                drivername = config.get(service, 'drivername')
                database = config.get(service, 'database')
                logger.warning('Deprecation reminder: please add the suffix "database_" to all database-related parameters in your keylime.conf.')
                p_n_prefix = ''
            except NoOptionError:
                drivername = config.get(service, 'database_drivername')
                p_n_prefix = "database_"
                database = config.get(service, p_n_prefix + 'name')

            if drivername == 'sqlite':
                database_file = os.path.join(config.WORK_DIR, database)
                kl_dir = os.path.dirname(os.path.abspath(database_file))
                if not os.path.exists(kl_dir):
                    os.makedirs(kl_dir, 0o700)

                url = URL(
                    drivername=drivername,
                    username=None,
                    password=None,
                    host=None,
                    database=(database_file)
                )
                engine_args['connect_args'] = {'check_same_thread': False}

            else:
                url = URL(
                    drivername=drivername,
                    username=config.get(service, p_n_prefix + 'username'),
                    password=config.get(service, p_n_prefix + 'password'),
                    host=config.get(service, p_n_prefix + 'host'),
                    database=database
                )
                engine_args['pool_size'] = int(p_sz)
                engine_args['max_overflow'] = int(m_ovfl)

        # Enable DB debugging
        if config.DEBUG_DB and config.INSECURE_DEBUG:
            engine_args['echo'] = True

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
