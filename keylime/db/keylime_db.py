'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError

from keylime import keylime_logging

logger = keylime_logging.init_logging('sql_session_manager')


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
            logger.error(f'Error creating SQL session manager {e}')
        return Session()
