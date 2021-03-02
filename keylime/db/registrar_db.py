'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

import json

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, PickleType, Text


Base = declarative_base()


class JSONPickleType(PickleType):  # pylint: disable=abstract-method
    impl = Text


class RegistrarMain(Base):
    __tablename__ = 'registrarmain'
    agent_id = Column(String(80),
                      primary_key=True)
    key = Column(String(45))
    aik_tpm = Column(String(500))
    ekcert = Column(String(2048))
    ek_tpm = Column(String(500))
    virtual = Column(Integer)
    active = Column(Integer)
    provider_keys = Column(JSONPickleType(pickler=json))
    regcount = Column(Integer)
