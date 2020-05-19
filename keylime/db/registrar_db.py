'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, PickleType, Text

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

Base = declarative_base()


class JSONPickleType(PickleType):
    impl = Text


class RegistrarMain(Base):
    __tablename__ = 'registrarmain'
    agent_id = Column(String(80),
                      primary_key=True)
    key = Column(String)
    aik = Column(String)
    ek = Column(String)
    ekcert = Column(String)
    virtual = Column(Integer)
    active = Column(Integer)
    provider_keys = Column(JSONPickleType(pickler=json))
    regcount = Column(Integer)
