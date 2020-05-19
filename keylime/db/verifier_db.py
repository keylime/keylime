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


class VerfierMain(Base):
    __tablename__ = 'verifiermain'
    agent_id = Column(String(80),
                      primary_key=True)
    v = Column(String)
    ip = Column(String(15))
    port = Column(Integer)
    operational_state = Column(Integer)
    public_key = Column(String)
    tpm_policy = Column(String)
    vtpm_policy = Column(String)
    meta_data = Column(String)
    ima_whitelist = Column(String)
    revocation_key = Column(String)
    tpm_version = Column(Integer)
    accept_tpm_hash_algs = Column(JSONPickleType(pickler=json))
    accept_tpm_encryption_algs = Column(JSONPickleType(pickler=json))
    accept_tpm_signing_algs = Column(JSONPickleType(pickler=json))
    hash_alg = Column(String)
    enc_alg = Column(String)
    sign_alg = Column(String)
