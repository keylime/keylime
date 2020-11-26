'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

import simplejson as json

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, PickleType, Text


Base = declarative_base()


class JSONPickleType(PickleType):
    impl = Text


class VerfierMain(Base):
    __tablename__ = 'verifiermain'
    agent_id = Column(String(80),
                      primary_key=True)
    v = Column(String(45))
    ip = Column(String(15))
    port = Column(Integer)
    operational_state = Column(Integer)
    public_key = Column(String(500))
    tpm_policy = Column(String(1000))
    vtpm_policy = Column(String(1000))
    meta_data = Column(String(200))
    allowlist = Column(Text(429400000))
    revocation_key = Column(String(2800))
    tpm_version = Column(Integer)
    accept_tpm_hash_algs = Column(JSONPickleType(pickler=json))
    accept_tpm_encryption_algs = Column(JSONPickleType(pickler=json))
    accept_tpm_signing_algs = Column(JSONPickleType(pickler=json))
    hash_alg = Column(String(10))
    enc_alg = Column(String(10))
    sign_alg = Column(String(10))
