'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, PickleType, Text, LargeBinary
from sqlalchemy import schema

from keylime.json import JSONPickler


Base = declarative_base()


class JSONPickleType(PickleType):  # pylint: disable=abstract-method
    impl = Text


class VerfierMain(Base):
    __tablename__ = 'verifiermain'
    agent_id = Column(String(80),
                      primary_key=True)
    v = Column(String(45))
    ip = Column(String(15))
    verifier_id = Column(String(80))
    verifier_ip = Column(String(15))
    verifier_port = Column(Integer)
    port = Column(Integer)
    operational_state = Column(Integer)
    public_key = Column(String(500))
    tpm_policy = Column(JSONPickleType(pickler=JSONPickler))
    vtpm_policy = Column(JSONPickleType(pickler=JSONPickler))
    meta_data = Column(String(200))
    allowlist = Column(Text(429400000))
    ima_sign_verification_keys = Column(Text(429400000))
    mb_refstate = Column(Text(429400000))
    revocation_key = Column(String(2800))
    accept_tpm_hash_algs = Column(JSONPickleType(pickler=JSONPickler))
    accept_tpm_encryption_algs = Column(JSONPickleType(pickler=JSONPickler))
    accept_tpm_signing_algs = Column(JSONPickleType(pickler=JSONPickler))
    hash_alg = Column(String(10))
    enc_alg = Column(String(10))
    sign_alg = Column(String(10))
    boottime = Column(Integer)
    ima_pcrs = Column(JSONPickleType(pickler=JSONPickler))
    pcr10 = Column(LargeBinary)
    next_ima_ml_entry = Column(Integer)
    severity_level = Column(Integer, nullable=True)
    last_event_id = Column(String(200), nullable=True)
    learned_ima_keyrings = Column(JSONPickleType(pickler=JSONPickler))


class VerifierAllowlist(Base):
    __tablename__ = 'allowlists'
    __table_args__ = (
        schema.UniqueConstraint('name', name='uniq_allowlists0name'),
    )
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    tpm_policy = Column(Text())
    vtpm_policy = Column(Text())
    ima_policy = Column(Text(429400000))
