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

class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True, default=1)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    group_id = Column(Integer,  unique=True, nullable=False)
    role_id = Column(Integer,  unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username