"""
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
"""

import unittest

from sqlalchemy import create_engine

from keylime.db.keylime_db import SessionManager
from keylime.db.registrar_db import RegistrarMain

# BEGIN TEST DATA

test_data = {
    "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
    "ek_tpm": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0dLxdAABVJO6qxamjCMh
yhWZgiFHZHnPEe0tMFyK3fNVr/w8lX9r+QOLxLmkT0IdgsEYtGZGefbD+qQl4O1s
k25823Xzu5tEF8966rTdkfsv8CRrNaBLwWlnt/n+qjIoU3xZJMmR+mFfqTc3a6zV
mPOYJstFtM8r4b9HPCUq6Mte/J3Wx4FxI9R4UrCUyiAeH++0QapIxuEGsVIYs92n
GyvFQYBZFRU6cIt33iaqTrRCICJp+YblMnw54YJGAH2vTVQf6/fLAnQt5L1UfmTy
R/ZA6advx8soekSBOIAW7XmV8Xp9mSquIHZdSXMJlcn/B35PU3BdkUtIYm5JuGGt
PQIDAQAB
-----END PUBLIC KEY-----""",
    "aik_tpm": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0dLxdAABVJO6qxamjCMh
yhWZgiFHZHnPEe0tMFyK3fNVr/w8lX9r+QOLxLmkT0IdgsEYtGZGefbD+qQl4O1s
k25823Xzu5tEF8966rTdkfsv8CRrNaBLwWlnt/n+qjIoU3xZJMmR+mFfqTc3a6zV
mPOYJstFtM8r4b9HPCUq6Mte/J3Wx4FxI9R4UrCUyiAeH++0QapIxuEGsVIYs92n
GyvFQYBZFRU6cIt33iaqTrRCICJp+YblMnw54YJGAH2vTVQf6/fLAnQt5L1UfmTy
R/ZA6advx8soekSBOIAW7XmV8Xp9mSquIHZdSXMJlcn/B35PU3BdkUtIYm5JuGGt
PQIDAQAB
-----END PUBLIC KEY-----""",
    "ekcert": """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEMV64bDANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNTEwMjAxMzQ3NDNaFw0yNTEwMjAxMzQ3NDNaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALftPhYN
t4rE+JnU/XOPICbOBLvfo6iA7nuq7zf4DzsAWBdsZEdFJQfaK331ihG3IpQnlQ2i
YtDim289265f0J4OkPFpKeFU27CsfozVaNUm6UR/uzwA8ncxFc3iZLRMRNLru/Al
VG053ULVDQMVx2iwwbBSAYO9pGiGbk1iMmuZaSErMdb9v0KRUyZM7yABiyDlM3cz
UQX5vLWV0uWqxdGoHwNva5u3ynP9UxPTZWHZOHE6+14rMzpobs6Ww2RR8BgF96rh
4rRAZEl8BXhwiQq4STvUXkfvdpWH4lzsGcDDtrB6Nt3KvVNvsKz+b07Dk+Xzt+EH
NTf3Byk2HlvX+scCAwEAAaOCATswggE3MB0GA1UdDgQWBBQ4k8292HPEIzMV4bE7
qWoNI8wQxzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBABJ1+Ap3rNlxZ0FW0aIgdzktbNHlvXWNxFdYIBbM
OKjmbOos0Y4O60eKPu259XmMItCUmtbzF3oKYXq6ybARUT2Lm+JsseMF5VgikSlU
BJALqpKVjwAds81OtmnIQe2LSu4xcTSavpsL4f52cUAu/maMhtSgN9mq5roYptq9
DnSSDZrX4uYiMPl//rBaNDBflhJ727j8xo9CCohF3yQUoQm7coUgbRMzyO64yMIO
3fhb+Vuc7sNwrMOz3VJN14C3JMoGgXy0c57IP/kD5zGRvljKEvrRC2I147+fPeLS
DueRMS6lblvRKiZgmGAg7YaKOkOaEmVDMQ+fTo2Po7hI5wc=
-----END CERTIFICATE-----""",
    "virtual": 0,
    "active": int(False),
    "key": "R0xKMU5maWVEaHVxQ0poZUZhWm9yRVkyRHZZUkVIMFA=",
    "provider_keys": {},
    "regcount": 1,
    "ip": "127.0.0.1",
    "port": 9002,
}

agent_id = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

# END TEST DATA


class TestRegistrarDB(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        RegistrarMain.metadata.create_all(self.engine, checkfirst=True)
        self.session = SessionManager().make_session(self.engine)
        self.populate_agent()

    def populate_agent(self):
        self.session.add(RegistrarMain(**test_data))
        self.session.commit()

    def test_add_agent(self):
        agent = self.session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
        self.assertEqual(
            agent.ek_tpm,
            """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0dLxdAABVJO6qxamjCMh
yhWZgiFHZHnPEe0tMFyK3fNVr/w8lX9r+QOLxLmkT0IdgsEYtGZGefbD+qQl4O1s
k25823Xzu5tEF8966rTdkfsv8CRrNaBLwWlnt/n+qjIoU3xZJMmR+mFfqTc3a6zV
mPOYJstFtM8r4b9HPCUq6Mte/J3Wx4FxI9R4UrCUyiAeH++0QapIxuEGsVIYs92n
GyvFQYBZFRU6cIt33iaqTrRCICJp+YblMnw54YJGAH2vTVQf6/fLAnQt5L1UfmTy
R/ZA6advx8soekSBOIAW7XmV8Xp9mSquIHZdSXMJlcn/B35PU3BdkUtIYm5JuGGt
PQIDAQAB
-----END PUBLIC KEY-----""",
        )
        self.assertEqual(
            agent.aik_tpm,
            """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0dLxdAABVJO6qxamjCMh
yhWZgiFHZHnPEe0tMFyK3fNVr/w8lX9r+QOLxLmkT0IdgsEYtGZGefbD+qQl4O1s
k25823Xzu5tEF8966rTdkfsv8CRrNaBLwWlnt/n+qjIoU3xZJMmR+mFfqTc3a6zV
mPOYJstFtM8r4b9HPCUq6Mte/J3Wx4FxI9R4UrCUyiAeH++0QapIxuEGsVIYs92n
GyvFQYBZFRU6cIt33iaqTrRCICJp+YblMnw54YJGAH2vTVQf6/fLAnQt5L1UfmTy
R/ZA6advx8soekSBOIAW7XmV8Xp9mSquIHZdSXMJlcn/B35PU3BdkUtIYm5JuGGt
PQIDAQAB
-----END PUBLIC KEY-----""",
        )
        self.assertEqual(
            agent.ekcert,
            """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEMV64bDANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNTEwMjAxMzQ3NDNaFw0yNTEwMjAxMzQ3NDNaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALftPhYN
t4rE+JnU/XOPICbOBLvfo6iA7nuq7zf4DzsAWBdsZEdFJQfaK331ihG3IpQnlQ2i
YtDim289265f0J4OkPFpKeFU27CsfozVaNUm6UR/uzwA8ncxFc3iZLRMRNLru/Al
VG053ULVDQMVx2iwwbBSAYO9pGiGbk1iMmuZaSErMdb9v0KRUyZM7yABiyDlM3cz
UQX5vLWV0uWqxdGoHwNva5u3ynP9UxPTZWHZOHE6+14rMzpobs6Ww2RR8BgF96rh
4rRAZEl8BXhwiQq4STvUXkfvdpWH4lzsGcDDtrB6Nt3KvVNvsKz+b07Dk+Xzt+EH
NTf3Byk2HlvX+scCAwEAAaOCATswggE3MB0GA1UdDgQWBBQ4k8292HPEIzMV4bE7
qWoNI8wQxzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBABJ1+Ap3rNlxZ0FW0aIgdzktbNHlvXWNxFdYIBbM
OKjmbOos0Y4O60eKPu259XmMItCUmtbzF3oKYXq6ybARUT2Lm+JsseMF5VgikSlU
BJALqpKVjwAds81OtmnIQe2LSu4xcTSavpsL4f52cUAu/maMhtSgN9mq5roYptq9
DnSSDZrX4uYiMPl//rBaNDBflhJ727j8xo9CCohF3yQUoQm7coUgbRMzyO64yMIO
3fhb+Vuc7sNwrMOz3VJN14C3JMoGgXy0c57IP/kD5zGRvljKEvrRC2I147+fPeLS
DueRMS6lblvRKiZgmGAg7YaKOkOaEmVDMQ+fTo2Po7hI5wc=
-----END CERTIFICATE-----""",
        )
        self.assertEqual(agent.virtual, 0)
        self.assertEqual(agent.active, int(False))
        self.assertEqual(agent.key, "R0xKMU5maWVEaHVxQ0poZUZhWm9yRVkyRHZZUkVIMFA=")
        self.assertEqual(agent.provider_keys, {})
        self.assertEqual(agent.regcount, 1)
        self.assertEqual(agent.ip, "127.0.0.1")
        self.assertEqual(agent.port, 9002)

    def test_delete_agent(self):
        agent = self.session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
        self.session.query(RegistrarMain).filter_by(agent_id=agent_id).delete()
        self.session.commit()
        agent = self.session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
        self.assertIsNone(agent)

    def tearDown(self):
        self.session.close()
