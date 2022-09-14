"""
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
"""

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import joinedload

from keylime import json
from keylime.db.keylime_db import SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist

# BEGIN TEST DATA

test_data = {
    "v": "cf0B779EA1dkHVWfTxQuSLHNFeutYeSmVWe7JOFWzXg=",
    "ip": "127.0.0.1",
    "port": 9002,
    "operational_state": 1,
    "public_key": "",
    "tpm_policy": '{"22": ["0000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "ffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "15": ["0000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"], "mask": "0x408400"}',
    "meta_data": '{"cert_serial": 2, "subject": "/C=US/CN=d432fbb3-d2f1-4a97-9ef7-75bd81c00000/ST=MA/L=Lexington/O=MITLL/OU=53"}',
    "ima_sign_verification_keys": "",
    "revocation_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDs1onKjLZHDnqu\nnrsCb5aZohK2FU+jjU4NT23x1UzYzpFU9wBZ0avj+HeFYbQiAKanSbS7PvhjJMdE\naWMgRMgigr2K1xx+ZhBu4zTPFMy11msxMIL/HPROSYx/9wUZrhf4z/rBsuppFVs3\nKfKmQHuptjZX+D+m+nANO8WOILyW2+5YO5FNw1XJ3gVO6elJJ/CzQcYWIioONuTM\nQ+g8OQc+yTZruwedcSpOX56GpBImWUKXzTz3zoX7AlYxjEBjT86rxoBVXo3ZIwYx\n+mJk7NADN2qvLSXxTnLBxISHdsUDBP5DfurFQPhZC5oARN6/Y4zPESnhm8iwlG5o\n2ZjxVzphAgMBAAECggEBAKVKudImUJTY8yBp4aS6koXYymxQBUvlM8MwW1A7iK2L\nxXxiAtms7uVlJK1vWhOdFrKMS1mfgiVXpscFMkx0FKWZT4XVyaohu3hYlCOupYyH\nADrNW6+G2q7EwA0TLnkUuuBI7v4+y0DZydZ/LT2ApY31gIn21R3JjWh+/crK6DP0\nJO51hLO+z4GAMbWimRzA3lnYltUSJEvam3EHnj/pW+hlczjdI6AfJTWRWx6+gqP3\nRBvLcjBA9ZIx4JzYab5tnvwnd8ZzVItYBQJ8UhxzNsrSzEGguUEO4G/jYQTtYi6T\nufksmewcIClp48AfDThKSCMQXgFwpVI4EPxwmfd6Mt0CgYEA+i+2jjeFREMNam4p\nEBf5tmY2xvg3HXGgCjBfllepZQZHQatfv/kEqhFW497W+okyjTXflMR1TkjMKAqO\nahA+D1lItycPxsvTTiZ85KgrybbQT7Y+s2ET2f68wZh2XyiJIYE/MNi3ZclIBFaY\npyXicj0RIB6IY9PIHNgdEHI4casCgYEA8ldrcbWof8YpwJ6KFVuMvkYKniVF0aXH\nsQUWL/dyjBYIq/jg3Z4J+b0360DhZVpp1SaO4jFISxVMRzkDf3/gbKxH9F4a9Id8\nDmGH15v1ooKBYfkk7GwEB3AOY4gN3RMnWb1hxxhjsM9pmeTffqgqYzHYzv1ArjHe\ntYkjWOqPECMCgYBT//kXPuTrymeSuHHpCWO6Lg9uNqCqrh/BzAQMAlrJpJYAIn3/\ngqhiQXgfAg7EB5SFfPUYie2o3yBMwV6XleSAWsXjWKYfZQgJUTrVuvEYxNykJthe\nedWkd7cAeSQlRwLj0PVafSj2b+JSMpEGbd3d5Ur+scGxYsXpiVYY04DICQKBgBPZ\nhTtzHbIZkSHt2nGVZhnPst7xPp7FbW3adM7I/eDrjRpI8GI2p6qFDSd/0PZ0SWbk\nGZ/9WWaNAAp1aQvwdXlxQxOJAbw1vLuQ0Yefhqcg+WgE+DlFP688RnFwm3IYN4jq\nMjAUl1XMJ2IrlQLS02X8lz2dEMcz3oIQEY0e6UjxAoGAFeiOjFF2i4wRRUKx8kpb\nnBKRmFaMXdkeMV2IQALJ4skNNflf0YdDFVniFUyq9vfbq2drJSnMiy8Dvju0j5PC\n+MALz22fsNoIV2h6gz0i1lXiyVgpoAhYCbbPv0wO6iHKPBzH3Onv6BKrVMy1pnzh\n6QsfbhjzBfFg1Zxp/h1tBqA=\n-----END PRIVATE KEY-----\n",
    "accept_tpm_hash_algs": ["sha512", "sha384", "sha256", "sha1"],
    "accept_tpm_encryption_algs": ["ecc", "rsa"],
    "accept_tpm_signing_algs": ["ecschnorr", "rsassa"],
    "hash_alg": "",
    "enc_alg": "",
    "sign_alg": "",
    "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
    "verifier_id": "default",
    "verifier_ip": "127.0.0.1",
    "verifier_port": 8881,
}

test_allowlist_data = {
    "name": "test-allowlist",
    "tpm_policy": '{"22": ["0000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "ffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "15": ["0000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"], "mask": "0x408400"}',
    "ima_policy": '{"allowlist": {"/boot/System.map-5.1.17-300.fc30.x86_64": ["bdc084cc61c67dada53ff92c3235fbc774eace36aceb11967718399837e36485"], "/boot/vmlinuz-5.0.9-301.fc30.x86_64": ["187e65c35f449df145b57940cb73606623ab1eccc352f5b0d9b64c4d2ad3be58"], "/boot/initramfs-5.1.15-300.fc30.x86_64.img": ["7fb94b644d95de6ed2f70c247cf9a572027815b8f6a00b8c5f7b9fd2feef0ff1"], "/boot/config-5.0.9-301.fc30.x86_64": ["540f7b2732b8018be45dcfdf737fa6e51d9f5924d85b6c1987ddb4215260b49f"], "boot_aggregate": ["0000000000000000000000000000000000000000"]}, "exclude": ["/*"]}',
}

agent_id = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

TENANT_FAILED = 10

# END TEST DATA


class TestVerfierDB(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://")
        VerfierMain.metadata.create_all(self.engine, checkfirst=True)
        self.session = SessionManager().make_session(self.engine)
        self.populate_tables()

    def populate_tables(self):
        allowlist = VerifierAllowlist(**test_allowlist_data)
        self.session.add(allowlist)
        self.session.add(VerfierMain(**test_data, ima_policy=allowlist))
        self.session.commit()

    def test_01_add_allowlist(self):
        allowlist = self.session.query(VerifierAllowlist).filter_by(name="test-allowlist").one()
        self.assertEqual(allowlist.name, "test-allowlist")
        self.assertEqual(allowlist.tpm_policy, test_allowlist_data["tpm_policy"])
        self.assertEqual(allowlist.ima_policy, test_allowlist_data["ima_policy"])

    def test_02_add_agent(self):
        agent = (
            self.session.query(VerfierMain)
            .options(joinedload(VerfierMain.ima_policy))
            .filter_by(agent_id=agent_id)
            .first()
        )
        self.assertEqual(agent.v, "cf0B779EA1dkHVWfTxQuSLHNFeutYeSmVWe7JOFWzXg=")
        self.assertEqual(agent.port, 9002)
        self.assertEqual(
            agent.tpm_policy,
            '{"22": ["0000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "ffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"], "15": ["0000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"], "mask": "0x408400"}',
        )
        self.assertEqual(
            agent.ima_policy.ima_policy,
            test_allowlist_data["ima_policy"],
        )
        self.assertEqual(
            agent.revocation_key,
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDs1onKjLZHDnqu\nnrsCb5aZohK2FU+jjU4NT23x1UzYzpFU9wBZ0avj+HeFYbQiAKanSbS7PvhjJMdE\naWMgRMgigr2K1xx+ZhBu4zTPFMy11msxMIL/HPROSYx/9wUZrhf4z/rBsuppFVs3\nKfKmQHuptjZX+D+m+nANO8WOILyW2+5YO5FNw1XJ3gVO6elJJ/CzQcYWIioONuTM\nQ+g8OQc+yTZruwedcSpOX56GpBImWUKXzTz3zoX7AlYxjEBjT86rxoBVXo3ZIwYx\n+mJk7NADN2qvLSXxTnLBxISHdsUDBP5DfurFQPhZC5oARN6/Y4zPESnhm8iwlG5o\n2ZjxVzphAgMBAAECggEBAKVKudImUJTY8yBp4aS6koXYymxQBUvlM8MwW1A7iK2L\nxXxiAtms7uVlJK1vWhOdFrKMS1mfgiVXpscFMkx0FKWZT4XVyaohu3hYlCOupYyH\nADrNW6+G2q7EwA0TLnkUuuBI7v4+y0DZydZ/LT2ApY31gIn21R3JjWh+/crK6DP0\nJO51hLO+z4GAMbWimRzA3lnYltUSJEvam3EHnj/pW+hlczjdI6AfJTWRWx6+gqP3\nRBvLcjBA9ZIx4JzYab5tnvwnd8ZzVItYBQJ8UhxzNsrSzEGguUEO4G/jYQTtYi6T\nufksmewcIClp48AfDThKSCMQXgFwpVI4EPxwmfd6Mt0CgYEA+i+2jjeFREMNam4p\nEBf5tmY2xvg3HXGgCjBfllepZQZHQatfv/kEqhFW497W+okyjTXflMR1TkjMKAqO\nahA+D1lItycPxsvTTiZ85KgrybbQT7Y+s2ET2f68wZh2XyiJIYE/MNi3ZclIBFaY\npyXicj0RIB6IY9PIHNgdEHI4casCgYEA8ldrcbWof8YpwJ6KFVuMvkYKniVF0aXH\nsQUWL/dyjBYIq/jg3Z4J+b0360DhZVpp1SaO4jFISxVMRzkDf3/gbKxH9F4a9Id8\nDmGH15v1ooKBYfkk7GwEB3AOY4gN3RMnWb1hxxhjsM9pmeTffqgqYzHYzv1ArjHe\ntYkjWOqPECMCgYBT//kXPuTrymeSuHHpCWO6Lg9uNqCqrh/BzAQMAlrJpJYAIn3/\ngqhiQXgfAg7EB5SFfPUYie2o3yBMwV6XleSAWsXjWKYfZQgJUTrVuvEYxNykJthe\nedWkd7cAeSQlRwLj0PVafSj2b+JSMpEGbd3d5Ur+scGxYsXpiVYY04DICQKBgBPZ\nhTtzHbIZkSHt2nGVZhnPst7xPp7FbW3adM7I/eDrjRpI8GI2p6qFDSd/0PZ0SWbk\nGZ/9WWaNAAp1aQvwdXlxQxOJAbw1vLuQ0Yefhqcg+WgE+DlFP688RnFwm3IYN4jq\nMjAUl1XMJ2IrlQLS02X8lz2dEMcz3oIQEY0e6UjxAoGAFeiOjFF2i4wRRUKx8kpb\nnBKRmFaMXdkeMV2IQALJ4skNNflf0YdDFVniFUyq9vfbq2drJSnMiy8Dvju0j5PC\n+MALz22fsNoIV2h6gz0i1lXiyVgpoAhYCbbPv0wO6iHKPBzH3Onv6BKrVMy1pnzh\n6QsfbhjzBfFg1Zxp/h1tBqA=\n-----END PRIVATE KEY-----\n",
        )
        self.assertEqual(agent.accept_tpm_hash_algs, ["sha512", "sha384", "sha256", "sha1"])
        self.assertEqual(agent.verifier_id, "default")
        self.assertEqual(agent.verifier_ip, "127.0.0.1")
        self.assertEqual(agent.verifier_port, 8881)

    def test_03_count_agents(self):
        agent = self.session.query(VerfierMain.agent_id).count()
        self.assertEqual(agent, 1)

    def test_04_serialize_agent_uuids(self):
        uuids = self.session.query(VerfierMain.agent_id).all()
        self.assertEqual(json.dumps(uuids), f'[["{agent_id}"]]')

    def test_05_set_operation_state(self):
        self.session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update(
            {"operational_state": TENANT_FAILED}
        )
        self.session.commit()
        agent = self.session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        self.assertEqual(agent.operational_state, 10)

    def test_06_set_verifier_ip_port(self):
        self.session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update({"verifier_ip": "127.0.0.2"})
        self.session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update({"verifier_port": 8882})
        self.session.commit()
        agent = self.session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        self.assertEqual(agent.verifier_ip, "127.0.0.2")
        self.assertEqual(agent.verifier_port, 8882)

    def test_07_delete_agent(self):
        agent = self.session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        self.session.query(VerfierMain).filter_by(agent_id=agent_id).delete()
        self.session.commit()
        agent = self.session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        self.assertIsNone(agent)

    def test_08_delete_allowlist(self):
        # can't delete allowlists attached to agents
        with self.assertRaises(Exception) as context:
            self.session.query(VerifierAllowlist).filter_by(name="test-allowlist").delete()
        self.assertTrue("FOREIGN KEY constraint failed" in str(context.exception))

        # unassign this allowlist from the agent
        agent = self.session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        agent.ima_policy_id = None
        self.session.commit()
        # now delete
        self.session.query(VerifierAllowlist).filter_by(name="test-allowlist").delete()
        self.session.commit()
        allowlist = self.session.query(VerifierAllowlist).filter_by(name="test-allowlist").first()
        self.assertIsNone(allowlist)

    def tearDown(self):
        self.session.close()
