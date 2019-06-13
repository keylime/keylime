import unittest
import sys
import os
from pathlib import Path

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = (f"{PACKAGE_ROOT}/keylime/")

# Custom imports
sys.path.insert(0, CODE_ROOT)

from keylime import keylime_sqlite

class Sqlite_Test(unittest.TestCase):

    def test_sql(self):
        # test invalid coldb
        cols_db = {
            'agent_ids': 'TEXT PRIMARY_KEY',
            }

        with self.assertRaisesRegex(Exception,'the primary key of the database must be agent_id'):
            _ = keylime_sqlite.KeylimeDB(None,cols_db,[],{})

        # testing
        db_filename = 'testdata.sqlite'

        if os.path.exists(db_filename):
            os.remove(db_filename)

        # in the form key, SQL type
        cols_db = {
            'agent_id': 'TEXT PRIMARY_KEY',
            'v': 'TEXT',
            'ip': 'TEXT',
            'port': 'INT',
            'operational_state': 'INT',
            'public_key': 'TEXT',
            'tpm_policy' : 'TEXT',
            'vtpm_policy' : 'TEXT',
            'metadata' : 'TEXT',
            'ima_whitelist' : 'TEXT',
            'revocation_key': 'TEXT',
            }

        # these are the columns that contain json data and need marshalling
        json_cols_db = ['tpm_policy','vtpm_policy','metadata','ima_whitelist']

        # in the form key : default value
        exclude_db = {
            'registrar_keys': '',
            'nonce': '',
            'b64_encrypted_V': '',
            'provide_V': True,
            'num_retries': 0,
            'pending_event': None,
            'first_verified':False,
            }
        db = keylime_sqlite.KeylimeDB(db_filename,cols_db,json_cols_db,exclude_db)

        json_body = {
            'v': 'vbaby',
            'agent_id': '209483',
            'cloudagent_ip': 'ipaddy',
            'cloudagent_port': '39843',
            'tpm_policy': '{"atpm":"1"}',
            'vtpm_policy': '{"abv":"1"}',
            'ima_whitelist': '{"abi":"1"}',
            'metadata': '{"cert_serial":"1"}',
            'operational_state': 0,
            'ip': "128.1.1.1.",
            'port': 2000,
            'revocation_key': '',
            'public_key': 'bleh',
            }

        json_body2 = {
            'v': 'vbaby',
            'agent_id': '2094aqrea3',
            'cloudagent_ip': 'ipaddy',
            'cloudagent_port': '39843',
            'tpm_policy': '{"a":"1"}',
            'vtpm_policy': '{"ab":"1"}',
            'ima_whitelist': '{"ab":"1"}',
            'metadata': '{"cert_serial":"1"}',
            'operational_state': 0,
            'ip': "128.1.1.1.",
            'port': 2000,
            'revocation_key': '',
            'public_key': 'bleh',
            }

        self.maxDiff=None

        #some DB testing stuff
        # test add/get
        db.add_agent('209483',json_body)
        got = db.get_agent(209483)
        self.assertEqual(json_body['metadata'], got['metadata'])

        # test disallowed overwrite
        self.assertEqual(db.add_agent('209483',json_body), None)

        # test update
        db.update_agent('209483','v','NEWVVV')
        got= db.get_agent(209483)
        self.assertEqual(got['v'], 'NEWVVV')

        # test invalid update
        with self.assertRaises(Exception):
            db.update_agent('209483','vee','NEWVVV')

        #test remove
        db.remove_agent('209483')
        self.assertEqual(db.get_agent_ids(),[])

        # test remove nothing
        self.assertEqual(db.remove_agent('209483'), False)

        # test get multiple ids
        db.add_agent('209483',json_body)
        db.add_agent('2094aqrea3',json_body2)
        self.assertEqual(db.get_agent_ids(),['209483','2094aqrea3'])

        #testing overwrite
        agent = db.get_agent('2094aqrea3')
        agent['agent_id']=209483
        agent['v']='OVERWRITTENVVVV'
        db.overwrite_agent(209483, agent)
        self.assertEqual(db.get_agent(209483)['v'],'OVERWRITTENVVVV')

        # test update all
        db.update_all_agents('operational_state', 2)

        self.assertEqual(db.get_agent(209483)['operational_state'], 2)
        self.assertEqual(db.get_agent('2094aqrea3')['operational_state'], 2)

        with self.assertRaises(Exception):
            db.update_all_agents('operational_stateaaaa', 2)

        # test count
        self.assertEqual(db.count_agents(), 2)

        # test print
        db.print_db()

        # test update all with json
        db.update_all_agents('vtpm_policy', '{"abv":"2"}')

        self.assertEqual(db.get_agent(209483)['vtpm_policy'], '{"abv":"2"}')
        self.assertEqual(db.get_agent('2094aqrea3')['vtpm_policy'], '{"abv":"2"}')

if __name__ == '__main__':
    unittest.main()