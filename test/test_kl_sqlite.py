import unittest
import sys
import os

# Useful constants for the test
KEYLIME_DIR=os.getcwdu()+"/../keylime/"

# Custom imports
sys.path.insert(0, KEYLIME_DIR)
from keylime_sqlite import *

class Sqlite_Test(unittest.TestCase):
 
    def test_sql(self):
        # test invalid coldb
        cols_db = {
            'instance_ids': 'TEXT PRIMARY_KEY',
            }
        
        with self.assertRaisesRegexp(Exception,'the primary key of the database must be instance_id'):
            _ = KeylimeDB(None,cols_db,[],{})
            
        # testing
        db_filename = 'testdata.sqlite'
        
        if os.path.exists(db_filename):
            os.remove(db_filename)
            
        # in the form key, SQL type
        cols_db = {
            'instance_id': 'TEXT PRIMARY_KEY',
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
        db = KeylimeDB(db_filename,cols_db,json_cols_db,exclude_db)
        
        json_body = {
            'v': 'vbaby',
            'instance_id': '209483',
            'cloudnode_ip': 'ipaddy',
            'cloudnode_port': '39843',
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
            'instance_id': '2094aqrea3',
            'cloudnode_ip': 'ipaddy',
            'cloudnode_port': '39843',
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
        db.add_instance('209483',json_body)
        got= db.get_instance(209483)
        self.assertEqual(json_body['metadata'], got['metadata'])
        
        # test disallowed overwrite
        self.assertEqual(db.add_instance('209483',json_body), None)
        
        # test update
        db.update_instance('209483','v','NEWVVV')
        got= db.get_instance(209483)
        self.assertEqual(got['v'], 'NEWVVV')
        
        # test invalid update
        with self.assertRaises(Exception):
            db.update_instance('209483','vee','NEWVVV')
        
        #test remove
        db.remove_instance('209483')
        self.assertEqual(db.get_instance_ids(),[])
        
        # test remove nothing
        self.assertEqual(db.remove_instance('209483'), False)

        # test get multiple ids
        db.add_instance('209483',json_body)
        db.add_instance('2094aqrea3',json_body2)
        self.assertEqual(db.get_instance_ids(),['209483','2094aqrea3'])
    
        #testing overwrite
        instance = db.get_instance('2094aqrea3')
        instance['instance_id']=209483
        instance['v']='OVERWRITTENVVVV'
        db.overwrite_instance(209483, instance)
        self.assertEqual(db.get_instance(209483)['v'],'OVERWRITTENVVVV')
        
        # test update all
        db.update_all_instances('operational_state', 2)
        
        self.assertEqual(db.get_instance(209483)['operational_state'], 2)
        self.assertEqual(db.get_instance('2094aqrea3')['operational_state'], 2)
        
        with self.assertRaises(Exception):
            db.update_all_instances('operational_stateaaaa', 2)
            
        # test count
        self.assertEqual(db.count_instances(), 2)
        
        # test print
        db.print_db()
        
        # test update all with json
        db.update_all_instances('vtpm_policy', '{"abv":"2"}')
        
        self.assertEqual(db.get_instance(209483)['vtpm_policy'], '{"abv":"2"}')
        self.assertEqual(db.get_instance('2094aqrea3')['vtpm_policy'], '{"abv":"2"}')

if __name__ == '__main__':
    unittest.main()