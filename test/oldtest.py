'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''

import unittest
import threading
import tornado_requests
import os

import json
import base64
import configparser
import common
import crypto
import tempfile

import signal
import subprocess

import queue

import uuid
import time
import tenant


from distutils.dir_util import copy_tree
import shutil


sentinel=None
cv_process = None
cn_process = None
cn_process_list = []

queue = queue.Queue()
num_threads = 5



config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)
  
cloudverifier_port = config.get('general', 'cloudverifier_port')
cloudagent_port = config.get('general', 'cloudagent_port')
registrar_port = config.get('general', 'registrar_port')

cloudagent_ip = config.get('tenant', 'cloudagent_ip')
cloudverifier_ip = config.get('tenant', 'cloudverifier_ip')
registrar_ip = config.get('tenant', 'cloudverifier_ip')
tpm_policy = json.loads(config.get('tenant', 'tpm_policy'))
my_cert = config.get('tenant', 'my_cert')
ca_cert = config.get('tenant', 'ca_cert')
private_key = config.get('tenant', 'private_key')
test_num_cloudagents = config.getint('general','test_num_cloudagents')
test_duration = config.getint('general','test_duration')
# cv_persistence_filename = config.get('cloud_verifier', 'persistence_filename')
# en_persistence_filename = config.get('registrar', 'persistence_filename')
cv_persistence_filename = None
en_persistence_filename = None


K = None
U = None
V = None

def readKUV():        
    global K, U, V
    
    # read the keys in
    f = open('content_keys.txt','r')
    K = base64.b64decode(f.readline())
    U = base64.b64decode(f.readline())
    V = base64.b64decode(f.readline())
    f.close()

def text_callback(request, context):
    context.status_code = 402
    return '{}'

class Test(unittest.TestCase):
  
    cloudverifier_process = None
  
    @classmethod
    def setUpClass(cls):

        cls.test_table = {
            "test_cloudagent_tenant_get_nonce" : {
                "prerun_function"  : {"name":"launch_cloudagent", "argument": None},                             
                "state_change_functions": [

                    {
                        "function_name": "test_cloudagent_tenant_get_nonce",
                        "http_request_verb":"GET",
                        "http_request_ip": cloudagent_ip,
                        "http_request_port": cloudagent_port,
                        "http_request_query": {"nonce":"ThisIsThePasswordABC"},
                        "http_request_path": "/v1/quotes/tenant",
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"check_test_cloudagent_tenant_get_nonce"},
                    }
                ],
                "postrun_function"  : {"name":"kill_cloudagent", "argument": None},                                
            },
            "test_cloudagent_tenant_get_quote" : {
                "prerun_function"  : {"name":"launch_cloudagent", "argument": None},    
                "state_change_functions": [

                    {
                        "function_name": "test_cloudagent_tenant_get_quote",
                        "http_request_verb":"POST",
                        "http_request_ip": cloudagent_ip,
                        "http_request_port":cloudagent_port,
                        "http_request_path": "/v1/quotes/tenant",
                        "http_request_body": '{"encrypt_check": "K+oD4GfBMAdOFy94ZxTU2hB77tySSB75VVz2Zo4jN02txhNK2KiO5JhE1SRIUVASMZMW/VQUS9WgWdCUaJ+LOTWSuQ13alG4P4cLoamBr9c=","encrypted_key":"rBWIxK4i6zTl/M69Yyh2hmX+itDR9QCx4CIqmuRrEN3JAIUc2M+balr8gPD9r3Bs0OxYRC8/kcxBNo9Bsm93WZKwlmbZt2uVxhfaAqXwdGVpMBnM3bQnAEj1LIFoZZyQ48PVIdrEO4WW73Z2X3fplEFgOC3YT3lzluYgrn8iBkMRm+o2pJMdhynh6xLguszLX7qDOccPIIJch14ftWlsy6Ya9a6LHr9+hIfs4p2ATVVSl1wtUbf/ouNJdqUPAiFc4oXsg+kHQzWWiipjsAm871cA4wlvUb+/D4mFz1p3PRAK9hcICGwKoanWh8jbeuYnoqkch2EoHeLqayrisfNogg=="}',
                        "http_result_status_expected": 200,
                    }
                ],
                "postrun_function"  : {"name":"kill_cloudagent", "argument": None}, 
            }, 
            "test_cloudverifier_tenant_provide_v" : {
                #"prerun_function"  : {"name":"launch_cloudverifier", "argument": None},
                "state_change_functions": [

                    {
                        "function_name": "test_cloudverifier_tenant_provide_v",
                        #"pre_function"  : {"name":"do_mock_for_test_cloudverifier_tenant_provide_v", "argument": None},
                        "http_request_verb":"POST",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_request_body": '{"v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=","agent_id":"06480EC4-6BF3-4F00-8323-FE6AE5868297","cloudagent_ip":"127.0.0.1","cloudagent_port":"8882","tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}}',
                        "http_result_status_expected": 200,
                        #"concurrent_instances" : 10,
                        #"concurrent_new_thread_function" : "new_thread",
                        #"test_iterations" : 100,
                    },                    
                ],           
            },
            "test_concurrent_access" : {
                "prerun_function"  : {"name":"launch_cloudverifier", "argument": None},
                "state_change_functions": [

                    {
                        "function_name": "test_concurrent_access",
                        "http_request_verb":"POST",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_request_body": '{"v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=","agent_id":"06480EC4-6BF3-4F00-8323-FE6AE5868297","cloudagent_ip":"127.0.0.1","cloudagent_port":"8882","tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}}',
                        "http_result_status_expected": 200,
                        "concurrency" : {"instances": 5, "new_thread_function":"new_thread"},
                        "test_iterations" : 100,
                    },                    
                ],   
                "state_validation_functions": [
                    {
                        "function_name": "test_agent_id_list",
                        "http_request_verb":"GET",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        #"http_request_body": '{"v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=","agent_id":"06480EC4-6BF3-4F00-8323-FE6AE5868297","cloudagent_ip":"127.0.0.1","cloudagent_port":"8882","tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}}',
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"check_and_delete_all_entries", "argument": 500}
                    },                               
                ],
                "postrun_function"  : {"name":"kill_cloudverifier", "argument": None},              
            },
            "test_concurrent_cloudnodiness" : {
                #"prerun_function"  : {"name":"launch_cloudagents", "args": {'starting_port':9000, 'num_cloudagent_instances':250}},
                "prerun_function"  : {"name":"launch_cloudagents", "args": {'port_file':'cloudagent_port.txt', 'num_cloudagent_instances':test_num_cloudagents}},
                "state_change_functions": [
 
                    {
                        "pre_function" : {"name":"test_concurrent_cloudnodiness_modify_request", "argument": 500},
                        "function_name": "test_concurrent_cloudnodiness",
                        "http_request_verb":"POST",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_request_body": '{"v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=","agent_id":"C432FBB3-D2F1-4A97-9EF7-75BD81C00000","cloudagent_ip":"cloudagent_ip.txt","cloudagent_port":"cloudagent_port.txt","tpm_policy": {"22":"ffffffffffffffffffffffffffffffffffffffff","16":"0000000000000000000000000000000000000000"} }',
                        "http_result_status_expected": 200,
                        "test_iterations" : test_num_cloudagents,
                        "post_function" : {"name":"test_concurrent_cloudnodiness_reset_request", "args": {"ip_file": "cloudagent_ip.txt","port_file":"cloudagent_port.txt"} },
                    },                    
                ],   
                "postrun_function"  : {"name":"kill_cloudagents_after_delay", "args": {'sleep': test_duration, 'port_file':'cloudagent_port.txt', 'num_cloudagent_instances':test_num_cloudagents} },              
            },
            "test_full_integration_happy_path" : {
                #"prerun_function"  : {"name":"launch_required_servers", "argument": None},
                "state_change_functions": [

                    {
                        "function_name": "do_cloudagent_part",
                        "http_request_verb":"GET",
                        "http_request_ip": cloudagent_ip,
                        "http_request_port":cloudagent_port,
                        "http_request_path": "/v1/quotes/tenant",
                        "http_request_query": {"nonce":"ThisIsThePasswordABC"},
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"provide_e"},
                        #"concurrent_new_thread_function" : "new_thread",
                        #"test_iterations" : 100,
                    },   
                    {
                        "function_name": "do_cloudverifier_part",
                        "http_request_verb":"POST",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_request_body": '{"v": "XrNfEiODfu1fdXGtWbA+Wk02UhBxx1jTq7zhbC54ROA=","agent_id":"C432FBB3-D2F1-4A97-9EF7-75BD81C866E9","cloudagent_ip":"127.0.0.1","cloudagent_port":"8882","tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}}',
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"check_test_sleep", "argument": 5},
                        #"concurrent_new_thread_function" : "new_thread",
                        #"test_iterations" : 100,
                    },                    
                ], 
                #"postrun_function"  : {"name":"kill_required_servers", "argument": None},             
            }, 
            "test_persistance_file_load" : {
                "prerun_function"  : {"name":"launch_cloudverifier", "args": '{"06480EC4-6BF3-4F00-8323-FE6AE5868297": {"tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}, "ip": "127.0.0.1", "port": "8882", "v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU="}}'},
                "state_change_functions": [

                    {
                        "function_name": "test_persistance_file_load",
                        "http_request_verb":"GET",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"check_test_persistance_file_load", "argument": "06480EC4-6BF3-4F00-8323-FE6AE5868297"},

                    },                    
                ], 
                "postrun_function"  : {"name":"kill_cloudverifier", "argument": None},             
            },              
            "test_persistance_file_write" : {
                "prerun_function"  : {"name":"launch_cloudverifier", "args": '{}'},
                "state_change_functions": [
                    {
                        "function_name": "test_persistance_file_write",
                        "http_request_verb":"POST",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_request_body": '{"v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=","agent_id":"06480EC4-6BF3-4F00-8323-FE6AE5868297","cloudagent_ip":"127.0.0.1","cloudagent_port":"8882","tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}}',
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"check_test_persistance_file_write", "argument": "06480EC4-6BF3-4F00-8323-FE6AE5868297"},
                    },                     
                ], 
                "postrun_function"  : {"name":"kill_cloudverifier", "argument": None},            
            },
            "test_persistance_file_bad" : {
                "prerun_function"  : {"name":"launch_cloudverifier", "args": '{'},
            }, 
            "test_persistance_file_empty" : {
                "prerun_function"  : {"name":"launch_cloudverifier", "args": ''},
                "state_change_functions": [
                    {
                        "function_name": "test_persistance_file_empty",
                        "http_request_verb":"GET",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"test_check_persistance_file_empty", "argument": None},
                    },                    
                ], 
                "postrun_function"  : {"name":"kill_cloudverifier", "argument": None},               
            },
            "test_persistance_file_nonexistent" : {
                "prerun_function"  : {"name":"launch_cloudverifier", "args": None},
                "state_change_functions": [
                    {
                        "function_name": "test_persistance_file_nonexistent",
                        "http_request_verb":"GET",
                        "http_request_ip": cloudverifier_ip,
                        "http_request_port":cloudverifier_port,
                        "http_request_path": "/v1/instances",
                        "http_result_status_expected": 200,
                        "check_function" : {"name":"test_check_persistance_file_empty", "argument": None},
                    },                    
                ], 
                "postrun_function"  : {"name":"kill_cloudverifier", "argument": None},                
            },                                     
        }

    def test_concurrent_cloudnodiness(self):
        self.execute_test_definition() 
    def test_cloudagent_tenant_get_nonce(self):
        self.execute_test_definition()        
    def test_cloudagent_tenant_get_quote(self):
        self.execute_test_definition() 
    def test_cloudverifier_tenant_provide_v(self):
        self.execute_test_definition()
    def test_concurrent_access(self):
        self.execute_test_definition()  
    def test_full_integration_happy_path(self):
        self.execute_test_definition()
    def test_persistance_file_load(self):
        self.execute_test_definition()
    def test_persistance_file_write(self):
        self.execute_test_definition() 
    def test_persistance_file_bad(self):
        self.execute_test_definition() 
    def test_persistance_file_empty(self):
        self.execute_test_definition() 
    def test_persistance_file_nonexistent(self):
        self.execute_test_definition() 

        
    def test_cloudagent_cloud_verifier_get_quote(self):
        pass  

    def check_test_sleep(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        time.sleep(argument)

#'{"v": "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=","agent_id":"06480EC4-6BF3-4F00-8323-FE6AE5868297","cloudagent_ip":"127.0.0.1","cloudagent_port":"8882","tpm_policy": {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}}',

    def read_line_in_file(self, infile, line_number):
        with open(infile) as fp:
            for i, line in enumerate(fp):
                if i == line_number:
                    return line
    def sleep_for_a_while(self, argument):
        time.sleep(float(argument))

    def test_concurrent_cloudnodiness_modify_request(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)
        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                request_body = test_functions.get("http_request_body")
                try:
                    json_request_body = json.loads(request_body)
                    
                    tmpp_policy = json_request_body['tpm_policy']
                    
                    mask = 0
                    for key in list(tmpp_policy.keys()):
                        if key.isdigit() :
                            mask = mask + (1<<int(key))

                    mask_str = "0x%X"%(mask)
                    tmpp_policy['mask'] = mask_str
                    json_request_body['tpm_policy'] = tmpp_policy
                    
                    cloudagent_ip = json_request_body['cloudagent_ip']                                      
                    if cloudagent_ip.endswith('.txt'):
                        cloudagent_ip_file = cloudagent_ip
                        cloudagent_ip_read_from_file = self.read_line_in_file(cloudagent_ip_file, test_iteration)
                        json_request_body['cloudagent_ip'] = cloudagent_ip_read_from_file.strip()  
                             
 
                    cloudagent_port = json_request_body['cloudagent_port']                                      
                    if cloudagent_port.endswith('.txt'):
                        cloudagent_port_file = cloudagent_port
                        cloudagent_port_read_from_file = self.read_line_in_file(cloudagent_port_file, test_iteration)
                        json_request_body['cloudagent_port'] = cloudagent_port_read_from_file.strip() 

#                     parser = ConfigParser.RawConfigParser()
#                     parser.read(common.CONFIG_FILE)
#                     test_agent_uuid = parser.get('general', 'agent_uuid')
                    
                    test_agent_uuid = json_request_body['agent_id']
                    
                    
                    port_string_length = len(str(json_request_body['cloudagent_port']))
                    contrived_uuid = test_agent_uuid[:-port_string_length]
                    contrived_uuid = contrived_uuid + str(json_request_body['cloudagent_port'])   
                    json_request_body['agent_id'] = contrived_uuid
                        
                    test_functions['http_request_body'] = json.dumps(json_request_body)        
                                                           
                    
                except Exception as e:
                    self.fail("Problem in test_concurrent_cloudnodiness_modify_request() replacing cloudagent_ip or cloudagent_port.  Error: %s"%e)         

    def test_concurrent_cloudnodiness_reset_request(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):

        #time.sleep(2)
        
        test_record = self.test_table.get(test_method_name)
        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                request_body = test_functions.get("http_request_body")
                try:
                    json_request_body = json.loads(request_body)
                    
                    #reset the request body to file arguments for next iteration
                    json_request_body['cloudagent_ip'] =  argument["ip_file"]                                
                    json_request_body['cloudagent_port'] = argument["port_file"]

                    test_functions['http_request_body'] = json.dumps(json_request_body)  

                except Exception as e:
                    self.fail("Problem in test_concurrent_cloudnodiness_modify_request() replacing cloudagent_ip or cloudagent_port.  Error: %s"%e) 


    def test_check_persistance_file_empty(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)
        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                target_body = test_functions.get("http_result_body_actual")
                try:
                    jsondecoded = json.loads(target_body)
                    # test to make sure these two keys (and values) are in the return
                    if len(jsondecoded) != 0:
                        self.fail("Expected empty persistence file to replace non existent persistence file on startup.") 
                except Exception as e:
                    self.fail("Problem reading persistence file after replacement of empty persistence file.  Error: %s"%e) 
                     
    def check_test_persistance_file_write(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)
        uuid_str = argument
        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                try:
                    with open(cv_persistence_filename, "r") as persistance_file:    
                        file_contents = persistance_file.read()
    
                        json_content = json.loads(file_contents)
                        if len(json_content) != 1 or json_content.get(uuid_str) is None:
                            self.fail("Unexpected persistence file contents.")
                except Exception as e:
                    self.fail("Problem reading persistence file after POST.  Error: %s"%e)  
                try:                                                
                    with open(cv_persistence_filename + ".bak", "r") as backup_persistance_file:    
                        backup_file_contents = backup_persistance_file.read()
    
                        json_backup_content = json.loads(backup_file_contents)
                        if len(json_backup_content) != 0:
                            self.fail("Unexpected backup persistence file contents.")                          
                except Exception as e:
                    self.fail("Problem reading backup persistence file after POST.  Error: %s"%e)                          

                    
                    
    def check_test_persistance_file_load(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)
        uuid_str = argument
        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                target_body = test_functions.get("http_result_body_actual")
                jsondecoded = json.loads(target_body)
                # test to make sure these two keys (and values) are in the return
                if len(jsondecoded) != 1 or jsondecoded.get(uuid_str) is None :
                    self.fail("Expected " + uuid_str + " to be in the list of active agent_ids")   

#     def do_mock_for_test_cloudverifier_tenant_provide_v(self, argument):
#         global text_callback
#         nonce = tpm_initialize.random_password(20)
#         tpm_policy = {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff" }
#         #theurl = 'http://' + cloudagent_ip + ':' + cloudagent_port + "/v1/quotes/cloudverifier" + "?nonce=" + nonce + "&mask=" + tpm_policy['mask']
#         theurl = 'http://' + cloudagent_ip + ':' + cloudagent_port + "/v1/quotes/cloudverifier" 
#         with requests_mock.Mocker(real_http=True) as m:
#             m.get(requests_mock.ANY, text=text_callback)       

    def provide_e(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)

        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                response_body = test_functions.get("http_result_body_actual")
                jsondecoded = json.loads(response_body)
                
                public_key = jsondecoded.get("pubkey")
                quote = jsondecoded.get("quote")
                
                # test to make sure these two keys (and values) are in the return
                if public_key == None or quote == None:
                    self.fail("Expected both pubkey and quote arguments." )
                else:
                    
                    mytenant = tenant.Tenant()
    
                    # command line options can overwrite config values
                    mytenant.cloudagent_ip = cloudagent_ip
                    mytenant.cloudverifier_ip = cloudverifier_ip
                    mytenant.agent_uuid = "C432FBB3-D2F1-4A97-9EF7-75BD81C866E9"
                    
                    if mytenant.validate_tpm_quote(public_key, quote): 
                        # encrypt U with the public key
                        global U, K
                        
                        encrypted_U = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key),str(U))
                        encrypt_check = crypto.do_hmac(K,mytenant.agent_uuid)
                        b64_encrypted_u = base64.b64encode(encrypted_U)
                        data = {
                                  'encrypted_key': b64_encrypted_u,
                                  'encrypt_check': encrypt_check
                                }
                        u_json_message = json.dumps(data)
                        
                        #post encrypted U back to Cloud Agent
                        response = tornado_requests.request("POST", "http://%s:%s/v1/quotes/tenant"%(cloudagent_ip,cloudagent_port),data=u_json_message)
                        
                        if response.status_code != 200:
                            self.fail("Posting of Encrypted U to the Cloud Agent failed with response code %d" %response.status_code )                 
                    else:
                        self.fail("TPM Quote from cloud agent is invalid for nonce: %s"%self.nonce )                                

    def check_test_cloudagent_tenant_get_nonce(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)

        #perform each of the test functions and store the results
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                target_body = test_functions.get("http_result_body_actual")
                jsondecoded = json.loads(target_body)
                # test to make sure these two keys (and values) are in the return
                if jsondecoded.get("pubkey") == None or jsondecoded.get("quote") == None:
                    self.fail("Expected both pubkey and quote arguments." )     

    def check_validate_test_cloudverifier_tenant_provide_v(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)

        #lookup test data and compare the results to canned values
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                target_body = test_functions.get("http_result_body_actual")
                jsondecoded = json.loads(target_body)
    
                v = jsondecoded.get("v")
                ip = jsondecoded.get("ip")  
                port = jsondecoded.get("port")
                tpm_policy = jsondecoded.get("tpm_policy")  

                if v is None or v !=  "nsRIy93UeeAi3GhAxpEcMH6R7OmaB7ArBdn2bEgyEwU=":
                    self.fail("Returned v from instance 06480EC4-6BF3-4F00-8323-FE6AE5868297 was not correct.")     
                if ip is None or ip !=  "127.0.0.1":
                    self.fail("Returned ip from instance 06480EC4-6BF3-4F00-8323-FE6AE5868297 was not correct.")     
                if port is None or port !=  "8882":
                    self.fail("Returned port from instance 06480EC4-6BF3-4F00-8323-FE6AE5868297 was not correct.")  
                if tpm_policy is None or tpm_policy !=  {"00": "0000000000000000000000000000000000000000", "mask": "0x400801", "22": "ffffffffffffffffffffffffffffffffffffffff"}:
                    self.fail("Returned tpm_policy from instance 06480EC4-6BF3-4F00-8323-FE6AE5868297 was not correct.") 
                       
    def check_and_delete_all_entries(self, test_method_name, test_function_name, state_change_or_validation, test_iteration, argument):
        test_record = self.test_table.get(test_method_name)

        #lookup test data and compare the results to canned values
        for test_functions in test_record[state_change_or_validation]:
            if test_functions.get("function_name") == test_function_name:
                target_body = test_functions.get("http_result_body_actual")
                agent_id_list = json.loads(target_body)
                
                expected_len = argument
                actual_len = len(agent_id_list)
                if actual_len != expected_len:
                    self.fail("Expected " +  str(expected_len) +" instance id's but received " + str(actual_len))  
                
                for agent_id in agent_id_list:
                    params = {
                        'agent_id': agent_id,
                        }
                    try:  
                        response = tornado_requests.request("DELETE",
                        "http://" + cloudverifier_ip + ":" + cloudverifier_port + "/v1/instances",
                        params=params)  
                        
                        if response.status_code != 200:
                            self.fail("Delete of agent_id " + agent_id + " failed.")  
  
                    except Exception as e:
                        self.fail("Delete of agent_id " + agent_id + " failed with exception: %s"%e)                    
                       
    

    def execute_the_test(self, setup_or_state_change_or_validation, test_functions, test_iteration ):          

        # call the pre_function
        pre_function = test_functions.get("pre_function")
        if pre_function is not None:
            pre_function_name = pre_function.get('name')
            pre_function_args = pre_function.get('args')
            function_return = getattr(self, pre_function_name)(self._testMethodName, test_functions["function_name"], setup_or_state_change_or_validation, test_iteration, pre_function_args) #self._testMethodName, test_functions["function_name"], setup_or_state_change_or_validation, check_argument
            if function_return == False:
                self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ":" + pre_function_name + " pre_function failure, test aborted." )

        full_url = "http://" + test_functions.get("http_request_ip") + ":" + test_functions.get("http_request_port") + test_functions.get("http_request_path")  
        http_request_body_tag = test_functions.get("http_request_body") 
        http_request_body_file_tag = test_functions.get("http_request_body_file")
        if http_request_body_tag != None and http_request_body_file_tag != None :
            self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + " contains both http_request_body and http_request_body_file tags." )
        
        thedata = ''
        if http_request_body_tag == None and http_request_body_file_tag != None:
            thedata = open(http_request_body_file_tag).read()
        else:
            thedata=http_request_body_tag
        verb =  test_functions.get("http_request_verb") 
        query = test_functions.get("http_request_query","") 
        test_functions.get("http_request_header")
        req_header = test_functions.get("http_request_header")
        
        response = tornado_requests.request(verb, full_url, 
            params=query, 
            data=thedata, 
            headers=req_header)
            
        temp = tempfile.TemporaryFile()
        for chunk in response.iter_content(1024):
            temp.write(chunk)
        
        temp.seek(0)
        # copy the results for future checking
        test_functions["http_result_status_actual"] = response.status_code
        test_functions["http_result_header_actual"] = response.headers
        test_functions["http_result_body_actual"] = temp.read()
        #validate response status
        if test_functions["http_result_status_actual"] != test_functions["http_result_status_expected"]:
            self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + " expected " + str(test_functions["http_result_status_expected"]) + " but received " + str(test_functions["http_result_status_actual"])) # reset the file marker for reading
        #validate response headers
        if test_functions.get("http_result_header_expected") is not None and not (all(item in list(response.headers.items()) for item in list(test_functions["http_result_header_expected"].items()))):
            self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ", didn't receive expected headers.")
        #validate (shallow) response body
        if test_functions.get("http_result_body_expected") is not None and json.loads(test_functions.get("http_result_body_expected")) != json.loads(test_functions.get("http_result_body_actual")):
            self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ", didn't receive exact expected result body.")
        #validate (deep) response body
        check_function = test_functions.get("check_function")
        if check_function is not None:
            check_argument = check_function.get("argument")
            if getattr(self, check_function["name"])(self._testMethodName, test_functions["function_name"], setup_or_state_change_or_validation, test_iteration, check_argument):
                self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ", didn't receive exact expected result body.")

        # call the post_function
        post_function = test_functions.get("post_function")
        if post_function is not None:
            post_function_name = post_function.get('name')
            post_function_args = post_function.get('args')
            function_return = getattr(self, post_function_name)(self._testMethodName, test_functions["function_name"], setup_or_state_change_or_validation, test_iteration, post_function_args)
            if function_return == False:
                self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ":" + post_function_name + " post_function failure, test aborted." )
        
        temp.close()


    def request_task(self, queue, setup_or_state_change_or_validation, test_functions, test_iteration):
        try:
            # Table data does not provide ability to inject unique agent_id's for each concurrent instance.
            # The queue stores unique agent_id objects, injected by the new_thread function.
            # Get the agent_id from the Queue and modify the original table data to change the agent_id to something unique.
            http_request_body_tag = test_functions.get("http_request_body") 
            http_request_body_file_tag = test_functions.get("http_request_body_file")
            if http_request_body_tag != None and http_request_body_file_tag != None :
                self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + " contains both http_request_body and http_request_body_file tags." )
            
            thedata = ''
            if http_request_body_tag == None and http_request_body_file_tag != None:
                thedata = open(http_request_body_file_tag).read()
            else:
                thedata=http_request_body_tag

            the_uid = queue.get()
            jsondata = json.loads(thedata)
            jsondata['agent_id'] = the_uid
            newdata = json.dumps(jsondata)
            
            # call the inline task passing the new data with the unique agent_id
            self.execute_the_test(setup_or_state_change_or_validation, test_functions, test_iteration )

        except Exception as e:
            self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ", unexpected exception error: %s"%e )    
        finally: 
            queue.task_done()
            
    def modify_persistence_file(self, argument):
        string_to_write = None
        if isinstance(argument, dict):
            string_to_write = json.dumps(argument)
        elif isinstance(argument, str):
            string_to_write = argument
        elif isinstance(argument, file):
            string_to_write = argument.read()
            argument.close()
        elif argument is None:
            if os.path.isfile(cv_persistence_filename):
                os.remove(cv_persistence_filename)   
                         
        if string_to_write is not None:       
            with open(cv_persistence_filename, "w") as persistance_file:    
                persistance_file.write(string_to_write)
            
        backup_file_name = cv_persistence_filename + ".bak"
        if os.path.isfile(backup_file_name):
            os.remove(backup_file_name)

    def launch_cloudverifier(self, argument):

        readKUV()
        
        #modify the persistence file per the passed argument
        if argument is not None:
            string_to_write = self.modify_persistence_file(argument)
            
        global cv_process 
        cv_process = subprocess.Popen("python cloud_verifier.py", shell=True) 
        time.sleep(1)
        return True

    def overwrite_config_file(self, path, section, option, value):
        parser = configparser.RawConfigParser()
        parser.read(path)
        
        
        parser.set(section, option, value)
        
        # Writing our configuration file to 'example.ini'
        with open(path, 'wb') as configfile:
            parser.write(configfile)


    def launch_cloudagents(self, argument):
        
        
        #self.launch_cloudverifier(None)
        port_file = argument.get('port_file')
        cloudagent_start_port = argument.get('starting_port')
        num_cloudagent_instances =  argument['num_cloudagent_instances']
        
        if cloudagent_start_port is not None:

            parser = configparser.RawConfigParser()
            parser.read(common.CONFIG_FILE)
            original_cloudagent_port = parser.get('general', 'cloudagent_port')
            test_agent_uuid = parser.get('general', 'agent_uuid')
      
      
            for cn in range(num_cloudagent_instances): 
                new_dir = r'../cloudagent_on_port_' + str(cloudagent_start_port)
                config_file_path = new_dir + "/keylime.conf"
                copy_tree('.', new_dir)
                shutil.copyfile(common.CONFIG_FILE, config_file_path)
                if not os.path.isdir(new_dir):
                    os.mkdir(new_dir)
                #shutil.copyfile(r'../keylime.conf', new_dir + r'/keylime.conf')
                self.overwrite_config_file(config_file_path, 'general', 'cloudagent_port', str(cloudagent_start_port))
                port_string_length = len(str(cloudagent_start_port))
                contrived_uuid = test_agent_uuid[:-port_string_length]
                contrived_uuid = contrived_uuid + str(cloudagent_start_port)
                self.overwrite_config_file(config_file_path, 'general', 'agent_uuid', contrived_uuid)  
                          
                cn_process_list.append(subprocess.Popen("python cloud_agent.py", shell=True, cwd=new_dir, preexec_fn=os.setsid).pid) 
                cloudagent_start_port = cloudagent_start_port + 1
                #time.sleep(2)
    
            self.overwrite_config_file(common.CONFIG_FILE, 'general', 'cloudagent_port', str(original_cloudagent_port))
            
        elif port_file is not None:

            parser = configparser.RawConfigParser()
            parser.read(common.CONFIG_FILE)
            original_cloudagent_port = parser.get('general', 'cloudagent_port')
            test_agent_uuid = parser.get('general', 'agent_uuid')
      
      
            for cn in range(num_cloudagent_instances): 
                cloudagent_port_read_from_file = self.read_line_in_file(port_file, cn).strip()
                
                new_dir = r'../cloudagent_on_port_' + cloudagent_port_read_from_file
                config_file_path = new_dir + "/keylime.conf"
                copy_tree('.', new_dir)
                shutil.copyfile(common.CONFIG_FILE, config_file_path)
                if not os.path.isdir(new_dir):
                    os.mkdir(new_dir)
                #shutil.copyfile(r'../keylime.conf', new_dir + r'/keylime.conf')
                self.overwrite_config_file(config_file_path, 'general', 'cloudagent_port', cloudagent_port_read_from_file)
                port_string_length = len(cloudagent_port_read_from_file)
                contrived_uuid = test_agent_uuid[:-port_string_length]
                contrived_uuid = contrived_uuid + cloudagent_port_read_from_file
                self.overwrite_config_file(config_file_path, 'general', 'agent_uuid', contrived_uuid)  
                          
                cn_process_list.append(subprocess.Popen("python cloud_agent.py", shell=True, cwd=new_dir, preexec_fn=os.setsid).pid) 
                cloudagent_port = int(cloudagent_port_read_from_file) + 1
                #time.sleep(2)
    
            self.overwrite_config_file(common.CONFIG_FILE, 'general', 'cloudagent_port', str(original_cloudagent_port))            
        print("done creating cloud agents, waiting for them to start...")
        time.sleep(10)
        print("starting test...")
        
        
    def kill_cloudagents_after_delay(self, argument):
        
        sleep_time = argument.get('sleep')
        time.sleep(sleep_time)
        

        
        #self.launch_cloudverifier(None)
        port_file = argument.get('port_file')
        cloudagent_start_port = argument.get('starting_port')
        num_cloudagent_instances =  argument['num_cloudagent_instances']
        
        if cloudagent_start_port is not None:

            parser = configparser.RawConfigParser()
            parser.read(common.CONFIG_FILE)

      
      
            for cn in range(num_cloudagent_instances): 
                new_dir = r'../cloudagent_on_port_' + str(cloudagent_start_port)
                shutil.rmtree(new_dir)
                cloudagent_port = cloudagent_start_port + 1


            
        elif port_file is not None:

            parser = configparser.RawConfigParser()
            parser.read(common.CONFIG_FILE)
            test_agent_uuid = parser.get('general', 'agent_uuid')
      
      
            for cn in range(num_cloudagent_instances): 
                cloudagent_port_read_from_file = self.read_line_in_file(port_file, cn).strip()
                port_string_length = len(cloudagent_port_read_from_file)
                contrived_uuid = test_agent_uuid[:-port_string_length]
                contrived_uuid = contrived_uuid + cloudagent_port_read_from_file
                params = {
                    'agent_id': contrived_uuid,
                    }
                try:
                    print(("Sending #" + str(cn) + " DELETE request to CV for uuid: " +  contrived_uuid))
                    response = tornado_requests.request("DELETE",
                    "http://" + cloudverifier_ip + ":" + cloudverifier_port + "/v1/instances",
                    params=params)  
                    
                    if response.status_code != 200:
                        self.fail("Delete of agent_id " + contrived_uuid + " failed.")  
                
                except Exception as e:
                    self.fail("Delete of agent_id " + contrived_uuid + " failed with exception: %s"%e)  
                

            for cn in range(num_cloudagent_instances): 
                cloudagent_port_read_from_file = self.read_line_in_file(port_file, cn).strip()
                new_dir = r'../cloudagent_on_port_' + cloudagent_port_read_from_file
                shutil.rmtree(new_dir)

        for the_pid in cn_process_list:
            print(("killing pid" + str(the_pid)))
            os.killpg(the_pid, signal.SIGTERM)

    def kill_cloudverifier(self, argument):
        cv_process.kill()
        return True

    def launch_cloudagent(self, argument):
        
        readKUV()
        
        global cn_process 
        cn_process = subprocess.Popen("python cloud_agent.py", shell=True) 
        time.sleep(1)
        return True

    def kill_cloudagent(self, argument):
        cn_process.kill()
        return True

    def launch_required_servers(self, argument):
        self.launch_cloudagent(argument)
        self.launch_cloudverifier(argument)
        return True

    def kill_required_servers(self, argument):
        self.kill_cloudagent(argument)
        self.kill_cloudverifier(argument)
        return True
        
    def new_thread(self, args):
        #create a new uuid, and place it in the queue
        the_global_queue = args[0]
        new_uuid = str(uuid.uuid4())
        the_global_queue.put(new_uuid)
        
        return threading.Thread(target=self.request_task,args=args)

    def execute_test_function_set(self, setup_or_state_change_or_validation):
        # look up the test record
        test_record = self.test_table.get(self._testMethodName)
        #perform each of the test functions and store the results
        change_or_validation = test_record.get(setup_or_state_change_or_validation)
        if change_or_validation is not None:
            for test_functions in test_record[setup_or_state_change_or_validation]:

                
#                 full_url = "http://" + test_functions.get("http_request_ip") + ":" + test_functions.get("http_request_port") + test_functions.get("http_request_path")  
#                 http_request_body_tag = test_functions.get("http_request_body") 
#                 http_request_body_file_tag = test_functions.get("http_request_body_file")
#                 if http_request_body_tag != None and http_request_body_file_tag != None :
#                     self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + " contains both http_request_body and http_request_body_file tags." )
# 
#                 thedata = ''
#                 if http_request_body_tag == None and http_request_body_file_tag != None:
#                     thedata = open(http_request_body_file_tag).read()
#                 else:
#                     thedata=http_request_body_tag
#                 verb =  test_functions.get("http_request_verb") 
#                 query = test_functions.get("http_request_query","") 
#                 test_functions.get("http_request_header")
#                 req_header = test_functions.get("http_request_header")
                
                concurrent_instances = None
                concurrent_new_thread_function = None               
                  
                concurrency_dict = test_functions.get("concurrency")
                if concurrency_dict is not None:
                    concurrent_instances = concurrency_dict.get("instances")
                    concurrent_new_thread_function = concurrency_dict.get("new_thread_function") 
                
                    if concurrent_instances is None or concurrent_new_thread_function is None:
                        self.fail("Test " + self._testMethodName + ":" + test_functions["function_name"] + ' contains concurrency agent without mandatory \\"instances\\" or and \\"new_thread_function\\" specifiers' )

                for test_iteration in range(int(test_functions.get("test_iterations","1"))):
                    
                    if concurrent_instances is None:

                        # do it inline on this thread
                        self.execute_the_test(setup_or_state_change_or_validation, test_functions, test_iteration)

                    else:
      
                        threads = []
                        for count in range(concurrent_instances):
                            args = (queue, setup_or_state_change_or_validation, test_functions, test_iteration)
                            # call the new_thread_function specified in the test table under concurrency tag.
                            # the new_thread_function is responsible for setting up the task, and creating the new thread.
                            # the task given to the thread must not block and call task_done() on completion regardless of success or failure
                            new_thread = getattr(self, concurrent_new_thread_function)(args)
                            threads.append(new_thread)
                        
                        #start the threads
                        for t in threads:
                            t.start()
                        
                        # blocks until all tasks have called task_done()
                        queue.join()
                        
                        #blocks until all threads are complete
                        for t in threads:
                            t.join()

            
    def execute_test_definition(self):
        test_record = self.test_table.get(self._testMethodName)
        prerun_function_dict = test_record.get("prerun_function")
        if prerun_function_dict is not None:
            prerun_function_name = prerun_function_dict.get("name")
            prerun_function_args = prerun_function_dict.get("args")
            function_return = getattr(self, prerun_function_name)(prerun_function_args)
            
        self.execute_test_function_set("setup_functions")
        self.execute_test_function_set("state_change_functions")    
        self.execute_test_function_set("state_validation_functions") 
        postrun_function_dict = test_record.get("postrun_function") 
          
        if postrun_function_dict is not None:
            postrun_function_name = postrun_function_dict.get("name")
            postrun_function_args = postrun_function_dict.get("args")
            function_return = getattr(self, postrun_function_name)(postrun_function_args)  
                          
    def setUp(self):
        pass

    def tearDown(self):
        #os.killpg(self.cloudverifier_process.pid, signal.SIGKILL)
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
