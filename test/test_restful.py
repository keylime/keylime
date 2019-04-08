'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2017 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''


""" NOTE:
This unittest is being used as a procedural test.
The tests must be run in-order and CANNOT be parallelized!

Tests all but two RESTful interfaces:
    * node's POST /v2/keys/vkey
        - Done by CV after the CV's POST /v2/instances/{UUID} command is performed
    * CV's PUT /v2/instances/{UUID}
        - POST already bootstraps node, so PUT is redundant in this test

The registrar's PUT vactivate interface is only tested if a vTPM is present!
"""


""" USAGE:
Should be run in test directory under root privileges with either command:
    * python -m unittest -v test_restful
    * green -vv
        (with `pip install green`)

To run without root privileges, be sure to export KEYLIME_TEST=True

For Python Coverage support (pip install coverage), set env COVERAGE_FILE and:
    * coverage run --parallel-mode test_restful.py
"""


# System imports
import dbus
import sys
import signal
import unittest
import subprocess
import time
import json
import os
import ConfigParser
import base64
import threading
import shutil
import errno

# Coverage support
if "COVERAGE_FILE" in os.environ:
    FORK_ARGS = ["coverage", "run", "--parallel-mode"]
    if "COVERAGE_DIR" in os.environ:
        FORK_ARGS += ["--rcfile="+os.environ["COVERAGE_DIR"]+"/.coveragerc"]
else:
    FORK_ARGS = ["python"]

# Useful constants for the test
KEYLIME_DIR=os.getcwdu()+"/../keylime/"

# Custom imports
sys.path.insert(0, KEYLIME_DIR)
import common
import tornado_requests
import registrar_client
import tenant
import crypto
import user_data_encrypt
import secure_mount
import tpm_obj
from tpm_abstract import TPM_Utilities

# Will be used to communicate with the TPM
tpm = None

#Ensure this is run as root
if os.geteuid() != 0 and common.REQUIRE_ROOT:
    exit("Tests need to be run with root privileges, or set env KEYLIME_TEST=True!")

# Force sorting tests alphabetically
unittest.TestLoader.sortTestMethodsUsing = lambda _, x, y: cmp(x, y)

# Config-related stuff
config = ConfigParser.SafeConfigParser()
config.read(common.CONFIG_FILE)

# Environment to pass to services
script_env = os.environ.copy()

# Globals to keep track of Keylime components
cv_process = None
reg_process = None
cn_process = None
tenant_templ = None

# Class-level components that are not static (so can't be added to test class)
public_key = None
keyblob = None
ek = None
aik = None
vtpm = False



# Like os.remove, but ignore file DNE exceptions
def fileRemove(path):
    try:
        os.remove(path)
    except OSError as e:
        # Ignore if file does not exist
        if e.errno != errno.ENOENT:
            raise


# Boring setup stuff
def setUpModule():
    try:
        env = os.environ.copy()
        env['PATH']=env['PATH']+":/usr/local/bin"
        # Run init_tpm_server and tpm_serverd (start fresh)
        its = subprocess.Popen(["init_tpm_server"], shell=False, env=env)
        its.wait()
        tsd = subprocess.Popen(["tpm_serverd"], shell=False, env=env)
        tsd.wait()
    except Exception as e:
        print "WARNING: Restarting TPM emulator failed!"
    # Note: the following is required as abrmd is failing to reconnect to MSSIM, once
    # MSSIM is killed and restarted. If this is an proved an actual bug and is
    # fixed upstream, the following dbus restart call can be removed.
    try:
        sysbus = dbus.SystemBus()
        systemd1 = sysbus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        manager = dbus.Interface(systemd1, 'org.freedesktop.systemd1.Manager')
        # If the systemd service exists, let's restart it.
        for service in sysbus.list_names():
            if "com.intel.tss2.Tabrmd" in service:
                print("Found dbus service: %s", str(service))
                try:
                    print("Restarting tpm2-abrmd.service.")
                    job = manager.RestartUnit('tpm2-abrmd.service', 'fail')
                except dbus.exceptions.DBusException as e:
                    print(e)
    except Exception as e:
        print("Non systemd instance detected, no tpm2-abrmd restart required.")

    try:
        # Start with a clean slate for this test
        fileRemove(common.WORK_DIR + "/tpmdata.json")
        fileRemove(common.WORK_DIR + "/cv_data.sqlite")
        fileRemove(common.WORK_DIR + "/reg_data.sqlite")
        shutil.rmtree(common.WORK_DIR + "/cv_ca", True)
    except Exception as e:
        print "WARNING: Cleanup of TPM files failed!"

    # CV must be run first to create CA and certs!
    launch_cloudverifier()
    launch_registrar()
    #launch_cloudnode()

    # get the tpm object
    global tpm
    tpm = tpm_obj.getTPM(need_hw_tpm=True)

    # Make the Tenant do a lot of set-up work for us
    global tenant_templ
    tenant_templ = tenant.Tenant()
    tenant_templ.cloudnode_ip = "localhost"
    tenant_templ.node_uuid = config.get('cloud_node', 'node_uuid')
    tenant_templ.registrar_boot_port = config.get('general', 'registrar_port')

# Destroy everything on teardown
def tearDownModule():
    # Tear down in reverse order of dependencies
    kill_cloudnode()
    kill_cloudverifier()
    kill_registrar()



def launch_cloudverifier():
    """Start up the cloud verifier"""
    global cv_process, script_env, FORK_ARGS
    if cv_process is None:
        filename = ["%s/cloud_verifier_tornado.py"%(KEYLIME_DIR)]
        cv_process = subprocess.Popen(
                                        FORK_ARGS + filename,
                                        shell=False,
                                        preexec_fn=os.setsid,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=script_env
                                    )
        def initthread():
            sys.stdout.write('\033[96m' + "\nCloud Verifier Thread" + '\033[0m')
            while True:
                line = cv_process.stdout.readline()
                if line=="":
                    break
                line = line.rstrip(os.linesep)
                sys.stdout.flush()
                sys.stdout.write('\n\033[96m' + line + '\033[0m')
        t = threading.Thread(target=initthread)
        t.start()
        time.sleep(30)
    return True

def launch_registrar():
    """Start up the registrar"""
    global reg_process, script_env, FORK_ARGS
    if reg_process is None:
        filename = ["%s/registrar.py"%(KEYLIME_DIR)]
        reg_process = subprocess.Popen(
                                        FORK_ARGS + filename,
                                        shell=False,
                                        preexec_fn=os.setsid,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=script_env
                                    )
        def initthread():
            sys.stdout.write('\033[95m' + "\nRegistrar Thread" + '\033[0m')
            while True:
                line = reg_process.stdout.readline()
                if line=="":
                    break
                line = line.rstrip(os.linesep)
                sys.stdout.flush()
                sys.stdout.write('\n\033[95m' + line + '\033[0m')
        t = threading.Thread(target=initthread)
        t.start()
        time.sleep(10)
    return True

def launch_cloudnode():
    """Start up the cloud node"""
    global cn_process, script_env, FORK_ARGS
    if cn_process is None:
        filename = ["%s/cloud_node.py"%(KEYLIME_DIR)]
        cn_process = subprocess.Popen(
                                        FORK_ARGS + filename,
                                        shell=False,
                                        preexec_fn=os.setsid,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        env=script_env
                                    )
        def initthread():
            sys.stdout.write('\033[94m' + "\nCloud Node Thread" + '\033[0m')
            while True:
                line = cn_process.stdout.readline()
                if line=="":
                    break
                line = line.rstrip(os.linesep)
                sys.stdout.flush()
                sys.stdout.write('\n\033[94m' + line + '\033[0m')
        t = threading.Thread(target=initthread)
        t.start()
        time.sleep(10)
    return True

def kill_cloudverifier():
    """Kill the cloud verifier"""
    global cv_process
    if cv_process is None:
        return
    os.killpg(os.getpgid(cv_process.pid), signal.SIGINT)
    cv_process.wait()
    cv_process = None

def kill_registrar():
    """Kill the registrar"""
    global reg_process
    if reg_process is None:
        return
    os.killpg(os.getpgid(reg_process.pid), signal.SIGINT)
    reg_process.wait()
    reg_process = None

def kill_cloudnode():
    """Kill the cloud node"""
    global cn_process
    if cn_process is None:
        return
    os.killpg(os.getpgid(cn_process.pid), signal.SIGINT)
    cn_process.wait()
    cn_process = None

def services_running():
    if reg_process.poll() is None and cv_process.poll() is None:
        return True
    return False



class TestRestful(unittest.TestCase):

    # Static class members (won't change between tests)
    payload = None
    auth_tag = None
    tpm_policy = None
    vtpm_policy = {}
    metadata = {}
    ima_whitelist = {}
    revocation_key = ""
    K = None
    U = None
    V = None
    api_version = common.API_VERSION


    @classmethod
    def setUpClass(cls):
        """Prepare the keys and payload to give to the CV"""
        contents = "random garbage to test as payload"
        ret = user_data_encrypt.encrypt(contents)
        cls.K = ret['k']
        cls.U = ret['u']
        cls.V = ret['v']
        cls.payload = ret['ciphertext']

        """Set up to register a node"""
        cls.auth_tag = crypto.do_hmac(cls.K,tenant_templ.node_uuid)

        """Prepare policies for node"""
        cls.tpm_policy = config.get('tenant', 'tpm_policy')
        cls.vtpm_policy = config.get('tenant', 'vtpm_policy')
        cls.tpm_policy = TPM_Utilities.readPolicy(cls.tpm_policy)
        cls.vtpm_policy = TPM_Utilities.readPolicy(cls.vtpm_policy)

        """Allow targeting a specific API version (default latest)"""
        cls.api_version = common.API_VERSION

    def setUp(self):
        """Nothing to set up before each test"""
        pass



    """Ensure everyone is running before doing tests"""
    def test_000_services(self):
        self.assertTrue(services_running(), "Not all services started successfully!")



    """Registrar Testset"""
    def test_010_reg_instance_post(self):
        """Test registrar's POST /v2/instances/{UUID} Interface"""
        global keyblob, aik, vtpm, ek

        # Change CWD for TPM-related operations
        cwd = os.getcwdu()
        common.ch_dir(common.WORK_DIR,None)
        secdir = secure_mount.mount()

        # Initialize the TPM with AIK
        (ek,ekcert,aik,ek_tpm,aik_name) = tpm.tpm_init(self_activate=False,config_pw=config.get('cloud_node','tpm_ownerpassword'))
        vtpm = tpm.is_vtpm()

        # Seed RNG (root only)
        if common.REQUIRE_ROOT:
            tpm.init_system_rand()

        # Handle virtualized and emulated TPMs
        if ekcert is None:
            if vtpm:
                ekcert = 'virtual'
            elif tpm.is_emulator():
                ekcert = 'emulator'

        # Get back to our original CWD
        common.ch_dir(cwd,None)

        data = {
            'ek': ek,
            'ekcert': ekcert,
            'aik': aik,
            'aik_name': aik_name,
            'ek_tpm': ek_tpm,
            'tpm_version': tpm.get_tpm_version(),
        }
        v_json_message = json.dumps(data)

        response = tornado_requests.request(
                                            "POST",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.registrar_ip,tenant_templ.registrar_boot_port,self.api_version,tenant_templ.node_uuid),
                                            data=v_json_message,
                                            context=None
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Registrar Instance Add return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("blob", response_body["results"], "Malformed response body!")

        keyblob = response_body["results"]["blob"]
        self.assertIsNotNone(keyblob, "Malformed response body!")

    @unittest.skipIf(vtpm == True, "Registrar's PUT /v2/instances/{UUID}/activate only for non-vTPMs!")
    def test_011_reg_instance_activate_put(self):
        """Test registrar's PUT /v2/instances/{UUID}/activate Interface"""
        global keyblob, aik

        self.assertIsNotNone(keyblob, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(aik, "Required value not set.  Previous step may have failed?")

        key = tpm.activate_identity(keyblob)
        data = {
            'auth_tag': crypto.do_hmac(base64.b64decode(key),tenant_templ.node_uuid),
        }
        v_json_message = json.dumps(data)

        response = tornado_requests.request(
                                            "PUT",
                                            "http://%s:%s/v%s/instances/%s/activate"%(tenant_templ.registrar_ip,tenant_templ.registrar_boot_port,self.api_version,tenant_templ.node_uuid),
                                            data=v_json_message,
                                            context=None
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Registrar Instance Activate return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")

    @unittest.skipIf(vtpm == False, "Registrar's PUT /v2/instances/{UUID}/vactivate only for vTPMs!")
    def test_012_reg_instance_vactivate_put(self):
        """Test registrar's PUT /v2/instances/{UUID}/vactivate Interface"""
        global keyblob, aik, ek

        self.assertIsNotNone(keyblob, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(aik, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(ek, "Required value not set.  Previous step may have failed?")

        key = tpm.activate_identity(keyblob)
        deepquote = tpm.create_deep_quote(hashlib.sha1(key).hexdigest(),tenant_templ.node_uuid+aik+ek)
        data = {
            'deepquote': deepquote,
        }
        v_json_message = json.dumps(data)

        response = tornado_requests.request(
                                            "PUT",
                                            "http://%s:%s/v%s/instances/%s/vactivate"%(tenant_templ.registrar_ip,tenant_templ.registrar_boot_port,self.api_version,tenant_templ.node_uuid),
                                            data=v_json_message,
                                            context=None
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Registrar Instance vActivate return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")

    def test_013_reg_instances_get(self):
        """Test registrar's GET /v2/instances Interface"""
        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/instances/"%(tenant_templ.registrar_ip,tenant_templ.registrar_port,self.api_version),
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Registrar Instance List return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("uuids", response_body["results"], "Malformed response body!")

        # We registered exactly one node so far
        self.assertEqual(1, len(response_body["results"]["uuids"]), "Incorrect system state!")

    def test_014_reg_instance_get(self):
        """Test registrar's GET /v2/instances/{UUID} Interface"""
        global aik

        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.registrar_ip,tenant_templ.registrar_port,self.api_version,tenant_templ.node_uuid),
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Registrar Instance return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("aik", response_body["results"], "Malformed response body!")
        self.assertIn("ek", response_body["results"], "Malformed response body!")
        self.assertIn("ekcert", response_body["results"], "Malformed response body!")

        aik = response_body["results"]["aik"]
        #TODO: results->provider_keys is only for virtual mode

    def test_015_reg_instance_delete(self):
        """Test registrar's DELETE /v2/instances/{UUID} Interface"""
        response = tornado_requests.request(
                                            "DELETE",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.registrar_ip,tenant_templ.registrar_port,self.api_version,tenant_templ.node_uuid),
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Registrar Delete return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")



    """Node Setup Testset"""
    def test_020_node_keys_pubkey_get(self):
        """Test node's GET /v2/keys/pubkey Interface"""

        # We want a real cloud node to communicate with!
        launch_cloudnode()

        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/keys/pubkey"%(tenant_templ.cloudnode_ip,tenant_templ.cloudnode_port,self.api_version),
                                            context=None
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Node pubkey return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("pubkey", response_body["results"], "Malformed response body!")

        global public_key
        public_key = response_body["results"]["pubkey"]
        self.assertNotEqual(public_key, None, "Malformed response body!")

    def test_021_reg_instance_get(self):
        # We need to refresh the aik value we've stored in case it changed
        self.test_014_reg_instance_get()

    def test_022_node_quotes_identity_get(self):
        """Test node's GET /v2/quotes/identity Interface"""
        global aik

        self.assertIsNotNone(aik, "Required value not set.  Previous step may have failed?")

        nonce = TPM_Utilities.random_password(20)

        numretries = config.getint('tenant','max_retries')
        while numretries >= 0:
            response = tornado_requests.request(
                                                "GET",
                                                "http://%s:%s/v%s/quotes/identity?nonce=%s"%(tenant_templ.cloudnode_ip,tenant_templ.cloudnode_port,self.api_version,nonce)
                                            )
            if response.status_code == 200:
                break
            numretries-=1
            time.sleep(config.getint('tenant','max_retries'))
        self.assertEqual(response.status_code, 200, "Non-successful Node identity return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("quote", response_body["results"], "Malformed response body!")
        self.assertIn("pubkey", response_body["results"], "Malformed response body!")

        # Check the quote identity
        self.assertTrue(tpm.check_quote(nonce,response_body["results"]["pubkey"],response_body["results"]["quote"],aik), "Invalid quote!")

    @unittest.skip("Testing of nodes's POST /v2/keys/vkey disabled!  (spawned CV should do this already)")
    def test_023_node_keys_vkey_post(self):
        """Test node's POST /v2/keys/vkey Interface"""
        # CV should do this (during CV POST/PUT test)
        # Running this test might hide problems with the CV sending the V key
        global public_key

        self.assertIsNotNone(self.V, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(public_key, "Required value not set.  Previous step may have failed?")

        encrypted_V = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key),str(self.V))
        b64_encrypted_V = base64.b64encode(encrypted_V)
        data = {
                  'encrypted_key': b64_encrypted_V
                }
        v_json_message = json.dumps(data)

        response = tornado_requests.request(
                                            "POST", "http://%s:%s/v%s/keys/vkey"%(tenant_templ.cloudnode_ip,tenant_templ.cloudnode_port,self.api_version),
                                            data=v_json_message
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Node vkey post return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")

    def test_024_node_keys_ukey_post(self):
        """Test node's POST /v2/keys/ukey Interface"""
        global public_key

        self.assertIsNotNone(public_key, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(self.U, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(self.auth_tag, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(self.payload, "Required value not set.  Previous step may have failed?")

        encrypted_U = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key),str(self.U))
        b64_encrypted_u = base64.b64encode(encrypted_U)
        data = {
                  'encrypted_key': b64_encrypted_u,
                  'auth_tag': self.auth_tag,
                  'payload': self.payload
                }
        u_json_message = json.dumps(data)

        response = tornado_requests.request(
                                            "POST", "http://%s:%s/v%s/keys/ukey"%(tenant_templ.cloudnode_ip,tenant_templ.cloudnode_port,self.api_version),
                                            data=u_json_message
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Node ukey post return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")



    """Cloud Verifier Testset"""
    def test_030_cv_instance_post(self):
        """Test CV's POST /v2/instances/{UUID} Interface"""
        self.assertIsNotNone(self.V, "Required value not set.  Previous step may have failed?")

        b64_v = base64.b64encode(self.V)
        data = {
            'v': b64_v,
            'cloudnode_ip': tenant_templ.cloudnode_ip,
            'cloudnode_port': tenant_templ.cloudnode_port,
            'tpm_policy': json.dumps(self.tpm_policy),
            'vtpm_policy':json.dumps(self.vtpm_policy),
            'ima_whitelist':json.dumps(self.ima_whitelist),
            'metadata':json.dumps(self.metadata),
            'revocation_key':self.revocation_key,
            'accept_tpm_hash_algs': config.get('tenant','accept_tpm_hash_algs').split(','),
            'accept_tpm_encryption_algs': config.get('tenant','accept_tpm_encryption_algs').split(','),
            'accept_tpm_signing_algs': config.get('tenant','accept_tpm_signing_algs').split(','),
        }
        json_message = json.dumps(data)

        response = tornado_requests.request(
                                            "POST",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.cloudverifier_ip,tenant_templ.cloudverifier_port,self.api_version,tenant_templ.node_uuid),
                                            data=json_message,
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful CV Instance Post return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")

        time.sleep(10)

    @unittest.skip("Testing of CV's PUT /v2/instances/{UUID} disabled!")
    def test_031_cv_instance_put(self):
        """Test CV's PUT /v2/instances/{UUID} Interface"""
        #TODO: this should actually test PUT functionality (e.g., make node fail and then PUT back up)
        response = tornado_requests.request(
                                            "PUT",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.cloudverifier_ip,tenant_templ.cloudverifier_port,self.api_version,tenant_templ.node_uuid),
                                            data=b'',
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful CV Instance Post return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")

    def test_032_cv_instances_get(self):
        """Test CV's GET /v2/instances Interface"""
        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/instances/"%(tenant_templ.cloudverifier_ip,tenant_templ.cloudverifier_port,self.api_version),
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful CV Instance List return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("uuids", response_body["results"], "Malformed response body!")

        # Be sure our node is registered
        self.assertEqual(1, len(response_body["results"]["uuids"]))

    def test_033_cv_instance_get(self):
        """Test CV's GET /v2/instances/{UUID} Interface"""
        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.cloudverifier_ip,tenant_templ.cloudverifier_port,self.api_version,tenant_templ.node_uuid),
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful CV Instance return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")

        # Check a few of the important properties are present
        self.assertIn("operational_state", response_body["results"], "Malformed response body!")
        self.assertIn("ip", response_body["results"], "Malformed response body!")
        self.assertIn("port", response_body["results"], "Malformed response body!")



    """Node Poll Testset"""
    def test_040_node_quotes_integrity_get(self):
        """Test node's GET /v2/quotes/integrity Interface"""
        global public_key, aik

        self.assertIsNotNone(aik, "Required value not set.  Previous step may have failed?")

        nonce = TPM_Utilities.random_password(20)
        mask = self.tpm_policy["mask"]
        vmask = self.vtpm_policy["mask"]
        partial = "1"
        if public_key is None:
            partial = "0"

        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/quotes/integrity?nonce=%s&mask=%s&vmask=%s&partial=%s"%(tenant_templ.cloudnode_ip,tenant_templ.cloudnode_port,self.api_version,nonce,mask,vmask,partial)
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Node Integrity Get return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("quote", response_body["results"], "Malformed response body!")
        if public_key is None:
            self.assertIn("pubkey", response_body["results"], "Malformed response body!")
            public_key = response_body["results"]["pubkey"]
        self.assertIn("tpm_version", response_body["results"], "Malformed response body!")
        self.assertIn("hash_alg", response_body["results"], "Malformed response body!")

        quote = response_body["results"]["quote"]
        tpm_version = response_body["results"]["tpm_version"]
        hash_alg = response_body["results"]["hash_alg"]

        validQuote = tpm.check_quote(nonce,
                                            public_key,
                                            quote,
                                            aik,
                                            self.tpm_policy,
                                            hash_alg=hash_alg)
        self.assertTrue(validQuote)

    def test_041_node_keys_verify_get(self):
        """Test node's GET /v2/keys/verify Interface"""
        self.assertIsNotNone(self.K, "Required value not set.  Previous step may have failed?")

        challenge = TPM_Utilities.random_password(20)

        response = tornado_requests.request(
                                            "GET",
                                            "http://%s:%s/v%s/keys/verify?challenge=%s"%(tenant_templ.cloudnode_ip,tenant_templ.cloudnode_port,self.api_version,challenge)
                                        )
        self.assertEqual(response.status_code, 200, "Non-successful Node verify return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")
        self.assertIn("hmac", response_body["results"], "Malformed response body!")

        # Be sure response is valid
        mac = response_body['results']['hmac']
        ex_mac = crypto.do_hmac(self.K, challenge)
        self.assertEqual(mac, ex_mac, "Node failed to validate challenge code!")



    """CV Cleanup Testset"""
    def test_050_cv_instance_delete(self):
        """Test CV's DELETE /v2/instances/{UUID} Interface"""
        time.sleep(5)
        response = tornado_requests.request(
                                            "DELETE",
                                            "http://%s:%s/v%s/instances/%s"%(tenant_templ.cloudverifier_ip,tenant_templ.cloudverifier_port,self.api_version,tenant_templ.node_uuid),
                                            context=tenant_templ.context
                                        )
        self.assertEqual(response.status_code, 202, "Non-successful CV Instance Delete return code!")
        response_body = response.json()

        # Ensure response is well-formed
        self.assertIn("results", response_body, "Malformed response body!")



    def tearDown(self):
        """Nothing to bring down after each test"""
        pass

    @classmethod
    def tearDownClass(cls):
        """Nothing to bring down"""
        pass



if __name__ == '__main__':
    unittest.main()
