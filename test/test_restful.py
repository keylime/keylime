#!/usr/bin/python3
"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.

NOTE:
This unittest is being used as a procedural test.
The tests must be run in-order and CANNOT be parallelized!

Tests all but two RESTful interfaces:
    * agent's POST /keys/vkey
        - Done by CV after the CV's POST /agents/{UUID} command is performed
    * CV's PUT /agents/{UUID}
        - POST already bootstraps agent, so PUT is redundant in this test

USAGE:
Should be run in test directory under root privileges with either command:
    * python -m unittest -v test_restful
    * green -vv
        (with `pip install green`)

To run without root privileges, be sure to export KEYLIME_TEST=True

For Python Coverage support (pip install coverage), set env COVERAGE_FILE and:
    * coverage run --parallel-mode test_restful.py
"""
import base64
import configparser
import datetime
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import dbus
from cryptography.hazmat.primitives import serialization

import keylime.cmd.convert_config as convert

env = os.environ.copy()

# The whole setup of the temporary directory and configurations must happen
# before loading 'config', otherwise the environment variables will not be set
# on 'config' load time, making it to not find the files and raising exceptions.

remove_temp_dir = False
temp_dir = env.get("KEYLIME_TEMP_DIR")
if not temp_dir:
    # If not defined, create a new temporary directory
    temp_dir = tempfile.mkdtemp()
    remove_temp_dir = True

# Custom imports
PACKAGE_ROOT = Path(__file__).parents[1]
KEYLIME_SRC = f"{PACKAGE_ROOT}/keylime"
sys.path.append(KEYLIME_SRC)

COMPONENTS = ["agent", "verifier", "tenant", "registrar", "ca", "logging"]

# Create keylime dir
if "KEYLIME_DIR" not in env:
    keylime_dir = os.path.join(temp_dir, "keylime_dir")
    os.mkdir(keylime_dir)
    os.environ["KEYLIME_DIR"] = keylime_dir
else:
    keylime_dir = env.get("KEYLIME_DIR")

if "KEYLIME_CONF_DIR" not in env:
    # Create config dir
    conf_dir = os.path.join(temp_dir, "conf")
    os.mkdir(conf_dir)

    # Generate configuration files
    old_config = configparser.RawConfigParser()
    templates_dir = os.path.join(PACKAGE_ROOT, "templates")
    conf = convert.process_versions(COMPONENTS, templates_dir, old_config)

    # Override configuration values
    conf["agent"]["uuid"] = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
    conf["tenant"]["require_ek_cert"] = "False"

    # Output files
    convert.output(COMPONENTS, conf, templates_dir, conf_dir)

    # Override configuration files using environment variables
    os.environ["KEYLIME_AGENT_CONFIG"] = os.path.join(conf_dir, "agent.conf")
    os.environ["KEYLIME_VERIFIER_CONFIG"] = os.path.join(conf_dir, "verifier.conf")
    os.environ["KEYLIME_REGISTRAR_CONFIG"] = os.path.join(conf_dir, "registrar.conf")
    os.environ["KEYLIME_TENANT_CONFIG"] = os.path.join(conf_dir, "tenant.conf")
    os.environ["KEYLIME_CA_CONFIG"] = os.path.join(conf_dir, "ca.conf")
    os.environ["KEYLIME_LOGGING_CONFIG"] = os.path.join(conf_dir, "logging.conf")

# pylint: disable=wrong-import-position
from keylime import (
    api_version,
    cloud_verifier_common,
    config,
    crypto,
    fs_util,
    json,
    secure_mount,
    tenant,
    tornado_requests,
    web_util,
)
from keylime.cmd import user_data_encrypt
from keylime.common import algorithms
from keylime.ima import ima
from keylime.requests_client import RequestsClient
from keylime.tpm import tpm_abstract, tpm_main

# Coverage support
if "COVERAGE_FILE" in os.environ:
    FORK_ARGS = ["coverage", "run", "--parallel-mode"]
    if "COVERAGE_DIR" in os.environ:
        FORK_ARGS += ["--rcfile=" + os.environ["COVERAGE_DIR"] + "/.coveragerc"]
else:
    FORK_ARGS = ["python3"]

# Will be used to communicate with the TPM
tpm_instance = None


# cmp depreciated in Python 3, so lets recreate it.
def cmp(a, b):
    return (a > b) - (a < b)


# Ensure this is run as root
if os.geteuid() != 0:
    sys.exit("Tests need to be run with root privileges")

# Force sorting tests alphabetically
unittest.TestLoader.sortTestMethodsUsing = lambda _, x, y: cmp(x, y)

# Environment to pass to services
script_env = os.environ.copy()

# Globals to keep track of Keylime components
cv_process = None
reg_process = None
agent_process = None
tenant_templ = None
SKIP_RUST_TEST = not bool(os.getenv("RUST_TEST"))

# Class-level components that are not static (so can't be added to test class)
public_key = None
mtls_cert = None
keyblob = None
ek_tpm = None
aik_tpm = None

# Boring setup stuff
def setUpModule():
    try:
        env["PATH"] = env["PATH"] + ":/usr/local/bin"
        # Run init_tpm_server and tpm_serverd (start fresh)
        with subprocess.Popen(["init_tpm_server"], shell=False, env=env) as its:
            its.wait()
        with subprocess.Popen(["tpm_serverd"], shell=False, env=env) as tsd:
            tsd.wait()
    except Exception:
        print("WARNING: Restarting TPM emulator failed!")
    # Note: the following is required as abrmd is failing to reconnect to MSSIM, once
    # MSSIM is killed and restarted. If this is an proved an actual bug and is
    # fixed upstream, the following dbus restart call can be removed.
    try:
        sysbus = dbus.SystemBus()
        systemd1 = sysbus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
        manager = dbus.Interface(systemd1, "org.freedesktop.systemd1.Manager")
        # If the systemd service exists, let's restart it.
        for service in sysbus.list_names():
            if "com.intel.tss2.Tabrmd" in service:
                print("Found dbus service:", str(service))
                try:
                    print("Restarting tpm2-abrmd.service.")
                    manager.RestartUnit("tpm2-abrmd.service", "fail")
                except dbus.exceptions.DBusException as e:
                    print(e)
    except Exception:
        print("Non systemd agent detected, no tpm2-abrmd restart required.")

    global script_env
    script_env = os.environ.copy()

    # CV must be run first to create CA and certs!
    launch_cloudverifier()
    launch_registrar()
    # launch_cloudagent()

    # Make the Tenant do a lot of set-up work for us
    global tenant_templ
    tenant_templ = tenant.Tenant()
    tenant_templ.agent_uuid = config.get("agent", "uuid")
    tenant_templ.agent_ip = "localhost"
    tenant_templ.agent_port = config.get("agent", "port")
    tenant_templ.verifier_ip = config.get("verifier", "ip")
    tenant_templ.verifier_port = config.get("verifier", "port")
    tenant_templ.registrar_ip = config.get("registrar", "ip")
    tenant_templ.registrar_boot_port = config.get("registrar", "port")
    tenant_templ.registrar_tls_boot_port = config.get("registrar", "tls_port")
    tenant_templ.registrar_base_url = f"{tenant_templ.registrar_ip}:{tenant_templ.registrar_boot_port}"
    tenant_templ.registrar_base_tls_url = f"{tenant_templ.registrar_ip}:{tenant_templ.registrar_tls_boot_port}"
    tenant_templ.agent_base_url = f"{tenant_templ.agent_ip}:{tenant_templ.agent_port}"
    tenant_templ.supported_version = "2.0"
    # Set up TLS
    # Note: the constructor reads the configuration file and initializes the key
    # and certificate


# Destroy everything on teardown
def tearDownModule():
    # Tear down in reverse order of dependencies
    kill_cloudagent()
    kill_cloudverifier()
    kill_registrar()

    # Run tpm2_clear to allow other processes to use the TPM
    subprocess.run("tpm2_clear", stdout=subprocess.PIPE, check=False)

    if remove_temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)


def launch_cloudverifier():
    """Start up the cloud verifier"""
    global cv_process
    if cv_process is None:
        cv_process = subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn,consider-using-with
            "keylime_verifier",
            shell=False,
            preexec_fn=os.setsid,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=script_env,
        )

        def initthread():
            sys.stdout.write("\033[96m" + "\nCloud Verifier Thread" + "\033[0m")
            while True:
                line = cv_process.stdout.readline()
                if line == b"":
                    break
                line = line.decode("utf-8")
                line = line.rstrip(os.linesep)
                sys.stdout.flush()
                sys.stdout.write("\n\033[96m" + line + "\033[0m")

        t = threading.Thread(target=initthread)
        t.start()
        time.sleep(30)
    return True


def launch_registrar():
    """Start up the registrar"""
    global reg_process
    if reg_process is None:
        reg_process = subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn,consider-using-with
            "keylime_registrar",
            shell=False,
            preexec_fn=os.setsid,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=script_env,
        )

        def initthread():
            sys.stdout.write("\033[95m" + "\nRegistrar Thread" + "\033[0m")
            while True:
                line = reg_process.stdout.readline()
                if line == b"":
                    break
                line = line.decode("utf-8")
                line = line.rstrip(os.linesep)
                sys.stdout.flush()
                sys.stdout.write("\n\033[95m" + line + "\033[0m")

        t = threading.Thread(target=initthread)
        t.start()
        time.sleep(10)
    return True


def launch_cloudagent(agent="python"):
    """Start up the cloud agent"""
    global agent_process
    if agent == "python":
        agent_path = "keylime_agent"
    elif agent == "rust":
        agent_path = script_env.get("KEYLIME_RUST_AGENT")
        agent_config = script_env.get("KEYLIME_RUST_CONF")

        if not agent_config:
            if os.path.exists("../../rust-keylime/keylime-agent.conf"):
                conf_path = os.path.abspath("../../rust-keylime/keylime-agent.conf")
                sys.stdout.write(f"\n'KEYLIME_RUST_CONF' not set, using copy of {conf_path}")

                # Replace uuid and tpm_ownerpassword options to make it work
                # with the rest of the test
                s = ""
                with open(conf_path, "r", encoding="utf-8") as f:
                    s = f.read()

                s = re.sub(r"^uuid =.*$", 'uuid = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"', s, flags=re.M)
                s = re.sub(r"^tpm_ownerpassword =.*$", 'tpm_ownerpassword = "keylime"', s, flags=re.M)

                agent_config = os.path.join(temp_dir, "conf/rust-agent.conf")
                with open(agent_config, "w", encoding="utf-8") as f:
                    f.write(s)

            else:
                sys.stdout.write(
                    "\nPath to Rust agent config not set in env var 'KEYLIME_RUST_CONF'. Set it or try running run_tests.sh"
                )
                return False

        if not agent_path:
            if os.path.exists("../../rust-keylime/target/debug/keylime_agent"):
                agent_path = os.path.abspath("../../rust-keylime/target/debug/keylime_agent")
                sys.stdout.write(f"\n'KEYLIME_RUST_AGENT' not set, using {agent_path}")
            else:
                sys.stdout.write(
                    "\nPath to Rust agent binary not set in env var 'KEYLIME_RUST_AGENT'. Set it or try running run_tests.sh"
                )
                return False

        script_env["RUST_LOG"] = "keylime_agent=debug"
        script_env["KEYLIME_AGENT_CONFIG"] = agent_config
    else:
        agent_path = "echo"
    if agent_process is None:

        # In case the run_as option is set, change files ownership to allow
        # dropping privileges
        run_as = config.get("agent", "run_as").strip('" ')
        if run_as:
            sys.stdout.write(f"\nrun_as option is set, changing owner of {keylime_dir} to {run_as}")
            params = run_as.split(":")
            if len(params) != 2:
                raise Exception("run_as option in agent.conf is in wrong format. Expected 'user:group'")
            user = params[0].strip()
            group = params[1].strip()

            # Recursively change ownership
            for dirpath, _, filenames in os.walk(temp_dir):
                shutil.chown(dirpath, user=user, group=group)
                for filename in filenames:
                    shutil.chown(os.path.join(dirpath, filename), user=user, group=group)

        agent_process = subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn,consider-using-with
            agent_path,
            shell=False,
            preexec_fn=os.setsid,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=script_env,
        )

        def initthread():
            sys.stdout.write("\033[94m" + "\nCloud Agent Thread" + "\033[0m")
            while True:
                line = agent_process.stdout.readline()
                if line == b"":
                    break
                line = line.decode("utf-8")
                line = line.rstrip(os.linesep)
                sys.stdout.flush()
                sys.stdout.write("\n\033[94m" + line + "\033[0m")

        t = threading.Thread(target=initthread)
        t.start()
        for retry in range(10):
            r = subprocess.run(["ss", "-l", "-t", "-n", "-p", "( sport = :9002 )"], stdout=subprocess.PIPE, check=False)
            if b":9002" in r.stdout:
                break
            if retry == 10:
                raise Exception(f"{agent} keylime_agent failed to launch")
            time.sleep(1)
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


def kill_cloudagent():
    """Kill the cloud agent"""
    global agent_process
    if agent_process is None:
        return
    os.killpg(os.getpgid(agent_process.pid), signal.SIGINT)
    agent_process.wait()
    agent_process = None


def services_running():
    if reg_process.poll() is None and cv_process.poll() is None:
        return True
    return False


class TestRestful(unittest.TestCase):

    # Static class members (won't change between tests)
    payload = None
    auth_tag = None
    tpm_policy = {}
    metadata = {}
    allowlist = {}
    excllist = {}
    ima_policy_bundle = {}
    bad_ima_policy_bundle = {}
    revocation_key = ""
    mb_refstate = None
    K = None
    U = None
    V = None
    cloudagent_ip = None
    cloudagent_port = None

    @classmethod
    def setUpClass(cls):
        """Prepare the keys and payload to give to the CV"""
        contents = "random garbage to test as payload"
        ret = user_data_encrypt.encrypt(contents.encode("utf-8"))
        cls.K = ret["k"]
        cls.U = ret["u"]
        cls.V = ret["v"]
        cls.payload = ret["ciphertext"]

        # Set up to register an agent
        cls.auth_tag = crypto.do_hmac(cls.K, tenant_templ.agent_uuid)

        # Prepare policies for agent
        cls.tpm_policy = "{}"
        cls.tpm_policy = tpm_abstract.TPM_Utilities.readPolicy(cls.tpm_policy)

        # Allow targeting a specific API version (default latest)
        cls.api_version = "2.0"

        # Set up allowlist bundles. Use invalid exclusion list regex for bad bundle.
        cls.ima_policy_bundle = ima.read_allowlist()
        cls.ima_policy_bundle["excllist"] = []

        cls.bad_ima_policy_bundle = ima.read_allowlist()
        cls.bad_ima_policy_bundle["excllist"] = ["*"]

    def setUp(self):
        """Nothing to set up before each test"""
        return

    def test_000_services(self):
        """Ensure everyone is running before doing tests"""
        self.assertTrue(services_running(), "Not all services started successfully!")

    # Registrar Testset
    def test_010_reg_agent_post(self):
        """Test registrar's POST /agents/{UUID} Interface"""
        global keyblob, tpm_instance, ek_tpm, aik_tpm
        contact_ip = "127.0.0.1"
        contact_port = 9002
        tpm_instance = tpm_main.tpm()

        # Change CWD for TPM-related operations
        cwd = os.getcwd()
        fs_util.ch_dir(config.WORK_DIR)
        _ = secure_mount.mount()

        # Create a mTLS cert for testing
        global mtls_cert
        rsa_key = crypto.rsa_generate(2048)
        valid_util = datetime.datetime.utcnow() + datetime.timedelta(days=(360 * 5))
        mtls_cert = crypto.generate_selfsigned_cert("TEST_CERT", rsa_key, valid_util).public_bytes(
            serialization.Encoding.PEM
        )

        # Initialize the TPM with AIK
        (ekcert, ek_tpm, aik_tpm) = tpm_instance.tpm_init(
            self_activate=False, config_pw=config.get("agent", "tpm_ownerpassword")
        )

        # Handle emulated TPMs
        if ekcert is None:
            if tpm_instance.is_emulator():
                ekcert = "emulator"

        # Get back to our original CWD
        fs_util.ch_dir(cwd)

        data = {"ekcert": ekcert, "aik_tpm": aik_tpm, "ip": contact_ip, "port": contact_port, "mtls_cert": mtls_cert}
        if ekcert is None or ekcert == "emulator":
            data["ek_tpm"] = ek_tpm

        test_010_reg_agent_post = RequestsClient(tenant_templ.registrar_base_url, False)
        response = test_010_reg_agent_post.post(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", data=json.dumps(data), verify=False
        )

        self.assertEqual(response.status_code, 200, "Non-successful Registrar agent Add return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("blob", json_response["results"], "Malformed response body!")

        keyblob = json_response["results"]["blob"]
        self.assertIsNotNone(keyblob, "Malformed response body!")

    def test_011_reg_agent_activate_put(self):
        """Test registrar's PUT /agents/{UUID}/activate Interface"""

        self.assertIsNotNone(keyblob, "Required value not set.  Previous step may have failed?")

        key = tpm_instance.activate_identity(keyblob)
        data = {
            "auth_tag": crypto.do_hmac(key, tenant_templ.agent_uuid),
        }
        test_011_reg_agent_activate_put = RequestsClient(tenant_templ.registrar_base_url, False)
        response = test_011_reg_agent_activate_put.put(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}/activate",
            data=json.dumps(data),
            verify=False,
        )

        self.assertEqual(response.status_code, 200, "Non-successful Registrar agent Activate return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

    def test_013_reg_agents_get(self):
        """Test registrar's GET /agents Interface"""

        test_013_reg_agents_get = RequestsClient(
            tenant_templ.registrar_base_tls_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_013_reg_agents_get.get(f"/v{self.api_version}/agents/", verify=True)

        self.assertEqual(response.status_code, 200, "Non-successful Registrar agent List return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("uuids", json_response["results"], "Malformed response body!")

        # We registered exactly one agent so far
        self.assertEqual(1, len(json_response["results"]["uuids"]), "Incorrect system state!")

    def test_014_reg_agent_get(self):
        """Test registrar's GET /agents/{UUID} Interface"""
        test_014_reg_agent_get = RequestsClient(
            tenant_templ.registrar_base_tls_url, True, tls_context=tenant_templ.tls_context
        )

        num_retries = 10
        while num_retries > 0:
            response = test_014_reg_agent_get.get(f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", verify=True)
            if response.status_code != 200:
                num_retries -= 1
                time.sleep(3)
            else:
                break

        self.assertEqual(response.status_code, 200, "Non-successful Registrar agent return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("ek_tpm", json_response["results"], "Malformed response body!")
        self.assertIn("aik_tpm", json_response["results"], "Malformed response body!")
        self.assertIn("ekcert", json_response["results"], "Malformed response body!")
        self.assertIn("mtls_cert", json_response["results"], "Malformed response body!")
        self.assertIn("ip", json_response["results"], "Malformed response body!")
        self.assertIn("port", json_response["results"], "Malformed response body!")

        global aik_tpm
        global mtls_cert
        mtls_cert = json_response["results"]["mtls_cert"]
        aik_tpm = json_response["results"]["aik_tpm"]

        # Create context to communicate with the agent
        tenant_templ.agent_tls_context = web_util.generate_tls_context(
            tenant_templ.client_cert,
            tenant_templ.client_key,
            tenant_templ.trusted_server_ca,
            tenant_templ.client_key_password,
            True,
            is_client=True,
            ca_cert_string=mtls_cert,
        )

    def test_015_reg_agent_delete(self):

        """Test registrar's DELETE /agents/{UUID} Interface"""
        test_015_reg_agent_delete = RequestsClient(
            tenant_templ.registrar_base_tls_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_015_reg_agent_delete.delete(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", verify=True
        )

        self.assertEqual(response.status_code, 200, "Non-successful Registrar Delete return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

        # The deletion is not immediate, check if the agent was actually deleted
        numretries = config.getint("tenant", "max_retries")
        deleted = False
        while numretries >= 0:
            response = test_015_reg_agent_delete.get(
                f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", verify=True
            )

            if response.status_code == 404:
                deleted = True
                break
            numretries -= 1
            time.sleep(config.getint("tenant", "retry_interval"))

        self.assertTrue(deleted)

    # Agent Setup Testset

    def test_020_reg_agent_get(self):
        # We want a real cloud agent to communicate with!
        self.assertTrue(launch_cloudagent())
        # We need to refresh the aik value we've stored in case it changed
        self.test_014_reg_agent_get()

    def test_021_agent_keys_pubkey_get(self):
        """Test agent's GET /keys/pubkey Interface"""

        test_021_agent_keys_pubkey_get = RequestsClient(
            tenant_templ.agent_base_url, True, tls_context=tenant_templ.agent_tls_context
        )

        response = test_021_agent_keys_pubkey_get.get(
            f"/v{self.api_version}/keys/pubkey",
            verify=True,
        )

        self.assertEqual(response.status_code, 200, "Non-successful Agent pubkey return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("pubkey", json_response["results"], "Malformed response body!")

        global public_key
        public_key = json_response["results"]["pubkey"]
        self.assertNotEqual(public_key, None, "Malformed response body!")

    def test_022_agent_quotes_identity_get(self):
        """Test agent's GET /quotes/identity Interface"""
        self.assertIsNotNone(aik_tpm, "Required value not set.  Previous step may have failed?")

        nonce = tpm_abstract.TPM_Utilities.random_password(20)

        numretries = config.getint("tenant", "max_retries")
        while numretries >= 0:
            test_022_agent_quotes_identity_get = RequestsClient(
                tenant_templ.agent_base_url, True, tls_context=tenant_templ.agent_tls_context
            )
            response = test_022_agent_quotes_identity_get.get(
                f"/v{self.api_version}/quotes/identity?nonce={nonce}", data=None, verify=True
            )

            if response.status_code == 200:
                break
            numretries -= 1
            time.sleep(config.getint("tenant", "retry_interval"))
        self.assertEqual(response.status_code, 200, "Non-successful Agent identity return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("quote", json_response["results"], "Malformed response body!")
        self.assertIn("pubkey", json_response["results"], "Malformed response body!")

        agentAttestState = cloud_verifier_common.get_AgentAttestStates().get_by_agent_id(tenant_templ.agent_uuid)

        # Check the quote identity
        failure = tpm_instance.check_quote(
            agentAttestState,
            nonce,
            json_response["results"]["pubkey"],
            json_response["results"]["quote"],
            aik_tpm,
            hash_alg=algorithms.Hash(json_response["results"]["hash_alg"]),
        )
        self.assertTrue(not failure, "Invalid quote!")

    @unittest.skip("Testing of agent's POST /keys/vkey disabled!  (spawned CV should do this already)")
    def test_023_agent_keys_vkey_post(self):
        """Test agent's POST /keys/vkey Interface"""
        # CV should do this (during CV POST/PUT test)
        # Running this test might hide problems with the CV sending the V key

        self.assertIsNotNone(self.V, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(public_key, "Required value not set.  Previous step may have failed?")

        encrypted_V = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key), str(self.V))
        b64_encrypted_V = base64.b64encode(encrypted_V)
        data = {"encrypted_key": b64_encrypted_V}

        test_023_agent_keys_vkey_post = RequestsClient(
            tenant_templ.agent_base_url, True, tls_context=tenant_templ.agent_tls_context
        )
        response = test_023_agent_keys_vkey_post.post(
            f"/v{self.api_version}/keys/vkey", data=json.dumps(data), verify=True
        )

        self.assertEqual(response.status_code, 200, "Non-successful Agent vkey post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

    def test_024_agent_keys_ukey_post(self):
        """Test agents's POST /keys/ukey Interface"""

        self.assertIsNotNone(public_key, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(self.U, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(self.auth_tag, "Required value not set.  Previous step may have failed?")
        self.assertIsNotNone(self.payload, "Required value not set.  Previous step may have failed?")

        encrypted_U = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key), self.U)
        b64_encrypted_u = base64.b64encode(encrypted_U)
        data = {
            "encrypted_key": b64_encrypted_u.decode("utf-8"),
            "auth_tag": self.auth_tag,
            "payload": self.payload.decode("utf-8") if self.payload else None,
        }

        test_024_agent_keys_ukey_post = RequestsClient(
            tenant_templ.agent_base_url, True, tls_context=tenant_templ.agent_tls_context
        )
        response = test_024_agent_keys_ukey_post.post(f"/v{self.api_version}/keys/ukey", json=data, verify=True)

        self.assertEqual(response.status_code, 200, "Non-successful Agent ukey post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

    def test_025_cv_allowlist_post(self):
        """Test CV's POST /allowlist/{name} Interface"""
        data = {
            "name": "test-allowlist",
            "tpm_policy": json.dumps(self.tpm_policy),
            "ima_policy_bundle": json.dumps(self.ima_policy_bundle),
        }

        cv_client = RequestsClient(tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context)
        response = cv_client.post(
            f"/v{self.api_version}/allowlists/test-allowlist",
            data=json.dumps(data),
            verify=True,
        )

        self.assertEqual(response.status_code, 201, "Non-successful CV allowlist Post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

    def test_026_cv_allowlist_get(self):
        """Test CV's GET /allowlists/{name} Interface"""
        cv_client = RequestsClient(tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context)
        response = cv_client.get(f"/v{self.api_version}/allowlists/test-allowlist", verify=True)

        self.assertEqual(response.status_code, 200, "Non-successful CV allowlist Post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        results = json_response["results"]
        self.assertEqual(results["name"], "test-allowlist")
        self.assertEqual(results["tpm_policy"], json.dumps(self.tpm_policy))
        self.assertEqual(
            results["ima_policy"],
            json.dumps(
                ima.process_ima_policy(
                    ima.unbundle_ima_policy(self.ima_policy_bundle, False), self.ima_policy_bundle["excllist"]
                )
            ),
        )

    def test_027_cv_allowlist_delete(self):
        """Test CV's DELETE /allowlists/{name} Interface"""
        cv_client = RequestsClient(tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context)
        response = cv_client.delete(f"/v{self.api_version}/allowlists/test-allowlist", verify=True)

        self.assertEqual(response.status_code, 204, "Non-successful CV allowlist Delete return code!")

    # Cloud Verifier Testset

    def test_030_cv_agent_post(self):
        """Test CV's POST /agents/{UUID} Interface"""
        self.assertIsNotNone(self.V, "Required value not set.  Previous step may have failed?")

        b64_v = base64.b64encode(self.V)
        data = {
            "v": b64_v,
            "cloudagent_ip": tenant_templ.agent_ip,
            "cloudagent_port": tenant_templ.agent_port,
            "tpm_policy": json.dumps(self.tpm_policy),
            "ima_policy_bundle": json.dumps(self.ima_policy_bundle),
            "ima_sign_verification_keys": "",
            "mb_refstate": None,
            "metadata": json.dumps(self.metadata),
            "revocation_key": self.revocation_key,
            "accept_tpm_hash_algs": config.getlist("tenant", "accept_tpm_hash_algs"),
            "accept_tpm_encryption_algs": config.getlist("tenant", "accept_tpm_encryption_algs"),
            "accept_tpm_signing_algs": config.getlist("tenant", "accept_tpm_signing_algs"),
            "supported_version": tenant_templ.supported_version,
            "ak_tpm": aik_tpm,
            "mtls_cert": mtls_cert,
        }

        test_030_cv_agent_post = RequestsClient(
            tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_030_cv_agent_post.post(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}",
            data=json.dumps(data),
            verify=True,
        )

        self.assertEqual(response.status_code, 200, "Non-successful CV agent Post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

        time.sleep(10)

    @unittest.skip("Testing of CV's PUT /agents/{UUID} disabled!")
    def test_031_cv_agent_put(self):
        """Test CV's PUT /agents/{UUID} Interface"""
        # TODO: this should actually test PUT functionality (e.g., make agent fail and then PUT back up)
        test_031_cv_agent_put = RequestsClient(
            tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_031_cv_agent_put.put(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", data=b"", verify=True
        )
        self.assertEqual(response.status_code, 200, "Non-successful CV agent Post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

    def test_032_cv_agents_get(self):
        """Test CV's GET /agents Interface"""
        test_032_cv_agents_get = RequestsClient(
            tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_032_cv_agents_get.get(f"/v{self.api_version}/agents/", verify=True)

        self.assertEqual(response.status_code, 200, "Non-successful CV agent List return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("uuids", json_response["results"], "Malformed response body!")

        # Be sure our agent is registered
        self.assertEqual(1, len(json_response["results"]["uuids"]))

    def test_033_cv_agent_get(self):
        """Test CV's GET /agents/{UUID} Interface"""
        test_033_cv_agent_get = RequestsClient(
            tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_033_cv_agent_get.get(f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", verify=True)

        self.assertEqual(response.status_code, 200, "Non-successful CV agent return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

        # Check a few of the important properties are present
        self.assertIn("operational_state", json_response["results"], "Malformed response body!")
        self.assertIn("ip", json_response["results"], "Malformed response body!")
        self.assertIn("port", json_response["results"], "Malformed response body!")

    def test_034_cv_agent_post_invalid_exclude_list(self):
        """Test CV's POST /agents/{UUID} Interface"""
        self.assertIsNotNone(self.V, "Required value not set.  Previous step may have failed?")

        b64_v = base64.b64encode(self.V)

        # Use bad allowlist bundle for testing
        data = {
            "v": b64_v,
            "mb_refstate": None,
            "cloudagent_ip": tenant_templ.agent_ip,
            "cloudagent_port": tenant_templ.agent_port,
            "tpm_policy": json.dumps(self.tpm_policy),
            "ima_policy_bundle": json.dumps(self.bad_ima_policy_bundle),
            "ima_sign_verification_keys": "",
            "metadata": json.dumps(self.metadata),
            "revocation_key": self.revocation_key,
            "accept_tpm_hash_algs": config.getlist("tenant", "accept_tpm_hash_algs"),
            "accept_tpm_encryption_algs": config.getlist("tenant", "accept_tpm_encryption_algs"),
            "accept_tpm_signing_algs": config.getlist("tenant", "accept_tpm_signing_algs"),
            "supported_version": tenant_templ.supported_version,
        }

        client = RequestsClient(tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context)
        response = client.post(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}",
            data=json.dumps(data),
            verify=True,
        )

        self.assertEqual(response.status_code, 400, "Successful CV agent Post return code!")

        # Ensure response is well-formed
        json_response = response.json()
        self.assertIn("results", json_response, "Malformed response body!")

    def test_035_test_delete_in_use_allowlist(self):
        """Test CV's DELETE /allowlists/{name} Interface with an in-use allowlist (should return non-successful status code)"""
        cv_client = RequestsClient(tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context)
        response = cv_client.delete(f"/v{self.api_version}/allowlists/{tenant_templ.agent_uuid}", verify=True)

        self.assertEqual(
            response.status_code, 409, "Unexpected status code for CV allowlist Delete of in-use allowlist!"
        )

    # Agent Poll Testset

    def test_040_agent_quotes_integrity_get(self):
        """Test agent's GET /quotes/integrity Interface"""
        global public_key

        self.assertIsNotNone(aik_tpm, "Required value not set.  Previous step may have failed?")

        nonce = tpm_abstract.TPM_Utilities.random_password(20)
        mask = self.tpm_policy["mask"]
        partial = "1"
        if public_key is None:
            partial = "0"

        test_040_agent_quotes_integrity_get = RequestsClient(
            tenant_templ.agent_base_url, True, tls_context=tenant_templ.agent_tls_context
        )
        response = test_040_agent_quotes_integrity_get.get(
            f"/v{self.api_version}/quotes/integrity?nonce={nonce}&mask={mask}&partial={partial}", verify=True
        )

        self.assertEqual(response.status_code, 200, "Non-successful Agent Integrity Get return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("quote", json_response["results"], "Malformed response body!")
        if public_key is None:
            self.assertIn("pubkey", json_response["results"], "Malformed response body!")
            public_key = json_response["results"]["pubkey"]
        self.assertIn("hash_alg", json_response["results"], "Malformed response body!")

        quote = json_response["results"]["quote"]
        hash_alg = algorithms.Hash(json_response["results"]["hash_alg"])

        agentAttestState = cloud_verifier_common.get_AgentAttestStates().get_by_agent_id(tenant_templ.agent_uuid)

        failure = tpm_instance.check_quote(
            agentAttestState, nonce, public_key, quote, aik_tpm, self.tpm_policy, hash_alg=hash_alg
        )
        self.assertTrue(not failure)

    async def test_041_agent_keys_verify_get(self):
        """Test agent's GET /keys/verify Interface
        We use async here to allow function await while key processes"""
        self.assertIsNotNone(self.K, "Required value not set.  Previous step may have failed?")
        challenge = tpm_abstract.TPM_Utilities.random_password(20)
        encoded = base64.b64encode(self.K).decode("utf-8")

        response = tornado_requests.request(
            "GET", f"http://{self.cloudagent_ip}:{self.cloudagent_port}/keys/verify?challenge={challenge}"
        )
        response = await response
        self.assertEqual(response.status, 200, "Non-successful Agent verify return code!")
        json_response = json.loads(response.read().decode())

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        self.assertIn("hmac", json_response["results"], "Malformed response body!")

        # Be sure response is valid
        mac = json_response["results"]["hmac"]
        ex_mac = crypto.do_hmac(encoded, challenge)
        # ex_mac = crypto.do_hmac(self.K, challenge)
        self.assertEqual(mac, ex_mac, "Agent failed to validate challenge code!")

    # CV Cleanup Testset

    def test_050_cv_agent_delete(self):
        """Test CV's DELETE /agents/{UUID} Interface"""
        test_050_cv_agent_delete = RequestsClient(
            tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context
        )
        response = test_050_cv_agent_delete.delete(
            f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", verify=True
        )

        self.assertEqual(response.status_code, 202, "Non-successful CV agent Delete return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")

        # The deletion is not immediate, check if the agent was actually deleted
        numretries = config.getint("tenant", "max_retries")
        while numretries >= 0:
            response = test_050_cv_agent_delete.get(
                f"/v{self.api_version}/agents/{tenant_templ.agent_uuid}", verify=True
            )

            if response.status_code == 404:
                break
            numretries -= 1
            time.sleep(config.getint("tenant", "retry_interval"))

    def test_060_cv_version_get(self):
        """Test CV's GET /version Interface"""
        cv_client = RequestsClient(tenant_templ.verifier_base_url, True, tls_context=tenant_templ.tls_context)
        response = cv_client.get("/version", verify=True)

        self.assertEqual(response.status_code, 200, "Non-successful CV allowlist Post return code!")
        json_response = response.json()

        # Ensure response is well-formed
        self.assertIn("results", json_response, "Malformed response body!")
        results = json_response["results"]
        self.assertEqual(results["current_version"], api_version.current_version())
        self.assertEqual(results["supported_versions"], api_version.all_versions())

    # Rust agent testset
    @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    def test_070_rust_agent_setup(self):
        """Set up the Rust agent"""

        # Kill the Python agent and launch the Rust agent!
        kill_cloudagent()
        self.test_015_reg_agent_delete()
        self.assertTrue(launch_cloudagent(agent="rust"))

    @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    def test_071_reg_agent_get(self):
        self.test_014_reg_agent_get()

    @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    def test_072_agent_keys_pubkey_get(self):
        self.test_021_agent_keys_pubkey_get()

    @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    def test_073_agent_quotes_identity_get(self):
        self.test_022_agent_quotes_identity_get()

    # @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    @unittest.skip("Testing of agent's POST /keys/vkey disabled!  (spawned CV should do this already)")
    def test_074_agent_keys_vkey_post(self):
        self.test_023_agent_keys_vkey_post()

    # @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    @unittest.skip(
        "Testing of Rust agent's POST /keys/ukey disabled! (Rust agent's API endpoint does not return JSON, see https://github.com/keylime/rust-keylime/issues/447)"
    )
    def test_075_agent_keys_ukey_post(self):
        self.test_024_agent_keys_ukey_post()

    @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    def test_076_agent_quotes_integrity_get(self):
        self.test_040_agent_quotes_integrity_get()

    @unittest.skipIf(SKIP_RUST_TEST, "Testing against rust-keylime is disabled!")
    async def test_077_agent_keys_verify_get(self):
        await self.test_041_agent_keys_verify_get()

    def tearDown(self):
        """Nothing to bring down after each test"""
        return

    @classmethod
    def tearDownClass(cls):
        """Nothing to bring down"""
        return


if __name__ == "__main__":
    unittest.main()
