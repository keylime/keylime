#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import asyncio
import http.server
import multiprocessing
import platform
import datetime
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import threading
import base64
import configparser
import uuid
import os
import socket
import sys
import time
import hashlib
import zipfile
import io
import importlib
import shutil
import subprocess
import psutil

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from keylime import config
from keylime import keylime_logging
from keylime import cmd_exec
from keylime import crypto
from keylime import ima
from keylime import json
from keylime import revocation_notifier
from keylime import registrar_client
from keylime import secure_mount
from keylime import web_util
from keylime import api_version as keylime_api_version
from keylime.common import algorithms, validators
from keylime.tpm.tpm_main import tpm
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.tpm.tpm2_objects import pubkey_from_tpm2b_public

# Configure logger
logger = keylime_logging.init_logging('cloudagent')

# lock required for multithreaded operation
uvLock = threading.Lock()

# Instaniate tpm
tpm_instance = tpm(need_hw_tpm=True)


class Handler(BaseHTTPRequestHandler):
    parsed_path = ''

    def do_HEAD(self):
        """Not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def do_GET(self):
        """This method services the GET request typically from either the Tenant or the Cloud Verifier.

        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.
        The Cloud verifier requires an additional mask paramter.  If the uri or parameters are incorrect, a 400 response is returned.
        """

        logger.info('GET invoked from %s with uri: %s', self.client_address, self.path)
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(
                self, 405, "Not Implemented: Use /version, /keys/ or /quotes/ interfaces")
            return

        if "version" in rest_params:
            version_info = {
                "supported_version": keylime_api_version.current_version()
            }
            web_util.echo_json_response(self, 200, version_info)
            return

        if not rest_params["api_version"]:
            web_util.echo_json_response(self, 400, "API Version not supported")
            return

        if "keys" in rest_params and rest_params['keys'] == 'verify':
            if self.server.K is None:
                logger.info('GET key challenge returning 400 response. bootstrap key not available')
                web_util.echo_json_response(
                    self, 400, "Bootstrap key not yet available.")
                return
            if "challenge" not in rest_params:
                logger.info('GET key challenge returning 400 response. No challenge provided')
                web_util.echo_json_response(
                    self, 400, "No challenge provided.")
                return

            challenge = rest_params['challenge']
            response = {}
            response['hmac'] = crypto.do_hmac(self.server.K, challenge)
            web_util.echo_json_response(self, 200, "Success", response)
            logger.info('GET key challenge returning 200 response.')

        # If agent pubkey requested
        elif "keys" in rest_params and rest_params["keys"] == "pubkey":
            response = {}
            response['pubkey'] = self.server.rsapublickey_exportable

            web_util.echo_json_response(self, 200, "Success", response)
            logger.info('GET pubkey returning 200 response.')
            return

        elif "quotes" in rest_params:
            nonce = rest_params.get('nonce', None)
            pcrmask = rest_params.get('mask', None)
            ima_ml_entry = rest_params.get('ima_ml_entry', '0')

            # if the query is not messed up
            if nonce is None:
                logger.warning('GET quote returning 400 response. nonce not provided as an HTTP parameter in request')
                web_util.echo_json_response(
                    self, 400, "nonce not provided as an HTTP parameter in request")
                return

            # Sanitization assurance (for tpm.run() tasks below)
            if not (nonce.isalnum() and
                    (pcrmask is None or validators.valid_hex(pcrmask)) and
                    ima_ml_entry.isalnum()):
                logger.warning('GET quote returning 400 response. parameters should be strictly alphanumeric')
                web_util.echo_json_response(
                    self, 400, "parameters should be strictly alphanumeric")
                return

            if len(nonce) > tpm_instance.MAX_NONCE_SIZE:
                logger.warning('GET quote returning 400 response. Nonce is too long (max size %i): %i',
                               tpm_instance.MAX_NONCE_SIZE, len(nonce))
                web_util.echo_json_response(
                    self, 400, f'Nonce is too long (max size {tpm_instance.MAX_NONCE_SIZE}): {len(nonce)}')
                return

            # identity quotes are always shallow
            hash_alg = tpm_instance.defaults['hash']
            if not tpm_instance.is_vtpm() or rest_params["quotes"] == 'identity':
                quote = tpm_instance.create_quote(
                    nonce, self.server.rsapublickey_exportable, pcrmask, hash_alg)
                imaMask = pcrmask

            # Allow for a partial quote response (without pubkey)
            enc_alg = tpm_instance.defaults['encrypt']
            sign_alg = tpm_instance.defaults['sign']

            if "partial" in rest_params and (rest_params["partial"] is None or rest_params["partial"] == "1"):
                response = {
                    'quote': quote,
                    'hash_alg': hash_alg,
                    'enc_alg': enc_alg,
                    'sign_alg': sign_alg,
                }
            else:
                response = {
                    'quote': quote,
                    'hash_alg': hash_alg,
                    'enc_alg': enc_alg,
                    'sign_alg': sign_alg,
                    'pubkey': self.server.rsapublickey_exportable,
                }

            response['boottime'] = self.server.boottime

            # return a measurement list if available
            if TPM_Utilities.check_mask(imaMask, config.IMA_PCR):
                ima_ml_entry = int(ima_ml_entry)
                if ima_ml_entry > self.server.next_ima_ml_entry:
                    ima_ml_entry = 0
                ml, nth_entry, num_entries = ima.read_measurement_list(config.IMA_ML, ima_ml_entry)
                if num_entries > 0:
                    response['ima_measurement_list'] = ml
                    response['ima_measurement_list_entry'] = nth_entry
                    self.server.next_ima_ml_entry = num_entries

            # similar to how IMA log retrievals are triggered by IMA_PCR, we trigger boot logs with MEASUREDBOOT_PCRs
            # other possibilities would include adding additional data to rest_params to trigger boot log retrievals
            # generally speaking, retrieving the 15Kbytes of a boot log does not seem significant compared to the
            # potential Mbytes of an IMA measurement list.
            if TPM_Utilities.check_mask(imaMask, config.MEASUREDBOOT_PCRS[0]):
                if not os.path.exists(config.MEASUREDBOOT_ML):
                    logger.warning("TPM2 event log not available: %s", config.MEASUREDBOOT_ML)
                else:
                    with open(config.MEASUREDBOOT_ML, 'rb') as f:
                        el = base64.b64encode(f.read())
                    response['mb_measurement_list'] = el

            web_util.echo_json_response(self, 200, "Success", response)
            logger.info('GET %s quote returning 200 response.', rest_params["quotes"])
            return

        else:
            logger.warning('GET returning 400 response. uri not supported: %s', self.path)
            web_util.echo_json_response(self, 400, "uri not supported")
            return

    def do_POST(self):
        """This method services the POST request typically from either the Tenant or the Cloud Verifier.

        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.
        The Cloud verifier requires an additional mask parameter.  If the uri or parameters are incorrect, a 400 response is returned.
        """
        rest_params = web_util.get_restful_params(self.path)

        if rest_params is None:
            web_util.echo_json_response(
                self, 405, "Not Implemented: Use /keys/ interface")
            return

        if not rest_params["api_version"]:
            web_util.echo_json_response(self, 400, "API Version not supported")
            return

        if rest_params.get("keys", None) not in ["ukey", "vkey"]:
            web_util.echo_json_response(self, 400, "Only /keys/ukey or /keys/vkey are supported")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length <= 0:
            logger.warning('POST returning 400 response, expected content in message. url: %s', self.path)
            web_util.echo_json_response(self, 400, "expected content in message")
            return

        post_body = self.rfile.read(content_length)
        try:
            json_body = json.loads(post_body)
            b64_encrypted_key = json_body['encrypted_key']
            decrypted_key = crypto.rsa_decrypt(
                self.server.rsaprivatekey, base64.b64decode(b64_encrypted_key))
        except (ValueError, KeyError, TypeError) as e:
            logger.warning('POST returning 400 response, could not parse body data: %s', e)
            web_util.echo_json_response(self, 400, "content is invalid")
            return

        have_derived_key = False

        if rest_params["keys"] == "ukey":
            if 'auth_tag' not in json_body:
                logger.warning('POST returning 400 response, U key provided without an auth_tag')
                web_util.echo_json_response(self, 400, "auth_tag is missing")
                return
            self.server.add_U(decrypted_key)
            self.server.auth_tag = json_body['auth_tag']
            self.server.payload = json_body.get('payload', None)
            have_derived_key = self.server.attempt_decryption()
        elif rest_params["keys"] == "vkey":
            self.server.add_V(decrypted_key)
            have_derived_key = self.server.attempt_decryption()
        else:
            logger.warning('POST returning  response. uri not supported: %s', self.path)
            web_util.echo_json_response(self, 400, "uri not supported")
            return
        logger.info('POST of %s key returning 200', ('V', 'U')[rest_params["keys"] == "ukey"])
        web_util.echo_json_response(self, 200, "Success")

        # no key yet, then we're done
        if not have_derived_key:
            return

        # woo hoo we have a key
        # ok lets write out the key now
        secdir = secure_mount.mount()  # confirm that storage is still securely mounted

        # clean out the secure dir of any previous info before we extract files
        if os.path.isdir("%s/unzipped" % secdir):
            shutil.rmtree("%s/unzipped" % secdir)

        # write out key file
        f = open(secdir + "/" + self.server.enc_keyname, 'w', encoding="utf-8")
        f.write(base64.b64encode(self.server.K).decode())
        f.close()

        # stow the U value for later
        tpm_instance.write_key_nvram(self.server.final_U)

        # optionally extend a hash of they key and payload into specified PCR
        tomeasure = self.server.K

        # if we have a good key, now attempt to write out the encrypted payload
        dec_path = os.path.join(secdir,
                                config.get('cloud_agent', "dec_payload_file"))
        enc_path = os.path.join(config.WORK_DIR, "encrypted_payload")

        dec_payload = None
        enc_payload = None
        if self.server.payload is not None:
            dec_payload = crypto.decrypt(
                self.server.payload, bytes(self.server.K))

            enc_payload = self.server.payload
        elif os.path.exists(enc_path):
            # if no payload provided, try to decrypt one from a previous run stored in encrypted_payload
            with open(enc_path, 'rb') as f:
                enc_payload = f.read()
            try:
                dec_payload = crypto.decrypt(enc_payload, self.server.K)
                logger.info("Decrypted previous payload in %s to %s", enc_path, dec_path)
            except Exception as e:
                logger.warning("Unable to decrypt previous payload %s with derived key: %s", enc_path, e)
                os.remove(enc_path)
                enc_payload = None

        # also write out encrypted payload to be decrytped next time
        if enc_payload is not None:
            with open(enc_path, 'wb') as f:
                f.write(self.server.payload.encode('utf-8'))

        # deal with payload
        payload_thread = None
        if dec_payload is not None:
            tomeasure = tomeasure + dec_payload
            # see if payload is a zip
            zfio = io.BytesIO(dec_payload)
            if config.getboolean('cloud_agent', 'extract_payload_zip') and zipfile.is_zipfile(zfio):
                logger.info("Decrypting and unzipping payload to %s/unzipped", secdir)
                with zipfile.ZipFile(zfio, 'r')as f:
                    f.extractall('%s/unzipped' % secdir)

                # run an included script if one has been provided
                initscript = config.get('cloud_agent', 'payload_script')
                if initscript != "":
                    def initthread():
                        env = os.environ.copy()
                        env['AGENT_UUID'] = self.server.agent_uuid
                        proc = subprocess.Popen(["/bin/bash", initscript], env=env, shell=False, cwd='%s/unzipped' % secdir,
                                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        for line in iter(proc.stdout.readline, b''):
                            logger.debug("init-output: %s", line.strip())
                        # should be a no-op as poll already told us it's done
                        proc.wait()

                    if not os.path.exists(
                            os.path.join(secdir, "unzipped", initscript)):
                        logger.info("No payload script %s found in %s/unzipped", initscript, secdir)
                    else:
                        logger.info("Executing payload script: %s/unzipped/%s", secdir, initscript)
                        payload_thread = threading.Thread(target=initthread, daemon=True)
            else:
                logger.info("Decrypting payload to %s", dec_path)
                with open(dec_path, 'wb') as f:
                    f.write(dec_payload)
            zfio.close()

        # now extend a measurement of the payload and key if there was one
        pcr = config.getint('cloud_agent', 'measure_payload_pcr')
        if 0 < pcr < 24:
            logger.info("extending measurement of payload into PCR %s", pcr)
            measured = tpm_instance.hashdigest(tomeasure)
            tpm_instance.extendPCR(pcr, measured)

        if payload_thread is not None:
            payload_thread.start()

        return

    # pylint: disable=W0622
    def log_message(self, format, *args):
        return

# consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn


class CloudAgentHTTPServer(ThreadingMixIn, HTTPServer):
    """Http Server which will handle each request in a separate thread."""

    # Do not modify directly unless you acquire uvLock. Set chosen for uniqueness of contained values
    u_set = set()
    v_set = set()

    rsaprivatekey = None
    rsapublickey = None
    rsapublickey_exportable = None
    mtls_cert_path = None
    rsakey_path = None
    mtls_cert = None
    done = threading.Event()
    auth_tag = None
    payload = None
    enc_keyname = None
    K = None
    final_U = None
    agent_uuid = None
    next_ima_ml_entry = 0 # The next IMA log offset the verifier may ask for.
    boottime = int(psutil.boot_time())

    def __init__(self, server_address, RequestHandlerClass, agent_uuid):
        """Constructor overridden to provide ability to pass configuration arguments to the server"""
        secdir = secure_mount.mount()
        keyname = os.path.join(secdir,
                               config.get('cloud_agent', 'rsa_keyname'))
        certname = os.path.join(secdir, config.get('cloud_agent', 'mtls_cert'))
        # read or generate the key depending on configuration
        if os.path.isfile(keyname):
            # read in private key
            logger.debug("Using existing key in %s", keyname)
            f = open(keyname, "rb")
            rsa_key = crypto.rsa_import_privkey(f.read())
        else:
            logger.debug("key not found, generating a new one")
            rsa_key = crypto.rsa_generate(2048)
            with open(keyname, "wb") as f:
                f.write(crypto.rsa_export_privkey(rsa_key))

        self.rsakey_path = keyname
        self.rsaprivatekey = rsa_key
        self.rsapublickey_exportable = crypto.rsa_export_pubkey(
            self.rsaprivatekey)

        if os.path.isfile(certname):
            logger.debug("Using existing mTLS cert in %s", certname)
            with open(certname, "rb") as f:
                mtls_cert = x509.load_pem_x509_certificate(f.read())
        else:
            logger.debug("No mTLS certificate found generating a new one")
            with open(certname, "wb") as f:
                # By default generate a TLS certificate valid for 5 years
                valid_util = datetime.datetime.utcnow() + datetime.timedelta(days=(360 * 5))
                mtls_cert = crypto.generate_selfsigned_cert(agent_uuid, rsa_key, valid_util)
                f.write(mtls_cert.public_bytes(serialization.Encoding.PEM))

        self.mtls_cert_path = certname
        self.mtls_cert = mtls_cert

        # attempt to get a U value from the TPM NVRAM
        nvram_u = tpm_instance.read_key_nvram()
        if nvram_u is not None:
            logger.info("Existing U loaded from TPM NVRAM")
            self.add_U(nvram_u)
        http.server.HTTPServer.__init__(
            self, server_address, RequestHandlerClass)
        self.enc_keyname = config.get('cloud_agent', 'enc_keyname')
        self.agent_uuid = agent_uuid

    def add_U(self, u):
        """Threadsafe method for adding a U value received from the Tenant

        Do not modify u_set of v_set directly.
        """
        with uvLock:
            # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
            if config.INSECURE_DEBUG:
                logger.debug("Adding U len %d data:%s", len(u), base64.b64encode(u))
            self.u_set.add(u)

    def add_V(self, v):
        """Threadsafe method for adding a V value received from the Cloud Verifier
        Do not modify u_set of v_set directly.
        """
        with uvLock:
            # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
            if config.INSECURE_DEBUG:
                logger.debug("Adding V: %s", base64.b64encode(v))
            self.v_set.add(v)

    def attempt_decryption(self):
        """On reception of a U or V value, this method is called to attempt the decryption of the Cloud Init script

        At least one U and V value must be received in order to attempt encryption. Multiple U and V values are stored
        to prevent an attacker from sending U/V values to deny service.
        """
        with uvLock:
            both_u_and_v_present = False
            return_value = False
            for u in self.u_set:
                for v in self.v_set:
                    both_u_and_v_present = True
                    return_value = self.decrypt_check(u, v)
                    if return_value:
                        # reset u and v sets
                        self.u_set = set()
                        self.v_set = set()
                        return return_value
            # TODO check on whether this happens or not.  NVRAM causes trouble
            if both_u_and_v_present:
                pass
                # logger.critical("Possible attack from: " + str(handler.client_address) + ".  Both U (potentially stale from TPM NVRAM) and V present but unsuccessful in attempt to decrypt check value.")
            return return_value

    def decrypt_check(self, decrypted_U, decrypted_V):
        """Decrypt the Cloud init script with the passed U and V values.

        This method will access the received auth tag, and may fail if decoy U and V values were received.
        Do not call directly unless you acquire uvLock. Returns None if decryption unsuccessful, else returns the
        decrypted agent UUID.
        """

        if self.auth_tag is None:
            return None

        if len(decrypted_U) != len(decrypted_V):
            logger.warning("Invalid U len %d or V len %d. skipping...", len(decrypted_U), len(decrypted_V))
            return None

        candidate_key = crypto.strbitxor(decrypted_U, decrypted_V)

        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if config.INSECURE_DEBUG:
            logger.debug("U: %s", base64.b64encode(decrypted_U))
            logger.debug("V: %s", base64.b64encode(decrypted_V))
            logger.debug("K: %s", base64.b64encode(candidate_key))

        logger.debug("auth_tag: %s", self.auth_tag)
        ex_mac = crypto.do_hmac(candidate_key, self.agent_uuid)

        if ex_mac == self.auth_tag:
            logger.info("Successfully derived K for UUID %s", self.agent_uuid)
            self.final_U = decrypted_U
            self.K = candidate_key
            return True

        logger.error("Failed to derive K for UUID %s", self.agent_uuid)

        return False


def revocation_listener():
    """
    This configures and starts the revocation listener. It is designed to be started in a separate process.
    """

    if not config.getboolean('cloud_agent', 'listen_notfications'):
        return

    secdir = secure_mount.mount()

    cert_path = config.get('cloud_agent', 'revocation_cert')
    if cert_path == "default":
        cert_path = os.path.join(secdir,
                                 "unzipped/RevocationNotifier-cert.crt")
    elif cert_path[0] != '/':
        # if it is a relative, convert to absolute in work_dir
        cert_path = os.path.abspath(
            os.path.join(config.WORK_DIR, cert_path))

    # Callback function handling the revocations
    def perform_actions(revocation):
        actionlist = []

        # load the actions from inside the keylime module
        actionlisttxt = config.get('cloud_agent', 'revocation_actions')
        if actionlisttxt.strip() != "":
            actionlist = actionlisttxt.split(',')
            actionlist = ["revocation_actions.%s" % i for i in actionlist]

        # load actions from unzipped
        action_list_path = os.path.join(secdir, "unzipped/action_list")
        if os.path.exists(action_list_path):
            with open(action_list_path, encoding="utf-8") as f:
                actionlisttxt = f.read()
            if actionlisttxt.strip() != "":
                localactions = actionlisttxt.strip().split(',')
                for action in localactions:
                    if not action.startswith('local_action_'):
                        logger.warning("Invalid local action: %s. Must start with local_action_", action)
                    else:
                        actionlist.append(action)

                uzpath = "%s/unzipped" % secdir
                if uzpath not in sys.path:
                    sys.path.append(uzpath)

        for action in actionlist:
            logger.info("Executing revocation action %s", action)
            try:
                module = importlib.import_module(action)
                execute = getattr(module, 'execute')
                asyncio.get_event_loop().run_until_complete(execute(revocation))
            except Exception as e:
                logger.warning("Exception during execution of revocation action %s: %s", action, e)

    try:
        while True:
            try:
                revocation_notifier.await_notifications(
                    perform_actions, revocation_cert_path=cert_path)
            except Exception as e:
                logger.exception(e)
                logger.warning("No connection to revocation server, retrying in 10s...")
                time.sleep(10)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Stopping revocation listener...")


def main():
    for ML in [config.MEASUREDBOOT_ML, config.IMA_ML]:
        if not os.access(ML, os.F_OK):
            logger.warning("Measurement list path %s not accessible by agent. Any attempt to instruct it to access this path - via \"keylime_tenant\" CLI - will result in agent process dying", ML)

    if config.get('cloud_agent', 'agent_uuid') == 'dmidecode':
        if os.getuid() != 0:
            raise RuntimeError('agent_uuid is configured to use dmidecode, '
                               'but current process is not running as root.')
        cmd = ['which', 'dmidecode']
        ret = cmd_exec.run(cmd, raiseOnError=False)
        if ret['code'] != 0:
            raise RuntimeError('agent_uuid is configured to use dmidecode, '
                               'but it\'s is not found on the system.')

    # Instanitate TPM class

    instance_tpm = tpm()
    # get params for initialization
    registrar_ip = config.get('cloud_agent', 'registrar_ip')
    registrar_port = config.get('cloud_agent', 'registrar_port')

    # get params for the verifier to contact the agent
    contact_ip = os.getenv("KEYLIME_AGENT_CONTACT_IP", None)
    if contact_ip is None and config.has_option('cloud_agent', 'agent_contact_ip'):
        contact_ip = config.get('cloud_agent', 'agent_contact_ip')
    contact_port = os.getenv("KEYLIME_AGENT_CONTACT_PORT", None)
    if contact_port is None and config.has_option('cloud_agent', 'agent_contact_port'):
        contact_port = config.get('cloud_agent', 'agent_contact_port', fallback="invalid")

    # initialize the tmpfs partition to store keys if it isn't already available
    secure_mount.mount()

    # change dir to working dir
    config.ch_dir(config.WORK_DIR, logger)

    # initialize tpm
    (ekcert, ek_tpm, aik_tpm) = instance_tpm.tpm_init(self_activate=False, config_pw=config.get(
        'cloud_agent', 'tpm_ownerpassword'))  # this tells initialize not to self activate the AIK
    virtual_agent = instance_tpm.is_vtpm()

    # Warn if kernel version is <5.10 and another algorithm than SHA1 is used,
    # because otherwise IMA will not work
    kernel_version = tuple(platform.release().split("-")[0].split("."))
    if tuple(map(int,kernel_version)) < (5, 10, 0) and instance_tpm.defaults["hash"] != algorithms.Hash.SHA1:
        logger.warning("IMA attestation only works on kernel versions <5.10 with SHA1 as hash algorithm. "
                       "Even if ascii_runtime_measurements shows \"%s\" as the "
                       "algorithm, it might be just padding zeros", (instance_tpm.defaults["hash"]))

    if ekcert is None:
        if virtual_agent:
            ekcert = 'virtual'
        elif instance_tpm.is_emulator():
            ekcert = 'emulator'

    # now we need the UUID
    try:
        agent_uuid = config.get('cloud_agent', 'agent_uuid')
    except configparser.NoOptionError:
        agent_uuid = None
    if agent_uuid == 'hash_ek':
        ek_pubkey = pubkey_from_tpm2b_public(base64.b64decode(ek_tpm))
        ek_pubkey_pem = ek_pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
        agent_uuid = hashlib.sha256(ek_pubkey_pem).hexdigest()
    elif agent_uuid == 'generate' or agent_uuid is None:
        agent_uuid = str(uuid.uuid4())
    elif agent_uuid == 'dmidecode':
        cmd = ['dmidecode', '-s', 'system-uuid']
        ret = cmd_exec.run(cmd)
        sys_uuid = ret['retout'][0].decode('utf-8')
        agent_uuid = sys_uuid.strip()
        try:
            uuid.UUID(agent_uuid)
        except ValueError as e:
            raise RuntimeError("The UUID returned from dmidecode is invalid: %s" % e)  # pylint: disable=raise-missing-from
    elif agent_uuid == 'hostname':
        agent_uuid = socket.getfqdn()
    elif agent_uuid == 'environment':
        agent_uuid = os.getenv("KEYLIME_AGENT_UUID", None)
        if agent_uuid is None:
            raise RuntimeError("Env variable KEYLIME_AGENT_UUID is empty, but agent_uuid is set to 'environment'")
    elif not validators.valid_uuid(agent_uuid):
        raise RuntimeError("The UUID is not valid")

    if not validators.valid_agent_id(agent_uuid):
        raise RuntimeError("The agent ID set via agent uuid parameter use invalid characters")

    if config.STUB_VTPM and config.TPM_CANNED_VALUES is not None:
        # Use canned values for stubbing
        jsonIn = config.TPM_CANNED_VALUES
        if "add_vtpm_to_group" in jsonIn:
            # The value we're looking for has been canned!
            agent_uuid = jsonIn['add_vtpm_to_group']['retout']
        else:
            # Our command hasn't been canned!
            raise Exception("Command %s not found in canned json!" %
                            ("add_vtpm_to_group"))

    logger.info("Agent UUID: %s", agent_uuid)

    serveraddr = (config.get('cloud_agent', 'cloudagent_ip'),
                  config.getint('cloud_agent', 'cloudagent_port'))

    keylime_ca = config.get('cloud_agent', 'keylime_ca')
    if keylime_ca == "default":
        keylime_ca = os.path.join(config.WORK_DIR, 'cv_ca', 'cacert.crt')

    server = CloudAgentHTTPServer(serveraddr, Handler, agent_uuid)
    context = web_util.generate_mtls_context(server.mtls_cert_path, server.rsakey_path, keylime_ca, logger=logger)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    serverthread = threading.Thread(target=server.serve_forever, daemon=True)

    # register it and get back a blob
    mtls_cert = server.mtls_cert.public_bytes(serialization.Encoding.PEM)
    keyblob = registrar_client.doRegisterAgent(
        registrar_ip, registrar_port, agent_uuid, ek_tpm, ekcert, aik_tpm, mtls_cert, contact_ip, contact_port)

    if keyblob is None:
        instance_tpm.flush_keys()
        raise Exception("Registration failed")

    # get the ephemeral registrar key
    key = instance_tpm.activate_identity(keyblob)

    if key is None:
        instance_tpm.flush_keys()
        raise Exception("Activation failed")

    # tell the registrar server we know the key
    retval = registrar_client.doActivateAgent(
        registrar_ip, registrar_port, agent_uuid, key)

    if not retval:
        instance_tpm.flush_keys()
        raise Exception("Registration failed on activate")

    # Start revocation listener in a new process to not interfere with tornado
    revocation_process = multiprocessing.Process(target=revocation_listener, daemon=True)
    revocation_process.start()

    logger.info("Starting Cloud Agent on %s:%s with API version %s. Use <Ctrl-C> to stop", serveraddr[0], serveraddr[1], keylime_api_version.current_version())
    serverthread.start()

    def shutdown_handler(*_):
        logger.info("TERM Signal received, shutting down...")
        logger.debug("Stopping revocation notifier...")
        revocation_process.terminate()
        logger.debug("Shutting down HTTP server...")
        server.shutdown()
        server.server_close()
        serverthread.join()
        logger.debug("HTTP server stopped...")
        revocation_process.join()
        logger.debug("Revocation notifier stopped...")
        secure_mount.umount()
        logger.debug("Umounting directories...")
        instance_tpm.flush_keys()
        logger.debug("Flushed keys successfully")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGQUIT, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    # Keep the main thread alive by waiting for the server thread
    serverthread.join()
