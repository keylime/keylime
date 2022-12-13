import asyncio
import base64
import configparser
import datetime
import hashlib
import http.server
import importlib
import io
import multiprocessing
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import psutil
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from keylime import api_version as keylime_api_version
from keylime import (
    cmd_exec,
    config,
    crypto,
    fs_util,
    json,
    keylime_logging,
    registrar_client,
    revocation_notifier,
    secure_mount,
    user_utils,
    web_util,
)
from keylime.common import algorithms, validators
from keylime.ima import ima
from keylime.tpm.tpm2_objects import pubkey_from_tpm2b_public
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.tpm.tpm_main import tpm

# Configure logger
logger = keylime_logging.init_logging("cloudagent")

# lock required for multithreaded operation
uvLock = threading.Lock()

# Instaniate tpm
tpm_instance = tpm(need_hw_tpm=True)


class Handler(BaseHTTPRequestHandler):
    parsed_path = ""

    def do_HEAD(self):
        """Not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def do_GET(self):
        """This method services the GET request typically from either the Tenant or the Cloud Verifier.

        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.
        The Cloud verifier requires an additional mask paramter.  If the uri or parameters are incorrect, a 400 response is returned.
        """

        logger.info("GET invoked from %s with uri: %s", self.client_address, self.path)
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /version, /keys/ or /quotes/ interfaces")
            return

        if "version" in rest_params:
            version_info = {"supported_version": keylime_api_version.current_version()}
            web_util.echo_json_response(self, 200, "Success", version_info)
            return

        if not rest_params["api_version"]:
            web_util.echo_json_response(self, 400, "API Version not supported")
            return

        if "keys" in rest_params and rest_params["keys"] == "verify":
            if self.server.K is None:
                logger.info("GET key challenge returning 400 response. bootstrap key not available")
                web_util.echo_json_response(self, 400, "Bootstrap key not yet available.")
                return
            if "challenge" not in rest_params:
                logger.info("GET key challenge returning 400 response. No challenge provided")
                web_util.echo_json_response(self, 400, "No challenge provided.")
                return

            challenge = rest_params["challenge"]
            response = {}
            response["hmac"] = crypto.do_hmac(self.server.K, challenge)
            web_util.echo_json_response(self, 200, "Success", response)
            logger.info("GET key challenge returning 200 response.")

        # If agent pubkey requested
        elif "keys" in rest_params and rest_params["keys"] == "pubkey":
            response = {}
            response["pubkey"] = self.server.publickey_exportable

            web_util.echo_json_response(self, 200, "Success", response)
            logger.info("GET pubkey returning 200 response.")
            return

        elif "quotes" in rest_params:
            nonce = rest_params.get("nonce", None)
            pcrmask = rest_params.get("mask", None)
            ima_ml_entry = rest_params.get("ima_ml_entry", "0")

            # if the query is not messed up
            if nonce is None:
                logger.warning("GET quote returning 400 response. nonce not provided as an HTTP parameter in request")
                web_util.echo_json_response(self, 400, "nonce not provided as an HTTP parameter in request")
                return

            # Sanitization assurance (for tpm.run() tasks below)
            if not (nonce.isalnum() and (pcrmask is None or validators.valid_hex(pcrmask)) and ima_ml_entry.isalnum()):
                logger.warning("GET quote returning 400 response. parameters should be strictly alphanumeric")
                web_util.echo_json_response(self, 400, "parameters should be strictly alphanumeric")
                return

            if len(nonce) > tpm_instance.MAX_NONCE_SIZE:
                logger.warning(
                    "GET quote returning 400 response. Nonce is too long (max size %i): %i",
                    tpm_instance.MAX_NONCE_SIZE,
                    len(nonce),
                )
                web_util.echo_json_response(
                    self, 400, f"Nonce is too long (max size {tpm_instance.MAX_NONCE_SIZE}): {len(nonce)}"
                )
                return

            hash_alg = tpm_instance.defaults["hash"]
            quote = tpm_instance.create_quote(nonce, self.server.publickey_exportable, pcrmask, hash_alg)
            imaMask = pcrmask

            # Allow for a partial quote response (without pubkey)
            enc_alg = tpm_instance.defaults["encrypt"]
            sign_alg = tpm_instance.defaults["sign"]

            if "partial" in rest_params and (rest_params["partial"] is None or rest_params["partial"] == "1"):
                response = {
                    "quote": quote,
                    "hash_alg": hash_alg,
                    "enc_alg": enc_alg,
                    "sign_alg": sign_alg,
                }
            else:
                response = {
                    "quote": quote,
                    "hash_alg": hash_alg,
                    "enc_alg": enc_alg,
                    "sign_alg": sign_alg,
                    "pubkey": self.server.publickey_exportable,
                }

            response["boottime"] = self.server.boottime

            # return a measurement list if available
            if TPM_Utilities.check_mask(imaMask, config.IMA_PCR):
                ima_ml_entry = int(ima_ml_entry)
                if ima_ml_entry > self.server.next_ima_ml_entry:
                    ima_ml_entry = 0
                ml, nth_entry, num_entries = ima.read_measurement_list(self.server.ima_log_file, ima_ml_entry)
                if num_entries > 0:
                    response["ima_measurement_list"] = ml
                    response["ima_measurement_list_entry"] = nth_entry
                    self.server.next_ima_ml_entry = num_entries

            # similar to how IMA log retrievals are triggered by IMA_PCR, we trigger boot logs with MEASUREDBOOT_PCRs
            # other possibilities would include adding additional data to rest_params to trigger boot log retrievals
            # generally speaking, retrieving the 15Kbytes of a boot log does not seem significant compared to the
            # potential Mbytes of an IMA measurement list.
            if TPM_Utilities.check_mask(imaMask, config.MEASUREDBOOT_PCRS[0]):
                if not self.server.tpm_log_file_data:
                    logger.warning("TPM2 event log not available: %s", config.MEASUREDBOOT_ML)
                else:
                    response["mb_measurement_list"] = self.server.tpm_log_file_data

            web_util.echo_json_response(self, 200, "Success", response)
            logger.info("GET %s quote returning 200 response.", rest_params["quotes"])
            return

        else:
            logger.warning("GET returning 400 response. uri not supported: %s", self.path)
            web_util.echo_json_response(self, 400, "uri not supported")
            return

    def do_POST(self):
        """This method services the POST request typically from either the Tenant or the Cloud Verifier.

        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.
        The Cloud verifier requires an additional mask parameter.  If the uri or parameters are incorrect, a 400 response is returned.
        """
        rest_params = web_util.get_restful_params(self.path)

        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /keys/ or /notifications/ interface")
            return

        if not rest_params["api_version"]:
            web_util.echo_json_response(self, 400, "API Version not supported")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            logger.warning("POST returning 400 response, expected content in message. url: %s", self.path)
            web_util.echo_json_response(self, 400, "expected content in message")
            return

        post_body = self.rfile.read(content_length)
        try:
            json_body = json.loads(post_body)
        except Exception as e:
            logger.warning("POST returning 400 response, could not parse body data: %s", e)
            web_util.echo_json_response(self, 400, "content is invalid")
            return

        if "notifications" in rest_params:
            if rest_params["notifications"] == "revocation":
                revocation_notifier.process_revocation(
                    json_body, perform_actions, cert_path=self.server.revocation_cert_path
                )
                web_util.echo_json_response(self, 200, "Success")
            else:
                web_util.echo_json_response(self, 400, "Only /notifications/revocation is supported")
            return

        if rest_params.get("keys", None) not in ["ukey", "vkey"]:
            web_util.echo_json_response(self, 400, "Only /keys/ukey or /keys/vkey are supported")
            return

        try:
            b64_encrypted_key = json_body["encrypted_key"]
            decrypted_key = crypto.rsa_decrypt(self.server.private_key, base64.b64decode(b64_encrypted_key))
        except (ValueError, KeyError, TypeError) as e:
            logger.warning("POST returning 400 response, could not parse body data: %s", e)
            web_util.echo_json_response(self, 400, "content is invalid")
            return

        have_derived_key = False

        if rest_params["keys"] == "ukey":
            if "auth_tag" not in json_body:
                logger.warning("POST returning 400 response, U key provided without an auth_tag")
                web_util.echo_json_response(self, 400, "auth_tag is missing")
                return
            self.server.add_U(decrypted_key)
            self.server.auth_tag = json_body["auth_tag"]
            self.server.payload = json_body.get("payload", None)
            have_derived_key = self.server.attempt_decryption()
        elif rest_params["keys"] == "vkey":
            self.server.add_V(decrypted_key)
            have_derived_key = self.server.attempt_decryption()
        else:
            logger.warning("POST returning  response. uri not supported: %s", self.path)
            web_util.echo_json_response(self, 400, "uri not supported")
            return
        logger.info("POST of %s key returning 200", ("V", "U")[rest_params["keys"] == "ukey"])
        web_util.echo_json_response(self, 200, "Success")

        # no key yet, then we're done
        if not have_derived_key:
            return

        # woo hoo we have a key
        # ok lets write out the key now
        secdir = secure_mount.mount()  # confirm that storage is still securely mounted

        # clean out the secure dir of any previous info before we extract files
        if os.path.isdir(os.path.join(secdir, "unzipped")):
            shutil.rmtree(os.path.join(secdir, "unzipped"))

        # write out key file
        with open(os.path.join(secdir, self.server.enc_keyname), "w", encoding="utf-8") as f:
            f.write(base64.b64encode(self.server.K).decode())

        # stow the U value for later
        tpm_instance.write_key_nvram(self.server.final_U)

        # optionally extend a hash of they key and payload into specified PCR
        tomeasure = self.server.K

        # if we have a good key, now attempt to write out the encrypted payload
        dec_path = os.path.join(secdir, config.get("agent", "dec_payload_file"))
        enc_path = os.path.join(config.WORK_DIR, "encrypted_payload")

        dec_payload = None
        enc_payload = None
        if self.server.payload is not None:
            if not self.server.mtls_cert_enabled and not config.getboolean(
                "agent", "enable_insecure_payload", fallback=False
            ):
                logger.warning(
                    'agent mTLS is disabled, and unless "enable_insecure_payload" is set to "True", payloads cannot be deployed'
                )
                enc_payload = None
            else:
                dec_payload = crypto.decrypt(self.server.payload, bytes(self.server.K))
                enc_payload = self.server.payload

        elif os.path.exists(enc_path):
            # if no payload provided, try to decrypt one from a previous run stored in encrypted_payload
            with open(enc_path, "rb") as f:
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
            with open(enc_path, "wb") as f:
                f.write(self.server.payload.encode("utf-8"))

        # deal with payload
        payload_thread = None
        if dec_payload is not None:
            tomeasure = tomeasure + dec_payload
            # see if payload is a zip
            zfio = io.BytesIO(dec_payload)
            if config.getboolean("agent", "extract_payload_zip") and zipfile.is_zipfile(zfio):
                logger.info("Decrypting and unzipping payload to %s/unzipped", secdir)
                with zipfile.ZipFile(zfio, "r") as f:
                    f.extractall(os.path.join(secdir, "unzipped"))

                # run an included script if one has been provided
                initscript = config.get("agent", "payload_script")
                if initscript != "":

                    def initthread():
                        env = os.environ.copy()
                        env["AGENT_UUID"] = self.server.agent_uuid
                        with subprocess.Popen(
                            ["/bin/bash", initscript],
                            env=env,
                            shell=False,
                            cwd=os.path.join(secdir, "unzipped"),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                        ) as proc:
                            for line in iter(proc.stdout.readline, b""):
                                logger.debug("init-output: %s", line.strip())
                            # should be a no-op as poll already told us it's done
                            proc.wait()

                    if not os.path.exists(os.path.join(secdir, "unzipped", initscript)):
                        logger.info("No payload script %s found in %s/unzipped", initscript, secdir)
                    else:
                        logger.info("Executing payload script: %s/unzipped/%s", secdir, initscript)
                        payload_thread = threading.Thread(target=initthread, daemon=True)
            else:
                logger.info("Decrypting payload to %s", dec_path)
                with open(dec_path, "wb") as f:
                    f.write(dec_payload)
            zfio.close()

        # now extend a measurement of the payload and key if there was one
        pcr = config.getint("agent", "measure_payload_pcr")
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

    private_key = None
    private_key_path = None
    private_key_password = None
    public_key = None
    publickey_exportable = None
    cert = None
    cert_path = None
    mtls_cert_enabled = False
    trusted_ca = None
    revocation_cert_path = None
    done = threading.Event()
    auth_tag = None
    payload = None
    enc_keyname = None
    K = None
    final_U = None
    agent_uuid = None
    next_ima_ml_entry = 0  # The next IMA log offset the verifier may ask for.
    boottime = int(psutil.boot_time())

    def __init__(self, server_address, RequestHandlerClass, agent_uuid, contact_ip, ima_log_file, tpm_log_file_data):
        """Constructor overridden to provide ability to pass configuration arguments to the server"""
        # Find the locations for the U/V transport and mTLS key and certificate.
        # They are either relative to secdir (/var/lib/keylime/secure) or absolute paths.
        secdir = secure_mount.mount()

        # Get server TLS files from configuration file
        (cert_path, key_path, trusted_ca, key_password), _ = web_util.get_tls_options("agent", logger=logger)

        # read or generate the key depending on configuration
        if os.path.isfile(key_path):
            # read in private key
            logger.info("Using existing key in %s", key_path)
            with open(key_path, "rb") as f:
                private_key = crypto.rsa_import_privkey(f.read(), password=key_password)
        else:
            logger.info("Key for U/V transport and mTLS certificate not found, generating a new one")
            private_key = crypto.rsa_generate(2048)
            with open(key_path, "wb") as f:
                f.write(crypto.rsa_export_privkey(private_key, password=key_password))

        self.private_key_path = key_path
        self.private_key = private_key
        self.publickey_exportable = crypto.rsa_export_pubkey(self.private_key)

        self.mtls_cert_enabled = config.getboolean("agent", "enable_agent_mtls", fallback=False)
        if self.mtls_cert_enabled:
            if os.path.isfile(cert_path):
                logger.info("Using existing mTLS cert in %s", cert_path)
                with open(cert_path, "rb") as f:
                    cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
            else:
                logger.info("No mTLS certificate found, generating a new one")
                agent_ips = [server_address[0]]
                if contact_ip is not None:
                    agent_ips.append(contact_ip)
                with open(cert_path, "wb") as f:
                    # By default generate a TLS certificate valid for 5 years
                    valid_util = datetime.datetime.utcnow() + datetime.timedelta(days=(360 * 5))
                    cert = crypto.generate_selfsigned_cert(agent_uuid, private_key, valid_util, agent_ips)
                    f.write(cert.public_bytes(serialization.Encoding.PEM))

            if not trusted_ca:
                logger.warning("No certificates provided in 'trusted_client_ca'")

            self.trusted_ca = trusted_ca
            self.cert_path = cert_path
            self.cert = cert.public_bytes(serialization.Encoding.PEM)
        else:
            self.tls_options = None
            self.cert_path = None
            self.cert = "disabled"
            logger.info("WARNING: mTLS disabled, Tenant and Verifier will reach out to agent via HTTP")

        self.revocation_cert_path = config.get("agent", "revocation_cert")
        if self.revocation_cert_path == "default":
            self.revocation_cert_path = os.path.join(secdir, "unzipped/RevocationNotifier-cert.crt")
        elif self.revocation_cert_path[0] != "/":
            # if it is a relative, convert to absolute in work_dir
            self.revocation_cert_path = os.path.abspath(os.path.join(config.WORK_DIR, self.revocation_cert_path))

        # attempt to get a U value from the TPM NVRAM
        nvram_u = tpm_instance.read_key_nvram()
        if nvram_u is not None:
            logger.info("Existing U loaded from TPM NVRAM")
            self.add_U(nvram_u)
        http.server.HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self.enc_keyname = config.get("agent", "enc_keyname")
        self.agent_uuid = agent_uuid
        self.ima_log_file = ima_log_file
        self.tpm_log_file_data = tpm_log_file_data

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


# Execute revocation action
def perform_actions(revocation):
    # load the actions from inside the keylime module
    actionlist = config.getlist("agent", "revocation_actions")
    actionlist = [f"revocation_actions.{i}" % i for i in actionlist]

    # load actions from unzipped
    secdir = secure_mount.mount()
    action_list_path = os.path.join(secdir, "unzipped/action_list")
    if os.path.exists(action_list_path):
        with open(action_list_path, encoding="utf-8") as f:
            actionlisttxt = f.read()
        if actionlisttxt.strip() != "":
            localactions = actionlisttxt.strip().split(",")
            for action in localactions:
                if not action.startswith("local_action_"):
                    logger.warning("Invalid local action: %s. Must start with local_action_", action)
                else:
                    actionlist.append(action)

            uzpath = os.path.join(secdir, "unzipped")
            if uzpath not in sys.path:
                sys.path.append(uzpath)

    for action in actionlist:
        logger.info("Executing revocation action %s", action)
        try:
            module = importlib.import_module(action)
            execute = getattr(module, "execute")
            loop = asyncio.new_event_loop()
            loop.run_until_complete(execute(revocation))
        except Exception as e:
            logger.warning("Exception during execution of revocation action %s: %s", action, e)


def revocation_listener():
    """
    This configures and starts the revocation listener. It is designed to be started in a separate process.
    """

    if config.has_option("agent", "enable_revocation_notifications"):
        if not config.getboolean("agent", "enable_revocation_notifications"):
            return

    secdir = secure_mount.mount()

    cert_path = config.get("agent", "revocation_cert")
    if cert_path == "default":
        cert_path = os.path.join(secdir, "unzipped/RevocationNotifier-cert.crt")
    elif cert_path[0] != "/":
        # if it is a relative, convert to absolute in work_dir
        cert_path = os.path.abspath(os.path.join(config.WORK_DIR, cert_path))

    try:
        while True:
            try:
                revocation_notifier.await_notifications(perform_actions, revocation_cert_path=cert_path)
            except Exception as e:
                logger.exception(e)
                logger.warning("No connection to revocation server, retrying in 10s...")
                time.sleep(10)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Stopping revocation listener...")


def main() -> None:
    logger.warning("IMPORTANT: The Python agent is deprecated and will be removed with the next major release (7.0.0)!")
    logger.warning("           Please migrate to the Rust based agent: https://github.com/keylime/rust-keylime/")

    config.check_version("agent", logger=logger)

    for ML in [config.MEASUREDBOOT_ML, config.IMA_ML]:
        if not os.access(ML, os.F_OK):
            logger.warning(
                'Measurement list path %s not accessible by agent. Any attempt to instruct it to access this path - via "keylime_tenant" CLI - will result in agent process dying',
                ML,
            )

    ima_log_file = None
    if os.path.exists(config.IMA_ML):
        ima_log_file = open(config.IMA_ML, "r", encoding="utf-8")  # pylint: disable=consider-using-with

    tpm_log_file_data = None
    if os.path.exists(config.MEASUREDBOOT_ML):
        with open(config.MEASUREDBOOT_ML, "rb") as tpm_log_file:
            tpm_log_file_data = base64.b64encode(tpm_log_file.read())

    if config.get("agent", "uuid") == "dmidecode":
        if os.getuid() != 0:
            raise RuntimeError("agent_uuid is configured to use dmidecode, but current process is not running as root.")
        cmd = ["which", "dmidecode"]
        ret = cmd_exec.run(cmd, raiseOnError=False)
        if ret["code"] != 0:
            raise RuntimeError("agent_uuid is configured to use dmidecode, but it's is not found on the system.")

    # initialize the tmpfs partition to store keys if it isn't already available
    secdir = secure_mount.mount()

    # Now that operations requiring root privileges are done, drop privileges
    # if 'run_as' is available in the configuration.
    if os.getuid() == 0:
        run_as = config.get("agent", "run_as", fallback="")
        if run_as != "":
            user_utils.chown(secdir, run_as)
            user_utils.change_uidgid(run_as)
            logger.info("Dropped privileges to %s", run_as)
        else:
            logger.warning("Cannot drop privileges since 'run_as' is empty or missing in keylime.conf agent section.")

    # get params for initialization
    registrar_ip = config.get("agent", "registrar_ip")
    registrar_port = config.get("agent", "registrar_port")

    # get params for the verifier to contact the agent
    contact_ip = os.getenv("KEYLIME_AGENT_CONTACT_IP", None)
    if contact_ip is None and config.has_option("agent", "contact_ip"):
        contact_ip = config.get("agent", "contact_ip")

    contact_port = os.getenv("KEYLIME_AGENT_CONTACT_PORT", None)
    if contact_port is None and config.has_option("agent", "contact_port"):
        contact_port = config.get("agent", "contact_port", fallback="invalid")

    # change dir to working dir
    fs_util.ch_dir(config.WORK_DIR)

    # set a conservative general umask
    os.umask(0o077)

    # initialize tpm
    (ekcert, ek_tpm, aik_tpm) = tpm_instance.tpm_init(
        self_activate=False, config_pw=config.get("agent", "tpm_ownerpassword")
    )  # this tells initialize not to self activate the AIK

    # Warn if kernel version is <5.10 and another algorithm than SHA1 is used,
    # because otherwise IMA will not work
    kernel_version = tuple(platform.release().split("-")[0].split("."))
    if tuple(map(int, kernel_version)) < (5, 10, 0) and tpm_instance.defaults["hash"] != algorithms.Hash.SHA1:
        logger.warning(
            "IMA attestation only works on kernel versions <5.10 with SHA1 as hash algorithm. "
            'Even if ascii_runtime_measurements shows "%s" as the '
            "algorithm, it might be just padding zeros",
            (tpm_instance.defaults["hash"]),
        )

    if ekcert is None and tpm_instance.is_emulator():
        ekcert = "emulator"

    # now we need the UUID
    try:
        agent_uuid = config.get("agent", "uuid")
    except configparser.NoOptionError:
        agent_uuid = None
    if agent_uuid == "hash_ek":
        ek_pubkey = pubkey_from_tpm2b_public(base64.b64decode(ek_tpm))
        ek_pubkey_pem = ek_pubkey.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        agent_uuid = hashlib.sha256(ek_pubkey_pem).hexdigest()
    elif agent_uuid == "generate" or agent_uuid is None:
        agent_uuid = str(uuid.uuid4())
    elif agent_uuid == "dmidecode":
        cmd = ["dmidecode", "-s", "system-uuid"]
        ret = cmd_exec.run(cmd)
        sys_uuid = ret["retout"][0].decode("utf-8")
        agent_uuid = sys_uuid.strip()
        try:
            uuid.UUID(agent_uuid)
        except ValueError as e:
            raise RuntimeError(  # pylint: disable=raise-missing-from
                f"The UUID returned from dmidecode is invalid: {str(e)}"
            )
    elif agent_uuid == "hostname":
        agent_uuid = socket.getfqdn()
    elif agent_uuid == "environment":
        agent_uuid = os.getenv("KEYLIME_AGENT_UUID", None)
        if agent_uuid is None:
            raise RuntimeError("Env variable KEYLIME_AGENT_UUID is empty, but agent_uuid is set to 'environment'")
    elif not validators.valid_uuid(agent_uuid):
        raise RuntimeError("The UUID is not valid")

    if not validators.valid_agent_id(agent_uuid):
        raise RuntimeError("The agent ID set via agent uuid parameter use invalid characters")

    logger.info("Agent UUID: %s", agent_uuid)

    serveraddr = (config.get("agent", "ip"), config.getint("agent", "port"))

    server = CloudAgentHTTPServer(serveraddr, Handler, agent_uuid, contact_ip, ima_log_file, tpm_log_file_data)
    if server.mtls_cert_enabled:
        context = web_util.generate_tls_context(
            server.cert_path,
            server.private_key_path,
            server.trusted_ca,
            private_key_password=server.private_key_password,
            logger=logger,
        )
        server.socket = context.wrap_socket(server.socket, server_side=True)
    else:
        if (
            not config.getboolean("agent", "enable_insecure_payload", fallback=False)
            and config.get("agent", "payload_script") != ""
        ):
            raise RuntimeError(
                "agent mTLS is disabled, while a tenant can instruct the agent to execute code on the node. "
                'In order to allow the running of the agent, "enable_insecure_payload" has to be set to "True"'
            )

    serverthread = threading.Thread(target=server.serve_forever, daemon=True)

    # register it and get back a blob
    keyblob = registrar_client.doRegisterAgent(
        registrar_ip,
        registrar_port,
        agent_uuid,
        ek_tpm,
        ekcert,
        aik_tpm,
        mtls_cert=server.cert,
        contact_ip=contact_ip,
        contact_port=contact_port,
    )

    if keyblob is None:
        tpm_instance.flush_keys()
        raise Exception("Registration failed")

    # get the ephemeral registrar key
    key = tpm_instance.activate_identity(keyblob)

    if key is None:
        tpm_instance.flush_keys()
        raise Exception("Activation failed")

    # tell the registrar server we know the key
    retval = registrar_client.doActivateAgent(registrar_ip, registrar_port, agent_uuid, key)

    if not retval:
        tpm_instance.flush_keys()
        raise Exception("Registration failed on activate")

    # Start revocation listener in a new process to not interfere with tornado
    revocation_process = multiprocessing.Process(target=revocation_listener, daemon=True)
    revocation_process.start()

    logger.info(
        "Starting Cloud Agent on %s:%s with API version %s. Use <Ctrl-C> to stop",
        serveraddr[0],
        serveraddr[1],
        keylime_api_version.current_version(),
    )
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
        tpm_instance.flush_keys()
        logger.debug("Flushed keys successfully")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGQUIT, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    # Keep the main thread alive by waiting for the server thread
    serverthread.join()
