import argparse
import base64
import io
import json
import logging
import os
import sys
import tempfile
import time
import zipfile
from typing import List, Optional

import requests
from cryptography.hazmat.primitives import serialization as crypto_serialization

from keylime import api_version as keylime_api_version
from keylime import ca_util, cert_utils, config, crypto, keylime_logging, registrar_client, signing, web_util
from keylime.agentstates import AgentAttestState
from keylime.cli import options, policies
from keylime.cmd import user_data_encrypt
from keylime.common import algorithms, retry, states, validators
from keylime.requests_client import RequestsClient
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.tpm.tpm_main import tpm

# setup logging
logger = keylime_logging.init_logging("tenant")

# special exception that suppresses stack traces when it happens
class UserError(Exception):
    pass


class Tenant:
    """Simple command processor example."""

    config = None

    verifier_ip = None
    verifier_port = None

    agent_ip = None
    cv_cloudagent_ip = None
    agent_port = None

    registrar_ip = None
    registrar_port = None
    registrar_data = {}

    api_version = None

    uuid_service_generate_locally = None
    agent_uuid = ""

    K = b""
    V = b""
    U = b""
    auth_tag = None

    tpm_policy = None
    metadata = {}
    allowlist = {}
    ima_policy_name = ""
    ima_sign_verification_keys: Optional[str] = None
    revocation_key = ""
    accept_tpm_hash_algs = []
    accept_tpm_encryption_algs = []
    accept_tpm_signing_algs = []
    mb_refstate = None
    supported_version = None

    client_cert = None
    client_key = None
    client_key_password = None
    trusted_server_ca: List[str] = []
    enable_agent_mtls = False
    verify_server_cert = False
    verify_custom = None

    request_timeout = None

    # Context with the trusted CA certificates from the configuration
    tls_context = None

    # Context with the agent's mTLS certificate
    agent_tls_context = None

    payload = None

    tpm_instance = tpm()

    def __init__(self):
        """Set up required values and TLS"""
        self.nonce = None
        self.agent_ip = None
        self.agent_port = None
        self.verifier_id = None
        self.verifier_ip = config.get("tenant", "verifier_ip")
        self.verifier_port = config.get("tenant", "verifier_port")
        self.registrar_ip = config.get("tenant", "registrar_ip")
        self.registrar_port = config.get("tenant", "registrar_port")
        self.api_version = keylime_api_version.current_version()
        self.enable_agent_mtls = config.getboolean("tenant", "enable_agent_mtls")
        self.request_timeout = config.getint("tenant", "request_timeout", fallback=60)
        self.retry_interval = config.getfloat("tenant", "retry_interval")
        self.exponential_backoff = config.getboolean("tenant", "exponential_backoff")
        self.maxr = config.getint("tenant", "max_retries")

        logger.info("Setting up client TLS...")
        (cert, key, trusted_ca, key_password), verify_server_cert = web_util.get_tls_options(
            "tenant", is_client=True, logger=logger
        )

        if not self.enable_agent_mtls:
            logger.warning(
                "Warning: agent mTLS is currently disabled, keys will be sent in the clear! This should only be used for testing."
            )

        if not verify_server_cert:
            logger.warning(
                "Warning: server certificate verification is disabled as 'trusted_server_ca' option is set to 'all'. This should only be used for testing."
            )

        if not trusted_ca:
            logger.warning("No certificates provided in 'trusted_server_ca'")

        if cert and not os.path.isfile(cert):
            logger.warning("Could not find file %s provided in 'client_cert'", cert)

        if key and not os.path.isfile(key):
            logger.warning("Could not find file %s provided in 'client_key'", key)

        if all([(cert and os.path.isfile(cert)), (key and os.path.isfile(key))]):
            self.client_cert = cert
            self.client_key = key
            self.client_key_password = key_password
            self.verify_server_cert = verify_server_cert
            self.trusted_server_ca = trusted_ca

            self.tls_context = web_util.generate_tls_context(
                cert, key, trusted_ca, key_password, verify_server_cert, is_client=True, logger=logger
            )

            logger.info("TLS is enabled.")
        else:
            logger.warning("TLS is disabled.")

    @property
    def verifier_base_url(self):
        return f"{self.verifier_ip}:{self.verifier_port}"

    def init_add(self, args):
        """Set up required values. Command line options can overwrite these config values

        Arguments:
            args {[string]} -- agent_ip|agent_port|cv_agent_ip
        """
        if "agent_ip" in args:
            self.agent_ip = args["agent_ip"]

        if "agent_port" in args and args["agent_port"] is not None:
            self.agent_port = args["agent_port"]

        self.registrar_data = registrar_client.getData(
            self.registrar_ip, self.registrar_port, self.agent_uuid, self.tls_context
        )

        if self.registrar_data is None:
            raise UserError(f"Agent ${self.agent_uuid} data not found in the Registrar.")

        # try to get the port or ip from the registrar if it is missing
        if (self.agent_ip is None or self.agent_port is None) and self.registrar_data is not None:
            if self.agent_ip is None:
                if self.registrar_data["ip"] is not None:
                    self.agent_ip = self.registrar_data["ip"]
                else:
                    raise UserError("No Ip was specified or found in the Registrar")

            if self.agent_port is None and self.registrar_data["port"] is not None:
                self.agent_port = self.registrar_data["port"]

        # Check if a contact ip and port for the agent was found
        if self.agent_ip is None:
            raise UserError("The contact ip address for the agent was not specified.")

        if self.agent_port is None:
            raise UserError("The contact port for the agent was not specified.")

        # Auto-detection for API version
        self.supported_version = args["supported_version"]
        if self.supported_version is None:
            # Default to 1.0 if the agent did not send a mTLS certificate
            if self.registrar_data.get("mtls_cert", None) is None:
                self.supported_version = "1.0"
            else:
                # Try to connect to the agent to get supported version
                if self.registrar_data["mtls_cert"] == "disabled":
                    self.enable_agent_mtls = False
                    logger.warning(
                        "Warning: mTLS for agents is disabled: the identity of each node will be based on the properties of the TPM only. "
                        "Unless you have strict control of your network, it is strongly advised that remote code execution should be disabled, "
                        'by setting "payload_script=" and "extract_payload_zip=False" under "[agent]" in agent configuration file.'
                    )
                    tls_context = None
                else:
                    # Store the agent self-signed certificate as a string
                    self.verify_custom = self.registrar_data["mtls_cert"]

                    if not self.agent_tls_context:
                        self.agent_tls_context = web_util.generate_tls_context(
                            self.client_cert,
                            self.client_key,
                            self.trusted_server_ca,
                            self.client_key_password,
                            self.verify_server_cert,
                            is_client=True,
                            ca_cert_string=self.verify_custom,
                            logger=logger,
                        )
                    tls_context = self.agent_tls_context

                with RequestsClient(
                    f"{self.agent_ip}:{self.agent_port}",
                    tls_enabled=self.enable_agent_mtls,
                    tls_context=tls_context,
                ) as get_version:
                    res = get_version.get("/version")
                    if res and res.status_code == 200:
                        try:
                            data = res.json()
                            api_version = data["results"]["supported_version"]
                            if keylime_api_version.validate_version(api_version):
                                self.supported_version = api_version
                            else:
                                logger.warning("API version provided by the agent is not valid")
                        except (TypeError, KeyError):
                            pass

        if self.supported_version is None:
            api_version = keylime_api_version.current_version()
            logger.warning("Could not detect supported API version. Defaulting to %s", api_version)
            self.supported_version = api_version

        # Now set the cv_agent_ip
        if "cv_agent_ip" in args and args["cv_agent_ip"] is not None:
            self.cv_cloudagent_ip = args["cv_agent_ip"]
        else:
            self.cv_cloudagent_ip = self.agent_ip

        # Make sure all keys exist in dictionary
        if "file" not in args:
            args["file"] = None
        if "keyfile" not in args:
            args["keyfile"] = None
        if "payload" not in args:
            args["payload"] = None
        if "ca_dir" not in args:
            args["ca_dir"] = None
        if "incl_dir" not in args:
            args["incl_dir"] = None
        if "ca_dir_pw" not in args:
            args["ca_dir_pw"] = None

        # Set up accepted algorithms
        self.accept_tpm_hash_algs = config.getlist("tenant", "accept_tpm_hash_algs")
        self.accept_tpm_encryption_algs = config.getlist("tenant", "accept_tpm_encryption_algs")
        self.accept_tpm_signing_algs = config.getlist("tenant", "accept_tpm_signing_algs")

        (
            self.tpm_policy,
            self.mb_refstate,
            self.ima_policy_name,
            self.ima_sign_verification_keys,
            self.allowlist,
        ) = policies.process_allowlist(args)

        # if none
        if args["file"] is None and args["keyfile"] is None and args["ca_dir"] is None:
            raise UserError(
                "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
            )

        if args["keyfile"] is not None:
            if args["file"] is not None or args["ca_dir"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
                )

            # read the keys in
            if isinstance(args["keyfile"], dict) and "data" in args["keyfile"]:
                if isinstance(args["keyfile"]["data"], list) and len(args["keyfile"]["data"]) == 1:
                    keyfile = args["keyfile"]["data"][0]
                    if keyfile is None:
                        raise UserError("Invalid key file contents")
                    f = io.StringIO(keyfile)
                else:
                    raise UserError("Invalid key file provided")
            else:
                f = open(args["keyfile"], encoding="utf-8")  # pylint: disable=consider-using-with
            self.K = base64.b64decode(f.readline())
            self.U = base64.b64decode(f.readline())
            self.V = base64.b64decode(f.readline())
            f.close()

            # read the payload in (opt.)
            if isinstance(args["payload"], dict) and "data" in args["payload"]:
                if isinstance(args["payload"]["data"], list) and len(args["payload"]["data"]) > 0:
                    self.payload = args["payload"]["data"][0]
            else:
                if args["payload"] is not None:
                    with open(args["payload"], "rb") as f:
                        self.payload = f.read()

        if args["file"] is not None:
            if args["keyfile"] is not None or args["ca_dir"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
                )

            if isinstance(args["file"], dict) and "data" in args["file"]:
                if isinstance(args["file"]["data"], list) and len(args["file"]["data"]) > 0:
                    contents = args["file"]["data"][0]
                    if contents is None:
                        raise UserError("Invalid file payload contents")
                else:
                    raise UserError("Invalid file payload provided")
            else:
                with open(args["file"], "rb") as f:
                    contents = f.read()
            ret = user_data_encrypt.encrypt(contents)
            self.K = ret["k"]
            self.U = ret["u"]
            self.V = ret["v"]
            self.payload = ret["ciphertext"]

        if args["ca_dir"] is None and args["incl_dir"] is not None:
            raise UserError("--include option is only valid when used with --cert")
        if args["ca_dir"] is not None:
            if args["file"] is not None or args["keyfile"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent"
                )
            if args["ca_dir"] == "default":
                args["ca_dir"] = config.CA_WORK_DIR

            if "ca_dir_pw" in args and args["ca_dir_pw"] is not None:
                ca_util.setpassword(args["ca_dir_pw"])

            if not os.path.exists(args["ca_dir"]) or not os.path.exists(os.path.join(args["ca_dir"], "cacert.crt")):
                logger.warning("CA directory does not exist. Creating...")
                ca_util.cmd_init(args["ca_dir"])
            if not os.path.exists(os.path.join(args["ca_dir"], f"{self.agent_uuid}-private.pem")):
                ca_util.cmd_mkcert(args["ca_dir"], self.agent_uuid)

            cert_pkg, serial, subject = ca_util.cmd_certpkg(args["ca_dir"], self.agent_uuid)

            # support revocation
            if not os.path.exists(os.path.join(args["ca_dir"], "RevocationNotifier-private.pem")):
                ca_util.cmd_mkcert(args["ca_dir"], "RevocationNotifier")
            rev_package, _, _ = ca_util.cmd_certpkg(args["ca_dir"], "RevocationNotifier")

            # extract public and private keys from package
            sf = io.BytesIO(rev_package)
            with zipfile.ZipFile(sf) as zf:
                privkey = zf.read("RevocationNotifier-private.pem")
                cert = zf.read("RevocationNotifier-cert.crt")

            # put the cert of the revoker into the cert package
            sf = io.BytesIO(cert_pkg)
            with zipfile.ZipFile(sf, "a", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("RevocationNotifier-cert.crt", cert)

                # add additional files to zip
                if args["incl_dir"] is not None:
                    if isinstance(args["incl_dir"], dict) and "data" in args["incl_dir"] and "name" in args["incl_dir"]:
                        if isinstance(args["incl_dir"]["data"], list) and isinstance(args["incl_dir"]["name"], list):
                            if len(args["incl_dir"]["data"]) != len(args["incl_dir"]["name"]):
                                raise UserError("Invalid incl_dir provided")
                            for i in range(len(args["incl_dir"]["data"])):
                                zf.writestr(os.path.basename(args["incl_dir"]["name"][i]), args["incl_dir"]["data"][i])
                    else:
                        if os.path.exists(args["incl_dir"]):
                            files = next(os.walk(args["incl_dir"]))[2]
                            for filename in files:
                                with open(os.path.join(args["incl_dir"], filename), "rb") as f:
                                    zf.writestr(os.path.basename(f.name), f.read())
                        else:
                            logger.warning(
                                "Specified include directory %s does not exist. Skipping...", args["incl_dir"]
                            )

            cert_pkg = sf.getvalue()

            # put the private key into the data to be send to the CV
            self.revocation_key = privkey.decode("utf-8")

            # encrypt up the cert package
            ret = user_data_encrypt.encrypt(cert_pkg)
            self.K = ret["k"]
            self.U = ret["u"]
            self.V = ret["v"]
            self.metadata = {"cert_serial": serial, "subject": subject}
            self.payload = ret["ciphertext"]

        if self.payload is not None:
            max_payload_size = config.getint("tenant", "max_payload_size")
            if len(self.payload) > max_payload_size:
                raise UserError(f"Payload size {len(self.payload)} exceeds max size {max_payload_size}")

    def preloop(self):
        """encrypt the agent UUID as a check for delivering the correct key"""
        self.auth_tag = crypto.do_hmac(self.K, self.agent_uuid)
        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if config.INSECURE_DEBUG:
            logger.debug("K: %s", base64.b64encode(self.K))
            logger.debug("V: %s", base64.b64encode(self.V))
            logger.debug("U: %s", base64.b64encode(self.U))
            logger.debug("Auth Tag: %s", self.auth_tag)

    def check_ek(self, ekcert):
        """Check the Entity Key

        Arguments:
            ekcert {str} -- The endorsement key, either None, "emulator", or base64 encoded der cert

        Returns:
            [type] -- [description]
        """
        if config.getboolean("tenant", "require_ek_cert"):
            if ekcert == "emulator" and config.DISABLE_EK_CERT_CHECK_EMULATOR:
                logger.info("Not checking ekcert of TPM emulator")
            elif ekcert is None:
                logger.warning("No EK cert provided, require_ek_cert option in config set to True")
                return False
            elif not self.tpm_instance.verify_ek(base64.b64decode(ekcert), config.get("tenant", "tpm_cert_store")):
                logger.warning("Invalid EK certificate")
                return False

        return True

    def validate_tpm_quote(self, public_key, quote, hash_alg):
        """Validate TPM Quote received from the Agent

        Arguments:
            public_key {[type]} -- [description]
            quote {[type]} -- [description]
            hash_alg {bool} -- [description]

        Raises:
            UserError: [description]

        Returns:
            [type] -- [description]
        """
        if self.registrar_data is None:
            logger.warning("AIK not found in registrar, quote not validated")
            return False

        if not self.nonce:
            logger.warning("Nonce has not been set!")
            return False

        failure = self.tpm_instance.check_quote(
            AgentAttestState(self.agent_uuid),
            self.nonce,
            public_key,
            quote,
            self.registrar_data["aik_tpm"],
            hash_alg=hash_alg,
            compressed=(self.supported_version == "1.0"),
        )
        if failure:
            if self.registrar_data["regcount"] > 1:
                logger.error(
                    "WARNING: This UUID had more than one ek-ekcert registered to it! This might indicate that your system is misconfigured or a malicious host is present. Run 'regdelete' for this agent and restart"
                )
                sys.exit()
            return False

        if self.registrar_data["regcount"] > 1:
            logger.warning(
                "WARNING: This UUID had more than one ek-ekcert registered to it! This might indicate that your system is misconfigured. Run 'regdelete' for this agent and restart"
            )

        if not config.getboolean("tenant", "require_ek_cert") and config.get("tenant", "ek_check_script") == "":
            logger.warning(
                "DANGER: EK cert checking is disabled and no additional checks on EKs have been specified with ek_check_script option. Keylime is not secure!!"
            )
            return True

        # check EK cert and make sure it matches EK
        if not self.check_ek(self.registrar_data["ekcert"]):
            return False
        # if agent is virtual, check phyisical EK cert and make sure it matches phyiscal EK
        if "provider_keys" in self.registrar_data:
            if not self.check_ek(self.registrar_data["provider_keys"]["ekcert"]):
                return False

        # check all EKs with optional script:
        script = config.get("tenant", "ek_check_script")
        if not script:
            return True

        if script[0] != "/":
            script = os.path.join(config.WORK_DIR, script)

        logger.info("Checking EK with script %s", script)
        # now we need to exec the script with the ek and ek cert in vars
        env = os.environ.copy()
        env["AGENT_UUID"] = self.agent_uuid
        env["EK"] = (
            tpm2_objects.pubkey_from_tpm2b_public(
                base64.b64decode(self.registrar_data["ek_tpm"]),
            )
            .public_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        env["EK_TPM"] = self.registrar_data["ek_tpm"]
        if self.registrar_data["ekcert"] is not None:
            env["EK_CERT"] = self.registrar_data["ekcert"]
        else:
            env["EK_CERT"] = ""

        env["PROVKEYS"] = json.dumps(self.registrar_data.get("provider_keys", {}))

        # Define the TPM cert store for the external script.
        env["TPM_CERT_STORE"] = config.get("tenant", "tpm_cert_store")

        return cert_utils.verify_ek_script(script, env, config.WORK_DIR)

    def do_cvadd(self):
        """Initiate v, agent_id and ip and initiate the cloudinit sequence"""
        b64_v = base64.b64encode(self.V).decode("utf-8")
        logger.debug("b64_v: %s", b64_v)
        data = {
            "v": b64_v,
            "cloudagent_ip": self.cv_cloudagent_ip,
            "cloudagent_port": self.agent_port,
            "tpm_policy": json.dumps(self.tpm_policy),
            "ima_policy_bundle": json.dumps(self.allowlist),
            "ima_policy_name": self.ima_policy_name,
            "mb_refstate": json.dumps(self.mb_refstate),
            "ima_sign_verification_keys": json.dumps(self.ima_sign_verification_keys),
            "metadata": json.dumps(self.metadata),
            "revocation_key": self.revocation_key,
            "accept_tpm_hash_algs": self.accept_tpm_hash_algs,
            "accept_tpm_encryption_algs": self.accept_tpm_encryption_algs,
            "accept_tpm_signing_algs": self.accept_tpm_signing_algs,
            "ak_tpm": self.registrar_data["aik_tpm"],
            "mtls_cert": self.registrar_data.get("mtls_cert", None),
            "supported_version": self.supported_version,
        }
        json_message = json.dumps(data)
        do_cv = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cv.post(
            (f"/v{self.api_version}/agents/{self.agent_uuid}"), data=json_message, timeout=self.request_timeout
        )

        if response.status_code == 503:
            logger.error(
                "Cannot connect to Verifier at %s with Port %s. Connection refused.",
                self.verifier_ip,
                self.verifier_port,
            )
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 409:
            # this is a conflict, need to update or delete it
            print(response_json)
            sys.exit()
        elif response.status_code != 200:
            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            logger.error(
                "POST command response: %s Unexpected response from Cloud Verifier: %s",
                response.status_code,
                response.text,
            )
            sys.exit()
        else:
            numtries = 0
            added = False

            while not added:
                reponse_json = self.do_cvstatus()
                if reponse_json["code"] != 200:
                    numtries += 1
                    if numtries >= self.maxr:
                        logger.error(
                            "Agent ID %s still not added to the Verifier after %d tries",
                            self.agent_uuid,
                            numtries,
                        )
                        sys.exit()
                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "Agent ID %s still not added to the Verifier at try %d of %d , trying again in %s seconds...",
                        self.agent_uuid,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                else:
                    added = True

            if added:
                logger.info(
                    "Agent ID %s added to the Verifier after %d tries",
                    self.agent_uuid,
                    numtries,
                )

    def do_cvstatus(self):
        """Perform operational state look up for agent on the verifier"""

        do_cvstatus = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)

        response = do_cvstatus.get((f"/v{self.api_version}/agents/{self.agent_uuid}"), timeout=self.request_timeout)

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 503:
            logger.error(
                "Cannot connect to Verifier at %s with Port %s. Connection refused.",
                self.verifier_ip,
                self.verifier_port,
            )
            return response_json
        if response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            return response_json
        if response.status_code == 404:
            logger.info(
                "Verifier at %s with Port %s does not have agent %s.",
                self.verifier_ip,
                self.verifier_port,
                self.agent_uuid,
            )
            return response_json

        if response.status_code == 200:
            res = response_json.pop("results")
            response_json["results"] = {self.agent_uuid: res}

            operational_state = states.state_to_str(response_json["results"][self.agent_uuid]["operational_state"])
            response_json["results"][self.agent_uuid]["operational_state"] = operational_state

            logger.info("Agent Info:\n%s", json.dumps(response_json["results"]))

            return response_json

        logger.info(
            "Status command response: %s. Unexpected response from Cloud Verifier %s on port %s. %s",
            response.status_code,
            self.verifier_ip,
            self.verifier_port,
            str(response),
        )
        return response_json

    def do_cvlist(self):
        """List all agent statuses in cloudverifier"""

        do_cvstatus = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)

        verifier_id = ""
        if self.verifier_id is not None:
            verifier_id = self.verifier_id

        response = do_cvstatus.get(f"/v{self.api_version}/agents/?verifier={verifier_id}", timeout=self.request_timeout)

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 503:
            logger.error(
                "Cannot connect to Verifier at %s with Port %s. Connection refused.",
                self.verifier_ip,
                self.verifier_port,
            )
            return response_json
        if response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            return response_json
        if response.status_code == 404:
            logger.info(
                "Verifier at %s with Port %s does not have agent %s.",
                self.verifier_ip,
                self.verifier_port,
                self.agent_uuid,
            )
            return response_json
        if response.status_code == 200:

            logger.info('From verifier %s port %s retrieved: "%s"', self.verifier_ip, self.verifier_port, response_json)

            return response

        logger.info(
            "Status command response: %s. Unexpected response from Cloud Verifier %s on port %s. %s",
            response.status_code,
            self.verifier_ip,
            self.verifier_port,
            str(response),
        )
        return response

    def do_cvbulkinfo(self):
        """Perform operational state look up for agent"""

        do_cvstatus = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)

        verifier_id = ""
        if self.verifier_id is not None:
            verifier_id = self.verifier_id

        response = do_cvstatus.get(
            f"/v{self.api_version}/agents/?bulk={True}&verifier={verifier_id}", timeout=self.request_timeout
        )

        response_json = Tenant._jsonify_response(response, print_response=False)

        if response.status_code == 200:

            for agent in response_json["results"].keys():
                response_json["results"][agent]["operational_state"] = states.state_to_str(
                    response_json["results"][agent]["operational_state"]
                )
            logger.info("Bulk Agent Info:\n%s", json.dumps(response_json["results"]))

            return response_json

        raise UserError(
            f"Bulk Status: Unexpected response from Verifier {self.verifier_ip} on port {self.verifier_port}. Response status code is {response.status_code}"
        )

    def do_cvdelete(self, verifier_check=True):
        """Delete agent from Verifier."""
        if verifier_check:
            cvresponse = self.do_cvstatus()

            if not isinstance(cvresponse, dict):
                keylime_logging.log_http_response(logger, logging.ERROR, cvresponse)
                sys.exit()

            if cvresponse["code"] == 404:
                logger.info(
                    "Agent ID %s deleted from Verifier",
                    self.agent_uuid,
                )
                return

            self.verifier_ip = cvresponse["results"][self.agent_uuid]["verifier_ip"]
            self.verifier_port = cvresponse["results"][self.agent_uuid]["verifier_port"]

        do_cvdelete = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cvdelete.delete(f"/v{self.api_version}/agents/{self.agent_uuid}", timeout=self.request_timeout)

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response_json["code"] == 503:
            logger.error(
                "Cannot connect to Verifier at %s with Port %s. Connection refused.",
                self.verifier_ip,
                self.verifier_port,
            )
            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            sys.exit()

        if response_json["code"] == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            sys.exit()

        if response_json["code"] == 202:
            numtries = 0
            deleted = False

            while not deleted:
                reponse_json = self.do_cvstatus()
                if reponse_json["code"] != 404:
                    numtries += 1
                    if numtries >= self.maxr:
                        logger.error(
                            "Agent ID %s still not deleted from the Verifier after %d tries",
                            self.agent_uuid,
                            numtries,
                        )
                        sys.exit()
                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "Agent ID %s still not deleted from the Verifier at try %d of %d , trying again in %s seconds...",
                        self.agent_uuid,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                else:
                    deleted = True

            if deleted:
                logger.info(
                    "Agent ID %s deleted from the Verifier after %d tries",
                    self.agent_uuid,
                    numtries,
                )

                logger.info("Agent %s deleted from the CV", self.agent_uuid)

    def do_regstatus(self):
        agent_info = registrar_client.getData(self.registrar_ip, self.registrar_port, self.agent_uuid, self.tls_context)

        if not agent_info:
            logger.info(
                "Agent %s does not exist on the registrar. Please register the agent with the registrar.",
                self.agent_uuid,
            )
            response = {
                "code": 404,
                "status": f"Agent {self.agent_uuid} does not exist on "
                f"registrar {self.registrar_ip} port {self.registrar_port}.",
                "results": {},
            }
            logger.info(json.dumps(response))
            return response

        response = {
            "code": 200,
            "status": f"Agent {self.agent_uuid} exists on "
            f"registrar {self.registrar_ip} port {self.registrar_port}.",
            "results": {},
        }
        response["results"][self.agent_uuid] = agent_info
        response["results"][self.agent_uuid]["operational_state"] = states.state_to_str(states.REGISTERED)

        logger.info(json.dumps(response))

        return response

    def do_reglist(self):
        """List agents from Registrar"""
        response = registrar_client.doRegistrarList(
            self.registrar_ip, self.registrar_port, tls_context=self.tls_context
        )

        logger.info(
            "From registrar %s port %s retrieved %s", self.registrar_ip, self.registrar_port, json.dumps(response)
        )
        return response

    def do_regdelete(self):
        """Delete agent from Registrar"""
        response = registrar_client.doRegistrarDelete(
            self.registrar_ip, self.registrar_port, self.agent_uuid, tls_context=self.tls_context
        )

        return response

    def do_status(self):
        """Perform operational state look up for agent"""

        regresponse = self.do_regstatus()

        if regresponse["code"] == 404:
            return regresponse

        cvresponse = self.do_cvstatus()

        if not isinstance(cvresponse, dict):
            logger.error(
                "Unexpected response from Cloud Verifier %s on port %s. response %s",
                self.verifier_ip,
                self.verifier_port,
                str(cvresponse),
            )
            return cvresponse

        if regresponse["code"] == 200 and cvresponse["code"] == 200:
            return cvresponse
        if regresponse["code"] == 200 and cvresponse["code"] != 200:
            return regresponse

        logger.error(
            "Unknown inconsistent state between registrar %s on "
            "port %s and verifier %s on port %s occured. Got "
            "registrar response %s verifier response %s",
            self.verifier_ip,
            self.verifier_port,
            self.registrar_ip,
            self.registrar_port,
            str(regresponse),
            str(cvresponse),
        )

        return {"registrar": regresponse, "verifier": cvresponse}

    def do_cvreactivate(self, verifier_check=True):
        """Reactive Agent."""
        if verifier_check:
            agent_json = self.do_cvstatus()
            self.verifier_ip = agent_json["results"][self.agent_uuid]["verifier_ip"]
            self.verifier_port = agent_json["results"][self.agent_uuid]["verifier_port"]

        do_cvreactivate = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cvreactivate.put(
            f"/v{self.api_version}/agents/{self.agent_uuid}/reactivate",
            data=b"",
            timeout=self.request_timeout,
        )

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code == 503:
            logger.error(
                "Cannot connect to Verifier at %s with Port %s. Connection refused.",
                self.verifier_ip,
                self.verifier_port,
            )
            return response_json
        if response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            return response_json
        if response.status_code == 200:
            logger.info("Agent %s re-activated", self.agent_uuid)
            return response_json

        keylime_logging.log_http_response(logger, logging.ERROR, response_json)
        logger.error("Reactivate command response: %s Unexpected response from Cloud Verifier.", response.status_code)
        return response_json

    def do_cvstop(self):
        """Stop declared active agent"""
        params = f"/v{self.api_version}/agents/{self.agent_uuid}/stop"
        do_cvstop = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = do_cvstop.put(params, data=b"", timeout=self.request_timeout)

        if response.status_code == 503:
            logger.error(
                "Cannot connect to Verifier at %s with Port %s. Connection refused.",
                self.verifier_ip,
                self.verifier_port,
            )
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

        if response.status_code != 200:
            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            logger.error("Stop command response: %s Unexpected response from Cloud Verifier.", response.status_code)
        else:
            logger.info("Agent %s stopped", self.agent_uuid)

    def do_quote(self):
        """Perform TPM quote by GET towards Agent

        Raises:
            UserError: Connection handler
        """
        self.nonce = TPM_Utilities.random_password(20)

        numtries = 0
        response = None
        # Note: We need a specific retry handler (perhaps in common), no point having localised unless we have too.
        while True:
            try:
                params = f"/v{self.supported_version}/quotes/identity?nonce=%s" % (self.nonce)
                cloudagent_base_url = f"{self.agent_ip}:{self.agent_port}"

                if self.enable_agent_mtls and self.registrar_data and self.registrar_data["mtls_cert"]:
                    with RequestsClient(
                        cloudagent_base_url,
                        self.enable_agent_mtls,
                        tls_context=self.agent_tls_context,
                    ) as do_quote:
                        response = do_quote.get(params, timeout=self.request_timeout)
                else:
                    logger.warning("Connecting to agent without using mTLS!")
                    do_quote = RequestsClient(cloudagent_base_url, tls_enabled=False)
                    response = do_quote.get(params, timeout=self.request_timeout)

                response_json = Tenant._jsonify_response(response, print_response=True, raise_except=True)

            except Exception as e:
                if response is None or response.status_code in (503, 504):
                    numtries += 1
                    if numtries >= self.maxr:
                        logger.error(
                            "Tenant cannot establish connection to agent on %s with port %s",
                            self.agent_ip,
                            self.agent_port,
                        )
                        sys.exit()
                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "Tenant connection to agent at %s refused %s/%s times, trying again in %s seconds...",
                        self.agent_ip,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                    continue

                raise e
            break

        if response is not None and response.status_code != 200:
            raise UserError(f"Status command response: {response.status_code} Unexpected response from Cloud Agent.")

        if "results" not in response_json:
            raise UserError(f"Error: unexpected http response body from Cloud Agent: {str(response.status_code)}")

        quote = response_json["results"]["quote"]
        logger.debug("Agent_quote received quote: %s", quote)

        public_key = response_json["results"]["pubkey"]
        logger.debug("Agent_quote received public key: %s", public_key)

        # Ensure hash_alg is in accept_tpm_hash_algs list
        hash_alg = response_json["results"]["hash_alg"]
        logger.debug("Agent_quote received hash algorithm: %s", hash_alg)
        if not algorithms.is_accepted(
            hash_alg, config.getlist("tenant", "accept_tpm_hash_algs")
        ) or not algorithms.Hash.is_recognized(hash_alg):
            raise UserError(f"TPM Quote is using an unaccepted hash algorithm: {hash_alg}")

        # Ensure enc_alg is in accept_tpm_encryption_algs list
        enc_alg = response_json["results"]["enc_alg"]
        logger.debug("Agent_quote received encryption algorithm: %s", enc_alg)
        if not algorithms.is_accepted(enc_alg, config.getlist("tenant", "accept_tpm_encryption_algs")):
            raise UserError(f"TPM Quote is using an unaccepted encryption algorithm: {enc_alg}")

        # Ensure sign_alg is in accept_tpm_encryption_algs list
        sign_alg = response_json["results"]["sign_alg"]
        logger.debug("Agent_quote received signing algorithm: %s", sign_alg)
        if not algorithms.is_accepted(sign_alg, config.getlist("tenant", "accept_tpm_signing_algs")):
            raise UserError(f"TPM Quote is using an unaccepted signing algorithm: {sign_alg}")

        if not self.validate_tpm_quote(public_key, quote, algorithms.Hash(hash_alg)):
            raise UserError(f"TPM Quote from cloud agent is invalid for nonce: {self.nonce}")

        logger.info("Quote from %s validated", self.agent_ip)

        # encrypt U with the public key
        encrypted_U = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key), self.U)

        b64_encrypted_u = base64.b64encode(encrypted_U)
        logger.debug("b64_encrypted_u: %s", b64_encrypted_u.decode("utf-8"))
        data = {"encrypted_key": b64_encrypted_u.decode("utf-8"), "auth_tag": self.auth_tag}

        if self.payload is not None:
            data["payload"] = self.payload.decode("utf-8")

        # post encrypted U back to CloudAgent
        params = f"/v{self.supported_version}/keys/ukey"
        cloudagent_base_url = f"{self.agent_ip}:{self.agent_port}"

        if self.enable_agent_mtls and self.registrar_data and self.registrar_data["mtls_cert"]:
            with RequestsClient(
                cloudagent_base_url,
                self.enable_agent_mtls,
                tls_context=self.agent_tls_context,
            ) as post_ukey:
                response = post_ukey.post(params, json=data, timeout=self.request_timeout)
        else:
            logger.warning("Connecting to agent without using mTLS!")
            post_ukey = RequestsClient(cloudagent_base_url, tls_enabled=False)
            response = post_ukey.post(params, json=data, timeout=self.request_timeout)

        if response.status_code == 503:
            logger.error(
                "Cannot connect to Agent at %s with Port %s. Connection refused.", self.agent_ip, self.agent_port
            )
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        if response.status_code != 200:
            keylime_logging.log_http_response(logger, logging.ERROR, response_json)
            raise UserError(
                f"Posting of Encrypted U to the Cloud Agent failed with response code {response.status_code} ({response.text})"
            )

    def do_verify(self):
        """Perform verify using a random generated challenge"""
        challenge = TPM_Utilities.random_password(20)
        numtries = 0

        while True:
            response = None
            try:
                cloudagent_base_url = f"{self.agent_ip}:{self.agent_port}"

                if self.registrar_data and self.registrar_data["mtls_cert"]:
                    with RequestsClient(
                        cloudagent_base_url,
                        self.enable_agent_mtls,
                        tls_context=self.agent_tls_context,
                    ) as do_verify:
                        response = do_verify.get(
                            f"/v{self.supported_version}/keys/verify?challenge={challenge}",
                            timeout=self.request_timeout,
                        )
                else:
                    logger.warning("Connecting to agent without using mTLS!")
                    do_verify = RequestsClient(cloudagent_base_url, tls_enabled=False)
                    response = do_verify.get(
                        f"/v{self.supported_version}/keys/verify?challenge={challenge}", timeout=self.request_timeout
                    )

                response_json = Tenant._jsonify_response(response, print_response=False, raise_except=True)

            except Exception as e:
                if response is not None and response.status_code in (503, 504):
                    numtries += 1
                    if numtries >= self.maxr:
                        logger.error(
                            "Cannot establish connection to agent on %s with port %s", self.agent_ip, self.agent_port
                        )
                        self.do_cvstop()
                        sys.exit()
                    next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                    logger.info(
                        "Verifier connection to agent at %s refused %s/%s times, trying again in %s seconds...",
                        self.agent_ip,
                        numtries,
                        self.maxr,
                        next_retry,
                    )
                    time.sleep(next_retry)
                    continue
                self.do_cvstop()
                raise e
            if response.status_code == 200:
                if "results" not in response_json or "hmac" not in response_json["results"]:
                    logger.critical("Error: unexpected http response body from Cloud Agent: %s", response.status_code)
                    self.do_cvstop()
                    break
                mac = response_json["results"]["hmac"]

                ex_mac = crypto.do_hmac(self.K, challenge)

                if mac == ex_mac:
                    logger.info("Key derivation successful")
                else:
                    logger.error("Key derivation failed")
                    self.do_cvstop()
            else:
                keylime_logging.log_http_response(logger, logging.ERROR, response_json)
                numtries += 1
                if numtries >= self.maxr:
                    logger.error("Agent on %s with port %s failed key derivation", self.agent_ip, self.agent_port)
                    self.do_cvstop()
                    sys.exit()
                next_retry = retry.retry_time(self.exponential_backoff, self.retry_interval, numtries, logger)
                logger.info(
                    "Key derivation not yet complete (retry %s/%s), trying again in %s seconds... (Ctrl-C to stop)",
                    numtries,
                    self.maxr,
                    next_retry,
                )
                time.sleep(next_retry)
                continue
            break

    def do_add_allowlist(self, args):
        if "allowlist_name" not in args or not args["allowlist_name"]:
            raise UserError("allowlist_name is required to add an allowlist")

        (
            self.tpm_policy,
            self.mb_refstate,
            self.ima_policy_name,
            self.ima_sign_verification_keys,
            self.allowlist,
        ) = policies.process_allowlist(args)

        data = {"tpm_policy": json.dumps(self.tpm_policy), "ima_policy_bundle": json.dumps(self.allowlist)}
        body = json.dumps(data)
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.post(
            f"/v{self.api_version}/allowlists/{self.ima_policy_name}", data=body, timeout=self.request_timeout
        )
        Tenant._jsonify_response(response)

    def do_delete_allowlist(self, name):
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.delete(f"/v{self.api_version}/allowlists/{name}", timeout=self.request_timeout)
        Tenant._jsonify_response(response)

    def do_show_allowlist(self, name):  # pylint: disable=unused-argument
        cv_client = RequestsClient(self.verifier_base_url, True, tls_context=self.tls_context)
        response = cv_client.get(f"/v{self.api_version}/allowlists/{name}", timeout=self.request_timeout)
        print(f"Show allowlist command response: {response.status_code}.")
        Tenant._jsonify_response(response)

    @staticmethod
    def _jsonify_response(response, print_response=True, raise_except=False):
        try:
            json_response = response.json()
        except ValueError as e:
            if raise_except:
                raise ValueError("Unable to convert response to JSON format") from e
            json_response = {}

        if print_response:
            print(json_response)
        return json_response


def write_to_namedtempfile(data, delete_tmp_files):
    temp = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
        prefix="keylime-", delete=delete_tmp_files
    )
    temp.write(data)
    temp.flush()
    return temp.name


def main() -> None:
    """[summary]

    Keyword Arguments:
        argv {[type]} -- [description] (default: {sys.argv})

    Raises:
        UserError: [description]
        UserError: [description]
        UserError: [description]
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--command",
        action="store",
        dest="command",
        default="add",
        help="valid commands are add,delete,update,"
        "regstatus,cvstatus,status,reglist,cvlist,reactivate,"
        "regdelete,bulkinfo,addallowlist,showallowlist,deleteallowlist. defaults to add",
    )
    parser.add_argument(
        "-t", "--targethost", action="store", dest="agent_ip", help="the IP address of the host to provision"
    )
    parser.add_argument(
        "-tp", "--targetport", action="store", dest="agent_port", help="the Port of the host to provision"
    )
    parser.add_argument(
        "-r",
        "--registrarhost",
        action="store",
        dest="registrar_ip",
        help="the IP address of the registrar where to retrieve the agents data from.",
    )
    parser.add_argument(
        "-rp", "--registrarport", action="store", dest="registrar_port", help="the port of the registrar."
    )
    parser.add_argument(
        "--cv_targethost",
        action="store",
        default=None,
        dest="cv_agent_ip",
        help="the IP address of the host to provision that the verifier will use (optional).  Use only if different than argument to option -t/--targethost",
    )
    parser.add_argument("-v", "--cv", action="store", dest="verifier_ip", help="the IP address of the cloud verifier")
    parser.add_argument("-vp", "--cvport", action="store", dest="verifier_port", help="the port of the cloud verifier")
    parser.add_argument(
        "-vi", "--cvid", action="store", dest="verifier_id", help="the unique identifier of a cloud verifier"
    )
    parser.add_argument(
        "-nvc",
        "--no-verifier-check",
        action="store_false",
        dest="verifier_check",
        default=True,
        help="Disable the check to confirm if the agent is being processed by the specified verifier. Use only with -c/--command delete or reactivate",
    )
    parser.add_argument("-u", "--uuid", action="store", dest="agent_uuid", help="UUID for the agent to provision")
    parser.add_argument(
        "-f", "--file", action="store", default=None, help="Deliver the specified plaintext to the provisioned agent"
    )
    parser.add_argument(
        "--cert",
        action="store",
        dest="ca_dir",
        default=None,
        help='Create and deliver a certificate using a CA created by ca-util. Pass in the CA directory or use "default" to use the standard dir',
    )
    parser.add_argument(
        "-k", "--key", action="store", dest="keyfile", help="an intermedia key file produced by user_data_encrypt"
    )
    parser.add_argument(
        "-p",
        "--payload",
        action="store",
        default=None,
        help="Specify the encrypted payload to deliver with encrypted keys specified by -k",
    )
    parser.add_argument(
        "--include",
        action="store",
        dest="incl_dir",
        default=None,
        help="Include additional files in provided directory in certificate zip file.  Must be specified with --cert",
    )
    parser.add_argument(
        "--allowlist", action="store", dest="allowlist", default=None, help="Specify the file path of an allowlist"
    )
    parser.add_argument(
        "--signature-verification-key",
        "--sign_verification_key",
        action="append",
        dest="ima_sign_verification_keys",
        default=[],
        help="Specify an IMA file signature verification key",
    )
    parser.add_argument(
        "--signature-verification-key-sig",
        action="append",
        dest="ima_sign_verification_key_sigs",
        default=[],
        help="Specify the GPG signature file for an IMA file signature verification key; pair this option with --signature-verification-key",
    )
    parser.add_argument(
        "--signature-verification-key-sig-key",
        action="append",
        dest="ima_sign_verification_key_sig_keys",
        default=[],
        help="Specify the GPG public key file use to validate the --signature-verification-key-sig; pair this option with --signature-verification-key",
    )
    parser.add_argument(
        "--signature-verification-key-url",
        action="append",
        dest="ima_sign_verification_key_urls",
        default=[],
        help="Specify the URL for a remote IMA file signature verification key",
    )
    parser.add_argument(
        "--signature-verification-key-sig-url",
        action="append",
        dest="ima_sign_verification_key_sig_urls",
        default=[],
        help="Specify the URL for the remote GPG signature of a remote IMA file signature verification key; pair this option with --signature-verification-key-url",
    )
    parser.add_argument(
        "--signature-verification-key-sig-url-key",
        action="append",
        dest="ima_sign_verification_key_sig_url_keys",
        default=[],
        help="Specify the GPG public key file used to validate the --signature-verification-key-sig-url; pair this option with --signature-verification-key-url",
    )
    parser.add_argument(
        "--mb_refstate",
        action="store",
        dest="mb_refstate",
        default=None,
        help="Specify the location of a measure boot reference state (intended state)",
    )
    parser.add_argument(
        "--allowlist-checksum",
        action="store",
        dest="allowlist_checksum",
        default=None,
        help="Specify the SHA-256 checksum of an allowlist",
    )
    parser.add_argument(
        "--allowlist-sig",
        action="store",
        dest="allowlist_sig",
        default=None,
        help="Specify the GPG signature file of an allowlist",
    )
    parser.add_argument(
        "--allowlist-sig-key",
        action="store",
        dest="allowlist_sig_key",
        default=None,
        help="Specify the GPG public key file used to validate the --allowlist-sig or --allowlist-sig-url",
    )
    parser.add_argument(
        "--allowlist-url",
        action="store",
        dest="allowlist_url",
        default=None,
        help="Specify the URL of a remote allowlist",
    )
    parser.add_argument(
        "--allowlist-sig-url",
        action="store",
        dest="allowlist_sig_url",
        default=None,
        help="Specify the URL of the remote GPG signature file of an allowlist",
    )
    parser.add_argument(
        "--exclude",
        action="store",
        dest="ima_exclude",
        default=None,
        help="Specify the location of an IMA exclude list",
    )
    parser.add_argument(
        "--tpm_policy",
        action="store",
        dest="tpm_policy",
        default=None,
        help='Specify a TPM policy in JSON format. e.g., {"15":"0000000000000000000000000000000000000000"}',
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        default=False,
        help="Block on cryptographically checked key derivation confirmation from the agent once it has been provisioned",
    )
    parser.add_argument("--allowlist-name", help="The name of allowlist to operate with")
    parser.add_argument(
        "--supported-version",
        default=None,
        action="store",
        dest="supported_version",
        help="API version that is supported by the agent. Detected automatically by default",
    )

    args = parser.parse_args()

    argerr, argerrmsg = options.get_opts_error(args)
    if argerr:
        parser.error(argerrmsg)

    config.check_version("tenant", logger=logger)

    mytenant = Tenant()

    if args.agent_uuid is not None:
        mytenant.agent_uuid = args.agent_uuid
        if not validators.valid_agent_id(mytenant.agent_uuid):
            raise UserError("The agent ID set via agent uuid parameter use invalid characters")
    else:
        logger.warning("Using default UUID d432fbb3-d2f1-4a97-9ef7-75bd81c00000")
        mytenant.agent_uuid = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

    if args.verifier_id is not None:
        mytenant.verifier_id = args.verifier_id
    if args.verifier_ip is not None:
        mytenant.verifier_ip = args.verifier_ip
    if args.verifier_port is not None:
        mytenant.verifier_port = args.verifier_port

    if args.registrar_ip is not None:
        mytenant.registrar_ip = args.registrar_ip
    if args.registrar_port is not None:
        mytenant.registrar_port = args.registrar_port

    # we only need to fetch remote files if we are adding or updating
    if args.command in ["add", "update", "addallowlist"]:
        delete_tmp_files = logger.level > logging.DEBUG  # delete tmp files unless in DEBUG mode

        if args.allowlist_url:
            logger.info("Downloading Allowlist from %s", args.allowlist_url)
            response = requests.get(args.allowlist_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                args.allowlist = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Allowlist temporarily saved in %s", args.allowlist)
            else:
                raise Exception(
                    f"Downloading allowlist ({args.allowlist_url}) failed with status code {response.status_code}!"
                )

        if args.allowlist_sig_url:
            logger.info("Downloading Allowlist signature from %s", args.allowlist_sig_url)
            response = requests.get(args.allowlist_sig_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                args.allowlist_sig = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Allowlist signature temporarily saved in %s", args.allowlist_sig)
            else:
                raise Exception(
                    f"Downloading allowlist signature ({args.allowlist_sig_url}) failed with status code {response.status_code}!"
                )

        # verify all the local keys for which we have a signature file and a key to verify
        for i, key_file in enumerate(args.ima_sign_verification_keys):
            if len(args.ima_sign_verification_key_sigs) <= i:
                break
            keysig_file = args.ima_sign_verification_key_sigs[i]
            if len(args.ima_sign_verification_key_sig_keys) == 0:
                raise UserError(f"A gpg key is missing for key signature file '{keysig_file}'")

            gpg_key_file = args.ima_sign_verification_key_sig_keys[i]
            signing.verify_signature_from_file(gpg_key_file, key_file, keysig_file, "IMA file signing key")

            logger.info("Signature verification on %s was successful", key_file)

        # verify all the remote keys for which we have a signature URL and key to to verify
        # Append the downloaded key files to args.ima_sign_verification_keys
        for i, key_url in enumerate(args.ima_sign_verification_key_urls):

            logger.info("Downloading key from %s", key_url)
            response = requests.get(key_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                key_file = write_to_namedtempfile(response.content, delete_tmp_files)
                args.ima_sign_verification_keys.append(key_file)
                logger.debug("Key temporarily saved in %s", key_file)
            else:
                raise Exception(f"Downloading key ({key_url}) failed with status code {response.status_code}!")

            if len(args.ima_sign_verification_key_sig_urls) <= i:
                continue

            keysig_url = args.ima_sign_verification_key_sig_urls[i]

            if len(args.ima_sign_verification_key_sig_url_keys) == 0:
                raise UserError(f"A gpg key is missing for key signature URL '{keysig_url}'")

            logger.info("Downloading key signature from %s", keysig_url)
            response = requests.get(keysig_url, timeout=mytenant.request_timeout, allow_redirects=False)
            if response.status_code == 200:
                keysig_file = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Key signature temporarily saved in %s", keysig_file)
            else:
                raise Exception(
                    f"Downloading key signature ({key_url}) failed with status code {response.status_code}!"
                )

            gpg_key_file = args.ima_sign_verification_key_sig_url_keys[i]
            signing.verify_signature_from_file(gpg_key_file, key_file, keysig_file, "IMA file signing key")
            logger.info("Signature verification on %s was successful", key_url)

    if args.command == "add":
        mytenant.init_add(vars(args))
        mytenant.preloop()
        mytenant.do_quote()
        mytenant.do_cvadd()
        if args.verify:
            mytenant.do_verify()
    elif args.command == "update":
        mytenant.init_add(vars(args))
        mytenant.do_cvdelete(args.verifier_check)
        mytenant.preloop()
        mytenant.do_quote()
        mytenant.do_cvadd()
        if args.verify:
            mytenant.do_verify()
    elif args.command == "delete":
        mytenant.do_cvdelete(args.verifier_check)
    elif args.command == "status":
        mytenant.do_status()
    elif args.command == "cvstatus":
        mytenant.do_cvstatus()
    elif args.command == "bulkinfo":
        mytenant.do_cvbulkinfo()
    elif args.command == "cvlist":
        mytenant.do_cvlist()
    elif args.command == "reactivate":
        mytenant.do_cvreactivate(args.verifier_check)
    elif args.command == "regstatus":
        mytenant.do_regstatus()
    elif args.command == "reglist":
        mytenant.do_reglist()
    elif args.command == "regdelete":
        mytenant.do_regdelete()
    elif args.command == "addallowlist":
        mytenant.do_add_allowlist(vars(args))
    elif args.command == "showallowlist":
        mytenant.do_show_allowlist(args.allowlist_name)
    elif args.command == "deleteallowlist":
        mytenant.do_delete_allowlist(args.allowlist_name)
    else:
        raise UserError(f"Invalid command specified: {args.command}")
