#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import argparse
import base64
import hashlib
import io
import logging
import os
import subprocess
import sys
import time
import zipfile
import json
import tempfile
import requests

from cryptography.hazmat.primitives import serialization as crypto_serialization

from keylime.requests_client import RequestsClient
from keylime.common import states
from keylime import config
from keylime import keylime_logging
from keylime import registrar_client
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import tpm
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime import ima
from keylime import crypto
from keylime.cmd import user_data_encrypt
from keylime import ca_util
from keylime.common import algorithms
from keylime import ima_file_signatures
from keylime import measured_boot
from keylime import gpg

# setup logging
logger = keylime_logging.init_logging('tenant')

# special exception that suppresses stack traces when it happens
class UserError(Exception):
    pass


class Tenant():
    """Simple command processor example."""

    config = None

    cloudverifier_ip = None
    cloudverifier_port = None

    cloudagent_ip = None
    cv_cloudagent_ip = None
    cloudagent_port = None

    registrar_ip = None
    registrar_port = None

    webapp_ip = None
    webapp_port = None

    uuid_service_generate_locally = None
    agent_uuid = None

    K = None
    V = None
    U = None
    auth_tag = None

    tpm_policy = None
    vtpm_policy = {}
    metadata = {}
    allowlist = {}
    ima_sign_verification_keys = []
    revocation_key = ""
    accept_tpm_hash_algs = []
    accept_tpm_encryption_algs = []
    accept_tpm_signing_algs = []
    mb_refstate = None

    payload = None

    tpm_instance = tpm()

    def __init__(self):
        """ Set up required values and TLS
        """
        self.nonce = None
        self.agent_ip = None
        self.verifier_id = None
        self.agent_port = None
        self.verifier_ip = config.get('tenant', 'cloudverifier_ip')
        self.verifier_port = config.get('tenant', 'cloudverifier_port')
        self.registrar_ip = config.get('tenant', 'registrar_ip')
        self.registrar_port = config.get('tenant', 'registrar_port')
        self.webapp_port = config.getint('webapp', 'webapp_port')
        if not config.REQUIRE_ROOT and self.webapp_port < 1024:
            self.webapp_port += 2000
        self.webapp_ip = config.get('webapp', 'webapp_ip')

        self.my_cert, self.my_priv_key = self.get_tls_context()
        self.cert = (self.my_cert, self.my_priv_key)
        if config.getboolean('general', "enable_tls"):
            self.tls_enabled = True
        else:
            self.tls_enabled = False
            self.cert = ""
            logger.warning(
                "Warning: TLS is currently disabled, keys will be sent in the clear! This should only be used for testing.")

    @property
    def verifier_base_url(self):
        return f'{self.verifier_ip}:{self.verifier_port}'

    def get_tls_context(self):
        """Generate certifcate naming and path

        Returns:
            string -- my_cert (client_cert), my_priv_key (client private key)
        """
        my_cert = config.get('tenant', 'my_cert')
        my_priv_key = config.get('tenant', 'private_key')
        tls_dir = config.get('tenant', 'tls_dir')

        if tls_dir == 'default':
            my_cert = 'client-cert.crt'
            my_priv_key = 'client-private.pem'
            tls_dir = 'cv_ca'

        if tls_dir[0] != '/':
            tls_dir = os.path.abspath('%s/%s' % (config.WORK_DIR, tls_dir))

        logger.info("Setting up client TLS in %s", tls_dir)
        my_cert = "%s/%s" % (tls_dir, my_cert)
        my_priv_key = "%s/%s" % (tls_dir, my_priv_key)

        return my_cert, my_priv_key

    def process_allowlist(self, args):
        # Set up PCR values
        tpm_policy = config.get('tenant', 'tpm_policy')
        if "tpm_policy" in args and args["tpm_policy"] is not None:
            tpm_policy = args["tpm_policy"]
        self.tpm_policy = TPM_Utilities.readPolicy(tpm_policy)
        logger.info("TPM PCR Mask from policy is %s", self.tpm_policy['mask'])

        vtpm_policy = config.get('tenant', 'vtpm_policy')
        if "vtpm_policy" in args and args["vtpm_policy"] is not None:
            vtpm_policy = args["vtpm_policy"]
        self.vtpm_policy = TPM_Utilities.readPolicy(vtpm_policy)
        logger.info("TPM PCR Mask from policy is %s", self.vtpm_policy['mask'])

        if len(args.get("ima_sign_verification_keys")) > 0:
            # Auto-enable IMA (or-bit mask)
            self.tpm_policy['mask'] = "0x%X" % (
                    int(self.tpm_policy['mask'], 0) | (1 << config.IMA_PCR))

            # Add all IMA file signing verification keys to a keyring
            ima_keyring = ima_file_signatures.ImaKeyring()
            for filename in args["ima_sign_verification_keys"]:
                pubkey, keyidv2 = ima_file_signatures.get_pubkey_from_file(filename)
                if not pubkey:
                    raise UserError(
                        "File '%s' is not a file with a key" % filename)
                ima_keyring.add_pubkey(pubkey, keyidv2)
            self.ima_sign_verification_keys = ima_keyring.to_string()

        # Read command-line path string allowlist
        al_data = None

        if "allowlist" in args and args["allowlist"] is not None:

            self.enforce_pcrs(list(self.tpm_policy.keys()), [ config.IMA_PCR ], "IMA")

            # Auto-enable IMA (or-bit mask)
            self.tpm_policy['mask'] = "0x%X" % (
                    int(self.tpm_policy['mask'], 0) | (1 << config.IMA_PCR))

            if isinstance(args["allowlist"], str):
                if args["allowlist"] == "default":
                    args["allowlist"] = config.get('tenant', 'allowlist')
                al_data = ima.read_allowlist(args["allowlist"], args["allowlist_checksum"], args["allowlist_sig"], args["allowlist_sig_key"])
            elif isinstance(args["allowlist"], list):
                al_data = args["allowlist"]
            else:
                raise UserError("Invalid allowlist provided")

        # Read command-line path string IMA exclude list
        excl_data = None
        if "ima_exclude" in args and args["ima_exclude"] is not None:
            if isinstance(args["ima_exclude"], str):
                if args["ima_exclude"] == "default":
                    args["ima_exclude"] = config.get(
                        'tenant', 'ima_excludelist')
                excl_data = ima.read_excllist(args["ima_exclude"])
            elif isinstance(args["ima_exclude"], list):
                excl_data = args["ima_exclude"]
            else:
                raise UserError("Invalid exclude list provided")

        # Set up IMA
        if TPM_Utilities.check_mask(self.tpm_policy['mask'], config.IMA_PCR) or \
                TPM_Utilities.check_mask(self.vtpm_policy['mask'],
                                         config.IMA_PCR):
            # Process allowlists
            self.allowlist = ima.process_allowlists(al_data, excl_data)

        # Read command-line path string TPM event log (measured boot) reference state
        mb_refstate_data = None
        if "mb_refstate" in args and args["mb_refstate"] is not None:

            self.enforce_pcrs(list(self.tpm_policy.keys()), config.MEASUREDBOOT_PCRS, "measured boot")

            # Auto-enable TPM event log mesured boot (or-bit mask)
            for _pcr in config.MEASUREDBOOT_PCRS :
                self.tpm_policy['mask'] = "0x%X" % (
                    int(self.tpm_policy['mask'], 0) | (1 << _pcr))

            logger.info("TPM PCR Mask automatically modified is %s to include IMA/Event log PCRs", self.tpm_policy['mask'])

            if isinstance(args["mb_refstate"], str):
                if args["mb_refstate"] == "default":
                    args["mb_refstate"] = config.get('tenant', 'mb_refstate')
                mb_refstate_data = measured_boot.read_mb_refstate(args["mb_refstate"])
            else:
                raise UserError("Invalid measured boot reference state (intended state) provided")

        # Set up measured boot (TPM event log) reference state
        if TPM_Utilities.check_mask(self.tpm_policy['mask'], config.MEASUREDBOOT_PCRS[2]) :
            # Process measured boot reference state
            self.mb_refstate = mb_refstate_data

    def init_add(self, args):
        """ Set up required values. Command line options can overwrite these config values

        Arguments:
            args {[string]} -- agent_ip|agent_port|cv_agent_ip
        """
        if "agent_ip" in args:
            self.agent_ip = args["agent_ip"]

        if 'agent_port' in args and args['agent_port'] is not None:
            self.agent_port = args['agent_port']

        # try to get the port or ip from the registrar if it is missing
        if self.agent_ip is None or self.agent_port is None:
            registrar_client.init_client_tls("tenant")
            data = registrar_client.getData(self.registrar_ip, self.registrar_port, self.agent_uuid)
            if data is not None:
                if self.agent_ip is None:
                    if data['ip'] is not None:
                        self.agent_ip = data['ip']
                    else:
                        raise UserError("No Ip was specified or found in the Registrar")

                if self.agent_port is None and data['port'] is not None:
                    self.agent_port = data["port"]

        # If no agent port was found try to use the default from the config file
        if self.agent_port is None:
            self.agent_port = config.get('cloud_agent', 'cloudagent_port')

        # Check if a contact ip and port for the agent was found
        if self.agent_ip is None:
            raise UserError("The contact ip address for the agent was not specified.")

        if self.agent_port is None:
            raise UserError("The contact port for the agent was not specified.")

        # Now set the cv_agent_ip
        if 'cv_agent_ip' in args and args['cv_agent_ip'] is not None:
            self.cv_cloudagent_ip = args['cv_agent_ip']
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
        self.accept_tpm_hash_algs = config.get(
            'tenant', 'accept_tpm_hash_algs').split(',')
        self.accept_tpm_encryption_algs = config.get(
            'tenant', 'accept_tpm_encryption_algs').split(',')
        self.accept_tpm_signing_algs = config.get(
            'tenant', 'accept_tpm_signing_algs').split(',')

        self.process_allowlist(args)

        # if none
        if (args["file"] is None and args["keyfile"] is None and args["ca_dir"] is None):
            raise UserError(
                "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent")

        if args["keyfile"] is not None:
            if args["file"] is not None or args["ca_dir"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent")

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
                f = open(args["keyfile"], 'r')
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
                    f = open(args["payload"], 'r')
                    self.payload = f.read()
                    f.close()

        if args["file"] is not None:
            if args["keyfile"] is not None or args["ca_dir"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent")

            if isinstance(args["file"], dict) and "data" in args["file"]:
                if isinstance(args["file"]["data"], list) and len(args["file"]["data"]) > 0:
                    contents = args["file"]["data"][0]
                    if contents is None:
                        raise UserError("Invalid file payload contents")
                else:
                    raise UserError("Invalid file payload provided")
            else:
                with open(args["file"], 'r') as f:
                    contents = f.read()
            ret = user_data_encrypt.encrypt(contents)
            self.K = ret['k']
            self.U = ret['u']
            self.V = ret['v']
            self.payload = ret['ciphertext']

        if args["ca_dir"] is None and args["incl_dir"] is not None:
            raise UserError(
                "--include option is only valid when used with --cert")
        if args["ca_dir"] is not None:
            if args["file"] is not None or args["keyfile"] is not None:
                raise UserError(
                    "You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the agent")
            if args["ca_dir"] == 'default':
                args["ca_dir"] = config.CA_WORK_DIR

            if "ca_dir_pw" in args and args["ca_dir_pw"] is not None:
                ca_util.setpassword(args["ca_dir_pw"])

            if not os.path.exists(args["ca_dir"]) or not os.path.exists("%s/cacert.crt" % args["ca_dir"]):
                logger.warning("CA directory does not exist. Creating...")
                ca_util.cmd_init(args["ca_dir"])
            if not os.path.exists("%s/%s-private.pem" % (args["ca_dir"], self.agent_uuid)):
                ca_util.cmd_mkcert(args["ca_dir"], self.agent_uuid)

            cert_pkg, serial, subject = ca_util.cmd_certpkg(
                args["ca_dir"], self.agent_uuid)

            # support revocation
            if not os.path.exists("%s/RevocationNotifier-private.pem" % args["ca_dir"]):
                ca_util.cmd_mkcert(args["ca_dir"], "RevocationNotifier")
            rev_package, _, _ = ca_util.cmd_certpkg(
                args["ca_dir"], "RevocationNotifier")

            # extract public and private keys from package
            sf = io.BytesIO(rev_package)
            with zipfile.ZipFile(sf) as zf:
                privkey = zf.read("RevocationNotifier-private.pem")
                cert = zf.read("RevocationNotifier-cert.crt")

            # put the cert of the revoker into the cert package
            sf = io.BytesIO(cert_pkg)
            with zipfile.ZipFile(sf, 'a', compression=zipfile.ZIP_STORED) as zf:
                zf.writestr('RevocationNotifier-cert.crt', cert)

                # add additional files to zip
                if args["incl_dir"] is not None:
                    if isinstance(args["incl_dir"], dict) and "data" in args["incl_dir"] and "name" in args["incl_dir"]:
                        if isinstance(args["incl_dir"]["data"], list) and isinstance(args["incl_dir"]["name"], list):
                            if len(args["incl_dir"]["data"]) != len(args["incl_dir"]["name"]):
                                raise UserError("Invalid incl_dir provided")
                            for i in range(len(args["incl_dir"]["data"])):
                                zf.writestr(os.path.basename(
                                    args["incl_dir"]["name"][i]), args["incl_dir"]["data"][i])
                    else:
                        if os.path.exists(args["incl_dir"]):
                            files = next(os.walk(args["incl_dir"]))[2]
                            for filename in files:
                                with open("%s/%s" % (args["incl_dir"], filename), 'rb') as f:
                                    zf.writestr(
                                        os.path.basename(f.name), f.read())
                        else:
                            logger.warning('Specified include directory %s does not exist. Skipping...', args["incl_dir"])

            cert_pkg = sf.getvalue()

            # put the private key into the data to be send to the CV
            self.revocation_key = privkey.decode('utf-8')

            # encrypt up the cert package
            ret = user_data_encrypt.encrypt(cert_pkg)
            self.K = ret['k']
            self.U = ret['u']
            self.V = ret['v']
            self.metadata = {'cert_serial': serial, 'subject': subject}
            self.payload = ret['ciphertext']

        if self.payload is not None and len(self.payload) > config.getint('tenant', 'max_payload_size'):
            raise UserError("Payload size %s exceeds max size %d" % (
                len(self.payload), config.getint('tenant', 'max_payload_size')))

    def enforce_pcrs(self, policy_pcrs, protected_pcrs, pcr_use) :
        policy_pcrs = list(self.tpm_policy.keys())
        policy_pcrs.remove('mask')

        for _pcr in policy_pcrs :
            if int(_pcr) in protected_pcrs :
                logger.error('WARNING: PCR %s is specified in "tpm_policy", but will in fact be used by %s. Please remove it from policy', _pcr, pcr_use)
                sys.exit(1)

    def preloop(self):
        """ encrypt the agent UUID as a check for delivering the correct key
        """
        self.auth_tag = crypto.do_hmac(self.K, self.agent_uuid)
        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if config.INSECURE_DEBUG:
            logger.debug("K: %s", base64.b64encode(self.K))
            logger.debug("V: %s", base64.b64encode(self.V))
            logger.debug("U: %s", base64.b64encode(self.U))
            logger.debug("Auth Tag: %s", self.auth_tag)

    def check_ek(self, ekcert):
        """ Check the Entity Key

        Arguments:
            ekcert {str} -- The endorsement key, either None, "emulator", or base64 encoded der cert

        Returns:
            [type] -- [description]
        """
        if config.getboolean('tenant', 'require_ek_cert'):
            if config.STUB_TPM:
                logger.debug("Not checking ekcert due to STUB_TPM mode")
            elif ekcert == 'emulator' and config.DISABLE_EK_CERT_CHECK_EMULATOR:
                logger.info("Not checking ekcert of TPM emulator")
            elif ekcert is None:
                logger.warning("No EK cert provided, require_ek_cert option in config set to True")
                return False
            elif not self.tpm_instance.verify_ek(base64.b64decode(ekcert)):
                logger.warning("Invalid EK certificate")
                return False

        return True

    def validate_tpm_quote(self, public_key, quote, hash_alg):
        """ Validate TPM Quote received from the Agent

        Arguments:
            public_key {[type]} -- [description]
            quote {[type]} -- [description]
            hash_alg {bool} -- [description]

        Raises:
            UserError: [description]

        Returns:
            [type] -- [description]
        """
        registrar_client.init_client_tls('tenant')
        reg_data = registrar_client.getData(
            self.registrar_ip, self.registrar_port, self.agent_uuid)
        if reg_data is None:
            logger.warning("AIK not found in registrar, quote not validated")
            return False

        if not self.tpm_instance.check_quote(self.agent_uuid, self.nonce, public_key, quote, reg_data['aik_tpm'], hash_alg=hash_alg):
            if reg_data['regcount'] > 1:
                logger.error("WARNING: This UUID had more than one ek-ekcert registered to it! This might indicate that your system is misconfigured or a malicious host is present. Run 'regdelete' for this agent and restart")
                sys.exit()
            return False

        if reg_data['regcount'] > 1:
            logger.warning("WARNING: This UUID had more than one ek-ekcert registered to it! This might indicate that your system is misconfigured. Run 'regdelete' for this agent and restart")

        if not config.STUB_TPM and (not config.getboolean('tenant', 'require_ek_cert') and config.get('tenant', 'ek_check_script') == ""):
            logger.warning(
                "DANGER: EK cert checking is disabled and no additional checks on EKs have been specified with ek_check_script option. Keylime is not secure!!")

        # check EK cert and make sure it matches EK
        if not self.check_ek(reg_data['ekcert']):
            return False
        # if agent is virtual, check phyisical EK cert and make sure it matches phyiscal EK
        if 'provider_keys' in reg_data:
            if not self.check_ek(reg_data['provider_keys']['ekcert']):
                return False

        # check all EKs with optional script:
        script = config.get('tenant', 'ek_check_script')
        if not script:
            return True

        if script[0] != '/':
            script = "%s/%s" % (config.WORK_DIR, script)

        logger.info("Checking EK with script %s", script)
        # now we need to exec the script with the ek and ek cert in vars
        env = os.environ.copy()
        env['AGENT_UUID'] = self.agent_uuid
        env['EK'] = tpm2_objects.pubkey_from_tpm2b_public(
            base64.b64decode(reg_data['ek_tpm']),
            ).public_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        env['EK_TPM'] = reg_data['ek_tpm']
        if reg_data['ekcert'] is not None:
            env['EK_CERT'] = reg_data['ekcert']
        else:
            env['EK_CERT'] = ""

        env['PROVKEYS'] = json.dumps(reg_data.get('provider_keys', {}))
        proc = subprocess.Popen(script, env=env, shell=True,
                                cwd=config.WORK_DIR, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        retval = proc.wait()
        if retval != 0:
            raise UserError("External check script failed to validate EK")
        logger.debug("External check script successfully to validated EK")
        while True:
            line = proc.stdout.readline().decode()
            if line == "":
                break
            logger.debug("ek_check output: %s", line.strip())
        return True

    def do_cv(self):
        """ Initiaite v, agent_id and ip and initiate the cloudinit sequence
        """
        b64_v = base64.b64encode(self.V).decode('utf-8')
        logger.debug("b64_v: %s", b64_v)
        data = {
            'v': b64_v,
            'cloudagent_ip': self.cv_cloudagent_ip,
            'cloudagent_port': self.agent_port,
            'tpm_policy': json.dumps(self.tpm_policy),
            'vtpm_policy': json.dumps(self.vtpm_policy),
            'allowlist': json.dumps(self.allowlist),
            'mb_refstate': json.dumps(self.mb_refstate),
            'ima_sign_verification_keys': json.dumps(self.ima_sign_verification_keys),
            'metadata': json.dumps(self.metadata),
            'revocation_key': self.revocation_key,
            'accept_tpm_hash_algs': self.accept_tpm_hash_algs,
            'accept_tpm_encryption_algs': self.accept_tpm_encryption_algs,
            'accept_tpm_signing_algs': self.accept_tpm_signing_algs,
        }
        json_message = json.dumps(data)
        do_cv = RequestsClient(self.verifier_base_url, self.tls_enabled)
        response = do_cv.post(
            (f'/agents/{self.agent_uuid}'),
            data=json_message,
            cert=self.cert,
            verify=False
        )

        if response.status_code == 503:
            logger.error("Cannot connect to Verifier at %s with Port %s. Connection refused.", self.verifier_ip, self.verifier_port)
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        if response.status_code == 409:
            # this is a conflict, need to update or delete it
            logger.error("Agent %s already existed at CV. Please use delete or update.", self.agent_uuid)
            sys.exit()
        elif response.status_code != 200:
            keylime_logging.log_http_response(
                logger, logging.ERROR, response.json())
            logger.error("POST command response: %s Unexpected response from Cloud Verifier: %s", response.status_code, response.text)
            sys.exit()

    def do_cvstatus(self, listing=False, returnresponse=False, bulk=False):
        """ Perform opertional state look up for agent

        Keyword Arguments:
            listing {bool} -- If True, list all agent statues (default: {False})
        """
        agent_uuid = ""
        if not listing:
            agent_uuid = self.agent_uuid

        response = None
        do_cvstatus = RequestsClient(self.verifier_base_url, self.tls_enabled)
        if listing and (self.verifier_id is not None):
            verifier_id = self.verifier_id
            response = do_cvstatus.get(
                (f'/agents/?verifier={verifier_id}'),
                cert=self.cert,
                verify=False
            )
        elif (not listing) and (bulk):
            verifier_id = ""
            if self.verifier_id is not None:
                verifier_id = self.verifier_id
            response = do_cvstatus.get(
                (f'/agents/?bulk={bulk}&verifier={verifier_id}'),
                cert=self.cert,
                verify=False
            )
        else:
            response = do_cvstatus.get(
                (f'/agents/{agent_uuid}'),
                cert=self.cert,
                verify=False
            )

        if response.status_code == 503:
            logger.error("Cannot connect to Verifier at %s with Port %s. Connection refused.", self.verifier_ip, self.verifier_port)
            sys.exit()
        elif response == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        if response.status_code == 404:
            logger.error("Agent %s does not exist on the verifier. Please try to add or update agent", agent_uuid)
            sys.exit()

        if response.status_code != 200:
            logger.error("Status command response: %s. Unexpected response from Cloud Verifier.", response.status_code)
            sys.exit()
        else:
            response_json = response.json()
            if not returnresponse:
                if not listing:
                    if not bulk:
                        operational_state = response_json["results"]["operational_state"]
                        logger.info('Agent Status: "%s"', states.state_to_str(operational_state))
                    else:
                        for agent in response_json["results"].keys():
                            response_json["results"][agent]["operational_state"] = states.state_to_str(response_json["results"][agent]["operational_state"])
                        logger.info("Bulk Agent Info:\n%s" % json.dumps(response_json["results"]))
                else:
                    agent_array = response_json["results"]["uuids"]
                    logger.info('Agents: "%s"', agent_array)
            else:
                return response_json["results"]

        return None

    def do_cvdelete(self, verifier_check):
        """Delete agent from Verifier
        """
        if verifier_check:
            agent_json = self.do_cvstatus(listing=False, returnresponse=True)
            self.verifier_ip = agent_json["verifier_ip"]
            self.verifier_port = agent_json["verifier_port"]

        do_cvdelete = RequestsClient(self.verifier_base_url, self.tls_enabled)
        response = do_cvdelete.delete(
            (f'/agents/{self.agent_uuid}'),
            cert=self.cert,
            verify=False
        )

        if response.status_code == 503:
            logger.error("Cannot connect to Verifier at %s with Port %s. Connection refused.", self.verifier_ip, self.verifier_port)
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        if response.status_code == 202:
            deleted = False
            for _ in range(12):
                get_cvdelete = RequestsClient(
                    self.verifier_base_url, self.tls_enabled)
                response = get_cvdelete.get(
                    (f'/agents/{self.agent_uuid}'),
                    cert=self.cert,
                    verify=False
                )

                if response.status_code == 404:
                    deleted = True
                    break
                time.sleep(.4)
            if deleted:
                logger.info("CV completed deletion of agent %s", self.agent_uuid)
            else:
                logger.error("Timed out waiting for delete of agent %s to complete at CV", self.agent_uuid)
                sys.exit()
        elif response.status_code == 200:
            logger.info("Agent %s deleted from the CV", self.agent_uuid)
        else:
            response_body = response.json()
            keylime_logging.log_http_response(
                logger, logging.ERROR, response_body)

    def do_reglist(self):
        """List agents from Registrar
        """
        registrar_client.init_client_tls('tenant')
        response = registrar_client.doRegistrarList(
            self.registrar_ip, self.registrar_port)
        print(response)

    def do_regdelete(self):
        """ Delete agent from Registrar
        """
        registrar_client.init_client_tls('tenant')
        registrar_client.doRegistrarDelete(
            self.registrar_ip, self.registrar_port, self.agent_uuid)

    def do_cvreactivate(self, verifier_check):
        """ Reactive Agent
        """
        if verifier_check:
            agent_json = self.do_cvstatus(listing=False, returnresponse=True)
            self.verifier_ip = agent_json['verifier_ip']
            self.verifier_port = agent_json['verifier_port']

        do_cvreactivate = RequestsClient(
            self.verifier_base_url, self.tls_enabled)
        response = do_cvreactivate.put(
            (f'/agents/{self.agent_uuid}/reactivate'),
            data=b'',
            cert=self.cert,
            verify=False
        )

        if response.status_code == 503:
            logger.error("Cannot connect to Verifier at %s with Port %s. Connection refused.", self.verifier_ip, self.verifier_port)
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        response_body = response.json()

        if response.status_code != 200:
            keylime_logging.log_http_response(
                logger, logging.ERROR, response_body)
            logger.error("Update command response: %s Unexpected response from Cloud Verifier.", response.status_code)
        else:
            logger.info("Agent %s re-activated", self.agent_uuid)

    def do_cvstop(self):
        """ Stop declared active agent
        """
        params = f'/agents/{self.agent_uuid}/stop'
        do_cvstop = RequestsClient(self.verifier_base_url, self.tls_enabled)
        response = do_cvstop.put(
            params,
            cert=self.cert,
            data=b'',
            verify=False
        )

        if response.status_code == 503:
            logger.error("Cannot connect to Verifier at %s with Port %s. Connection refused.", self.verifier_ip, self.verifier_port)
            sys.exit()
        elif response.status_code == 504:
            logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
            sys.exit()

        response_body = response.json()
        if response.status_code != 200:
            keylime_logging.log_http_response(
                logger, logging.ERROR, response_body)
        else:
            logger.info("Agent %s stopped", self.agent_uuid)

    def do_quote(self):
        """ Perform TPM quote by GET towards Agent

        Raises:
            UserError: Connection handler
        """
        self.nonce = TPM_Utilities.random_password(20)

        numtries = 0
        response = None
        # Note: We need a specific retry handler (perhaps in common), no point having localised unless we have too.
        while True:
            try:
                params = '/quotes/identity?nonce=%s' % (self.nonce)
                cloudagent_base_url = f'{self.agent_ip}:{self.agent_port}'
                do_quote = RequestsClient(cloudagent_base_url, tls_enabled=False)
                response = do_quote.get(
                    params,
                    cert=self.cert
                )
                response_body = response.json()

            except Exception as e:
                if response.status_code in (503, 504):
                    numtries += 1
                    maxr = config.getint('tenant', 'max_retries')
                    if numtries >= maxr:
                        logger.error("Tenant cannot establish connection to agent on %s with port %s", self.agent_ip, self.agent_port)
                        sys.exit()
                    retry = config.getfloat('tenant', 'retry_interval')
                    logger.info("Tenant connection to agent at %s refused %s/%s times, trying again in %s seconds...",
                        self.agent_ip, numtries, maxr, retry)
                    time.sleep(retry)
                    continue

                raise e
            break

        try:
            if response is not None and response.status_code != 200:
                raise UserError(
                    "Status command response: %d Unexpected response from Cloud Agent." % response.status)

            if "results" not in response_body:
                raise UserError(
                    "Error: unexpected http response body from Cloud Agent: %s" % str(response.status))

            quote = response_body["results"]["quote"]
            logger.debug("Agent_quote received quote: %s", quote)

            public_key = response_body["results"]["pubkey"]
            logger.debug("Agent_quote received public key: %s", public_key)

            # Ensure hash_alg is in accept_tpm_hash_algs list
            hash_alg = response_body["results"]["hash_alg"]
            logger.debug("Agent_quote received hash algorithm: %s", hash_alg)
            if not algorithms.is_accepted(hash_alg, config.get('tenant', 'accept_tpm_hash_algs').split(',')):
                raise UserError(
                    "TPM Quote is using an unaccepted hash algorithm: %s" % hash_alg)

            # Ensure enc_alg is in accept_tpm_encryption_algs list
            enc_alg = response_body["results"]["enc_alg"]
            logger.debug("Agent_quote received encryption algorithm: %s", enc_alg)
            if not algorithms.is_accepted(enc_alg, config.get('tenant', 'accept_tpm_encryption_algs').split(',')):
                raise UserError(
                    "TPM Quote is using an unaccepted encryption algorithm: %s" % enc_alg)

            # Ensure sign_alg is in accept_tpm_encryption_algs list
            sign_alg = response_body["results"]["sign_alg"]
            logger.debug("Agent_quote received signing algorithm: %s", sign_alg)
            if not algorithms.is_accepted(sign_alg, config.get('tenant', 'accept_tpm_signing_algs').split(',')):
                raise UserError(
                    "TPM Quote is using an unaccepted signing algorithm: %s" % sign_alg)

            if not self.validate_tpm_quote(public_key, quote, hash_alg):
                raise UserError(
                    "TPM Quote from cloud agent is invalid for nonce: %s" % self.nonce)

            logger.info("Quote from %s validated", self.agent_ip)

            # encrypt U with the public key
            encrypted_U = crypto.rsa_encrypt(
                crypto.rsa_import_pubkey(public_key), self.U)

            b64_encrypted_u = base64.b64encode(encrypted_U)
            logger.debug("b64_encrypted_u: %s", b64_encrypted_u.decode('utf-8'))
            data = {
                'encrypted_key': b64_encrypted_u.decode('utf-8'),
                'auth_tag': self.auth_tag
            }

            if self.payload is not None:
                data['payload'] = self.payload.decode('utf-8')

            u_json_message = json.dumps(data)

            # post encrypted U back to CloudAgent
            params = '/keys/ukey'
            cloudagent_base_url = (
                f'{self.agent_ip}:{self.agent_port}'
            )

            post_ukey = RequestsClient(cloudagent_base_url, tls_enabled=False)
            response = post_ukey.post(
                params,
                data=u_json_message
            )

            if response.status_code == 503:
                logger.error("Cannot connect to Agent at %s with Port %s. Connection refused.", self.agent_ip, self.agent_port)
                sys.exit()
            elif response.status_code == 504:
                logger.error("Verifier at %s with Port %s timed out.", self.verifier_ip, self.verifier_port)
                sys.exit()

            if response.status_code != 200:
                keylime_logging.log_http_response(
                    logger, logging.ERROR, response_body)
                raise UserError(
                    "Posting of Encrypted U to the Cloud Agent failed with response code %d" % response.status)
        except Exception as e:
            self.do_cvstop()
            raise e

    def do_verify(self):
        """ Perform verify using a random generated challenge
        """
        challenge = TPM_Utilities.random_password(20)
        numtries = 0
        while True:
            try:
                cloudagent_base_url = (
                    f'{self.agent_ip}:{self.agent_port}'
                )
                do_verify = RequestsClient(
                    cloudagent_base_url, tls_enabled=False)
                response = do_verify.get(
                    (f'/keys/verify?challenge={challenge}'),
                    cert=self.cert,
                    verify=False
                )
            except Exception as e:
                if response.status_code in (503, 504):
                    numtries += 1
                    maxr = config.getint('tenant', 'max_retries')
                    if numtries >= maxr:
                        logger.error("Cannot establish connection to agent on %s with port %s", self.agent_ip, self.agent_port)
                        sys.exit()
                    retry = config.getfloat('tenant', 'retry_interval')
                    logger.info("Verifier connection to agent at %s refused %s/%s times, trying again in %s seconds...",
                        self.agent_ip, numtries, maxr, retry)
                    time.sleep(retry)
                    continue

                raise e
            response_body = response.json()
            if response.status_code == 200:
                if "results" not in response_body or 'hmac' not in response_body['results']:
                    logger.critical("Error: unexpected http response body from Cloud Agent: %s", response.status_code)
                    break
                mac = response_body['results']['hmac']

                ex_mac = crypto.do_hmac(self.K, challenge)

                if mac == ex_mac:
                    logger.info("Key derivation successful")
                else:
                    logger.error("Key derivation failed")
            else:
                keylime_logging.log_http_response(
                    logger, logging.ERROR, response_body)
                retry = config.getfloat('tenant', 'retry_interval')
                logger.warning("Key derivation not yet complete...trying again in %s seconds...Ctrl-C to stop", retry)
                time.sleep(retry)
                continue
            break

    def do_add_allowlist(self, args):
        if 'allowlist_name' not in args or not args['allowlist_name']:
            raise UserError('allowlist_name is required to add an allowlist')

        allowlist_name = args['allowlist_name']
        self.process_allowlist(args)
        data = {
            'tpm_policy': json.dumps(self.tpm_policy),
            'vtpm_policy': json.dumps(self.vtpm_policy),
            'allowlist': json.dumps(self.allowlist)
        }
        body = json.dumps(data)
        cv_client = RequestsClient(self.verifier_base_url, self.tls_enabled)
        response = cv_client.post(f'/allowlists/{allowlist_name}', data=body,
                                  cert=self.cert, verify=False)
        print(response.json())

    def do_delete_allowlist(self, name):
        cv_client = RequestsClient(self.verifier_base_url, self.tls_enabled)
        response = cv_client.delete(f'/allowlists/{name}',
                                    cert=self.cert, verify=False)
        print(response.json())

    def do_show_allowlist(self, name):
        cv_client = RequestsClient(self.verifier_base_url, self.tls_enabled)
        response = cv_client.get(f'/allowlists/{name}',
                                 cert=self.cert, verify=False)
        print(f"Show allowlist command response: {response.status_code}.")
        print(response.json())

def write_to_namedtempfile(data, delete_tmp_files):
    temp = tempfile.NamedTemporaryFile(prefix="keylime-", delete=delete_tmp_files)
    temp.write(data)
    temp.flush()
    return temp.name

def main(argv=sys.argv):
    """[summary]

    Keyword Arguments:
        argv {[type]} -- [description] (default: {sys.argv})

    Raises:
        UserError: [description]
        UserError: [description]
        UserError: [description]
    """
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('-c', '--command', action='store', dest='command', default='add',
                        help="valid commands are add,delete,update,status,list,reactivate,regdelete,bulkinfo. defaults to add")
    parser.add_argument('-t', '--targethost', action='store',
                        dest='agent_ip', help="the IP address of the host to provision")
    parser.add_argument('-tp', '--targetport', action='store',
                        dest='agent_port', help="the Port of the host to provision")
    parser.add_argument('-r', '--registrarhost', action='store',
                        dest='registrar_ip', help="the IP address of the registrar where to retrieve the agents data from.")
    parser.add_argument('-rp', '--registrarport', action="store",
                        dest='registrar_port', help="the port of the registrar.")
    parser.add_argument('--cv_targethost', action='store', default=None, dest='cv_agent_ip',
                        help='the IP address of the host to provision that the verifier will use (optional).  Use only if different than argument to option -t/--targethost')
    parser.add_argument('-v', '--cv', action='store', dest='verifier_ip',
                        help="the IP address of the cloud verifier")
    parser.add_argument('-vp', '--cvport', action='store', dest='verifier_port',
                        help="the port of the cloud verifier")
    parser.add_argument('-vi', '--cvid', action='store', dest='verifier_id',
                        help="the unique identifier of a cloud verifier")
    parser.add_argument('-nvc', '--no-verifier-check', action='store_false', dest='verifier_check', default=True,
                        help='Disable the check to confirm if the agent is being processed by the specified verifier. Use only with -c/--command delete or reactivate')
    parser.add_argument('-u', '--uuid', action='store',
                        dest='agent_uuid', help="UUID for the agent to provision")
    parser.add_argument('-f', '--file', action='store', default=None,
                        help='Deliver the specified plaintext to the provisioned agent')
    parser.add_argument('--cert', action='store', dest='ca_dir', default=None,
                        help='Create and deliver a certificate using a CA created by ca-util. Pass in the CA directory or use "default" to use the standard dir')
    parser.add_argument('-k', '--key', action='store', dest='keyfile',
                        help='an intermedia key file produced by user_data_encrypt')
    parser.add_argument('-p', '--payload', action='store', default=None,
                        help='Specify the encrypted payload to deliver with encrypted keys specified by -k')
    parser.add_argument('--include', action='store', dest='incl_dir', default=None,
                        help="Include additional files in provided directory in certificate zip file.  Must be specified with --cert")
    parser.add_argument('--allowlist', action='store', dest='allowlist',
                        default=None, help="Specify the file path of an allowlist")
    parser.add_argument('--signature-verification-key', '--sign_verification_key', action='append', dest='ima_sign_verification_keys',
                        default=[], help="Specify an IMA file signature verification key")
    parser.add_argument('--signature-verification-key-sig', action='append', dest='ima_sign_verification_key_sigs',
                        default=[], help="Specify the GPG signature file for an IMA file signature verification key; pair this option with --signature-verification-key")
    parser.add_argument('--signature-verification-key-sig-key', action='append', dest='ima_sign_verification_key_sig_keys',
                        default=[], help="Specify the GPG public key file use to validate the --signature-verification-key-sig; pair this option with --signature-verification-key")
    parser.add_argument('--signature-verification-key-url', action='append', dest='ima_sign_verification_key_urls',
                        default=[], help="Specify the URL for a remote IMA file signature verification key")
    parser.add_argument('--signature-verification-key-sig-url', action='append',
                        dest='ima_sign_verification_key_sig_urls',
                        default=[], help="Specify the URL for the remote GPG signature of a remote IMA file signature verification key; pair this option with --signature-verification-key-url")
    parser.add_argument('--signature-verification-key-sig-url-key', action='append',
                        dest='ima_sign_verification_key_sig_url_keys',
                        default=[], help="Specify the GPG public key file used to validate the --signature-verification-key-sig-url; pair this option with --signature-verification-key-url")
    parser.add_argument('--mb_refstate', action='store', dest='mb_refstate',
                        default=None, help="Specify the location of a measure boot reference state (intended state)")
    parser.add_argument('--allowlist-checksum', action='store', dest='allowlist_checksum',
                        default=None, help="Specify the SHA2 checksum of an allowlist")
    parser.add_argument('--allowlist-sig', action='store', dest='allowlist_sig',
                        default=None, help="Specify the GPG signature file of an allowlist")
    parser.add_argument('--allowlist-sig-key', action='store', dest='allowlist_sig_key',
                        default=None, help="Specify the GPG public key file used to validate the --allowlist-sig or --allowlist-sig-url")
    parser.add_argument('--allowlist-url', action='store', dest='allowlist_url',
                        default=None, help="Specify the URL of a remote allowlist")
    parser.add_argument('--allowlist-sig-url', action='store', dest='allowlist_sig_url',
                        default=None, help="Specify the URL of the remote GPG signature file of an allowlist")
    parser.add_argument('--exclude', action='store', dest='ima_exclude',
                        default=None, help="Specify the location of an IMA exclude list")
    parser.add_argument('--tpm_policy', action='store', dest='tpm_policy', default=None,
                        help="Specify a TPM policy in JSON format. e.g., {\"15\":\"0000000000000000000000000000000000000000\"}")
    parser.add_argument('--vtpm_policy', action='store', dest='vtpm_policy',
                        default=None, help="Specify a vTPM policy in JSON format")
    parser.add_argument('--verify', action='store_true', default=False,
                        help='Block on cryptographically checked key derivation confirmation from the agent once it has been provisioned')
    parser.add_argument('--allowlist-name', help='The name of allowlist to operate with')

    args = parser.parse_args(argv[1:])

    # Make sure argument dependencies are enforced
    if( args.allowlist and args.allowlist_url):
        parser.error("--allowlist and --allowlist-url cannot be specified at the same time")
    if( args.allowlist_url and not (args.allowlist_sig or args.allowlist_sig_url or args.allowlist_checksum)):
        parser.error("--allowlist-url must have either --allowlist-sig, --allowlist-sig-url or --allowlist-checksum to verifier integrity")
    if( args.allowlist_sig and not (args.allowlist_url or args.allowlist)):
        parser.error("--allowlist-sig must have either --allowlist or --allowlist-url")
    if( args.allowlist_sig_url and not (args.allowlist_url or args.allowlist)):
        parser.error("--allowlist-sig-url must have either --allowlist or --allowlist-url")
    if( args.allowlist_checksum and not (args.allowlist_url or args.allowlist)):
        parser.error("--allowlist-checksum must have either --allowlist or --allowlist-url")
    if( args.allowlist_sig and not args.allowlist_sig_key):
        parser.error("--allowlist-sig must also have --allowlist-sig-key")
    if( args.allowlist_sig_url and not args.allowlist_sig_key):
        parser.error("--allowlist-sig-url must also have --allowlist-sig-key")
    if( args.allowlist_sig_key and not (args.allowlist_sig or args.allowlist_sig_url)):
        parser.error("--allowlist-sig-key must have either --allowlist-sig or --allowlist-sig-url")

    mytenant = Tenant()

    if args.agent_uuid is not None:
        mytenant.agent_uuid = args.agent_uuid
        # if the uuid is actually a public key, then hash it
        if mytenant.agent_uuid.startswith('-----BEGIN PUBLIC KEY-----'):
            mytenant.agent_uuid = hashlib.sha256(
                mytenant.agent_uuid).hexdigest()
    else:
        logger.warning("Using default UUID D432FBB3-D2F1-4A97-9EF7-75BD81C00000")
        mytenant.agent_uuid = "D432FBB3-D2F1-4A97-9EF7-75BD81C00000"

    if config.STUB_VTPM and config.TPM_CANNED_VALUES is not None:
        # Use canned values for agent UUID
        jsonIn = config.TPM_CANNED_VALUES
        if "add_vtpm_to_group" in jsonIn:
            mytenant.agent_uuid = jsonIn['add_vtpm_to_group']['retout']
        else:
            # Our command hasn't been canned!
            raise UserError("Command %s not found in canned JSON!" %
                            ("add_vtpm_to_group"))

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

    # we only need to fetch remote files if we are adding or updateing
    if args.command in ['add', 'update']:
        delete_tmp_files = logger.level > logging.DEBUG # delete tmp files unless in DEBUG mode

        if args.allowlist_url:
            logger.info("Downloading Allowlist from %s", args.allowlist_url)
            response = requests.get(args.allowlist_url, allow_redirects=False)
            if response.status_code == 200:
                args.allowlist = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Allowlist temporarily saved in %s" % args.allowlist)
            else:
                raise Exception("Downloading allowlist (%s) failed with status code %s!" % (args.allowlist_url, response.status_code))

        if args.allowlist_sig_url:
            logger.info("Downloading Allowlist signature from %s", args.allowlist_sig_url)
            response = requests.get(args.allowlist_sig_url, allow_redirects=False)
            if response.status_code == 200:
                args.allowlist_sig = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Allowlist signature temporarily saved in %s", args.allowlist_sig)
            else:
                raise Exception("Downloading allowlist signature (%s) failed with status code %s!" % (args.allowlist_sig_url, response.status_code))

        # verify all the local keys for which we have a signature file and a key to verify
        for i, key_file in enumerate(args.ima_sign_verification_keys):
            if len(args.ima_sign_verification_key_sigs) <= i:
                break
            keysig_file = args.ima_sign_verification_key_sigs[i]
            if len(args.ima_sign_verification_key_sig_keys) == 0:
                raise UserError("A gpg key is missing for key signature file '%s'" % keysig_file)

            gpg_key_file = args.ima_sign_verification_key_sig_keys[i]
            gpg.gpg_verify_filesignature(gpg_key_file, key_file, keysig_file, "IMA file signing key")

            logger.info("Signature verification on %s was successful" % key_file)

        # verify all the remote keys for which we have a signature URL and key to to verify
        # Append the downloaded key files to args.ima_sign_verification_keys
        for i, key_url in enumerate(args.ima_sign_verification_key_urls):

            logger.info("Downloading key from %s", key_url)
            response = requests.get(key_url, allow_redirects=False)
            if response.status_code == 200:
                key_file = write_to_namedtempfile(response.content, delete_tmp_files)
                args.ima_sign_verification_keys.append(key_file)
                logger.debug("Key temporarily saved in %s" % key_file)
            else:
                raise Exception("Downloading key (%s) failed with status code %s!" % (key_url, response.status_code))

            if len(args.ima_sign_verification_key_sig_urls) <= i:
                continue

            keysig_url = args.ima_sign_verification_key_sig_urls[i]

            if len(args.ima_sign_verification_key_sig_url_keys) == 0:
                raise UserError("A gpg key is missing for key signature URL '%s'" % keysig_url)

            logger.info("Downloading key signature from %s" % keysig_url)
            response = requests.get(keysig_url, allow_redirects=False)
            if response.status_code == 200:
                keysig_file = write_to_namedtempfile(response.content, delete_tmp_files)
                logger.debug("Key signature temporarily saved in %s" % keysig_file)
            else:
                raise Exception("Downloading key signature (%s) failed with status code %s!" % (key_url, response.status_code))

            gpg_key_file = args.ima_sign_verification_key_sig_url_keys[i]
            gpg.gpg_verify_filesignature(gpg_key_file, key_file, keysig_file, "IMA file signing key")
            logger.info("Signature verification on %s was successful" % key_url)

    if args.command == 'add':
        mytenant.init_add(vars(args))
        mytenant.preloop()
        mytenant.do_cv()
        mytenant.do_quote()
        if args.verify:
            mytenant.do_verify()
    elif args.command == 'update':
        mytenant.init_add(vars(args))
        mytenant.do_cvdelete(args.verifier_check)
        mytenant.preloop()
        mytenant.do_cv()
        mytenant.do_quote()
        if args.verify:
            mytenant.do_verify()
    elif args.command == 'delete':
        mytenant.do_cvdelete(args.verifier_check)
    elif args.command == 'status':
        mytenant.do_cvstatus()
    elif args.command == 'bulkinfo':
        mytenant.do_cvstatus(bulk=True)
    elif args.command == 'list':
        mytenant.do_cvstatus(listing=True)
    elif args.command == 'reactivate':
        mytenant.do_cvreactivate(args.verifier_check)
    elif args.command == 'reglist':
        mytenant.do_reglist()
    elif args.command == 'regdelete':
        mytenant.do_regdelete()
    elif args.command == 'addallowlist':
        mytenant.do_add_allowlist(vars(args))
    elif args.command == 'showallowlist':
        mytenant.do_show_allowlist(args.allowlist_name)
    elif args.command == 'deleteallowlist':
        mytenant.do_delete_allowlist(args.allowlist_name)
    else:
        raise UserError("Invalid command specified: %s" % (args.command))
