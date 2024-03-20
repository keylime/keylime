import base64

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keylime import cert_utils, config, crypto
from keylime.models.base import *
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import Tpm


class RegistrarAgent(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("registrarmain")
        cls._id("agent_id", String(80))

        # The endorsement key (EK) of the TPM
        cls._field("ek_tpm", String(500))
        # The endorsement key (EK) certificate used to verify the TPM as genuine
        cls._field("ekcert", Certificate, nullable=True)
        # The attestation key (AK) used by Keylime to prepare TPM quotes
        cls._field("aik_tpm", String(500))
        # The initial attestation key (IAK) used when registering with a DevID
        cls._field("iak_tpm", String(500))
        # The initial attestation key (IAK) certificate used to verify IAK authenticity
        cls._field("iak_cert", Certificate, nullable=True)
        # The signing key used as initial device identity (IDevID) key
        cls._field("idevid_tpm", String(500))
        # The initial device identity (IDevID) certificate used to verify IDevID authenticity
        cls._field("idevid_cert", Certificate, nullable=True)
        # The HMAC key used to verify the response produced by TPM2_ActivateCredential to bind the AK to the EK
        cls._field("key", String(45))
        # Indicates that the AK has successfully been bound to the EK
        cls._field("active", Boolean)

        # The details used to establish connections to the agent when operating in pull mode
        cls._field("ip", String(15), nullable=True)
        cls._field("port", Integer, nullable=True)
        cls._field("mtls_cert", Certificate, nullable=True)

        # The number of times the agent has registered over its lifetime
        cls._field("regcount", Integer)

        # NO LONGER USED:
        # Indicates that the agent is running in a cloud VM and that the EKcert is not available from NVRAM
        cls._field("virtual", Boolean)
        # Information about the cloud VM (including the EKcert obtained out of band from the cloud provider)
        cls._field("provider_keys", Dictionary)

    @classmethod
    def empty(cls):
        agent = super().empty()
        agent.provider_keys = {}
        return agent

    def _check_key_against_cert(self, tpm_key_field, cert_field):
        tpm_key = self.changes.get(tpm_key_field)
        cert = self.changes.get(cert_field)

        # If key or certificate is not present in the pending changes, skip checking the key against the certificate
        if not tpm_key or not cert:
            return

        # Convert TPM key structure to a public key object and extract the raw key byte string
        try:
            tpm_pub = tpm2_objects.pubkey_from_tpm2b_public(base64.b64decode(tpm_key, validate=True))
            tpm_pub_bytes = tpm_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        except:
            self._add_error(tpm_key_field, "must be a valid TPM2B_PUBLIC structure")
            return

        # Make sure that the TPM key is either an RSA or EC public key
        if not isinstance(tpm_pub, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            self._add_error(tpm_key_field, "must contain a valid RSA or EC public key")
            return

        # Extract public key bytes from certificate
        cert_pub = cert.public_key()
        cert_pub_bytes = cert_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Check that the public key obtained from the TPM matches the public key contained in the certificate
        if tpm_pub_bytes != cert_pub_bytes:
            self._add_error(tpm_key_field, f"must contain the same public key found in {cert_field}")
            return

    def _check_cert_trust_status(self, cert_field, cert_type=""):
        cert = self.changes.get(cert_field)

        if not cert:
            return

        # This is the directory currently used to trust IAK/IDevID certificates but this will be replaced with a
        # more robust trust store implementation in a subsequent PR
        trust_store = config.get("tenant", "tpm_cert_store")

        if not cert_utils.verify_cert(cert, trust_store, cert_type):
            self._add_error(cert_field, "must contain a certificate issued by a CA present in the trust store")

    def _bind_ak_to_iak(self, iak_attest, iak_sign):
        # The ak-iak binding should only be verified when either aik_tpm or iak_tpm is changed
        if "aik_tpm" not in self.changes or "iak_tpm" not in self.changes:
            return

        # If one of aik_tpm or iak_tpm is missing from the record, the ak-iak binding cannot be verified so skip
        if not self.aik_tpm or not self.iak_tpm:
            return

        # If the iak_attest and iak_sign values are missing, treat this as an error
        if not iak_attest or not iak_sign:
            self._add_error("aik_tpm", "cannot be bound to the IAK because of a missing 'iak_attest' or 'iak_sign'")

        # Decode Base64 values to binary TPM structures
        aik_tpm = base64.b64decode(self.aik_tpm)
        iak_tpm = base64.b64decode(self.iak_tpm)
        iak_attest = base64.b64decode(iak_attest)
        iak_sign = base64.b64decode(iak_sign)

        # Verify that iak_attest properly contains reference to aik_tpm and that iak_sign is a signature thereover
        # produced by the private key corresponding to iak_tpm
        if not Tpm.verify_aik_with_iak(self.agent_id, aik_tpm, iak_tpm, iak_attest, iak_sign):
            self._add_error("aik_tpm", "cannot be confirmed as having been created by the same TPM as the IAK")

    def _check_ek(self):
        # Check that the EK public keys from the TPM match the public keys contained in the EK certificate
        self._check_key_against_cert("ek_tpm", "ekcert")

        # The current behaviour of the registrar is not to perform any verification of the EK certificate against
        # trusted TPM manufacturer certificates. This responsibility is left to the tenant. A future PR will add
        # a trust store to the registrar at which point the below line will be uncommented
        #
        ## self._check_cert_trust_status("ek_cert")

        # Note: The AK cannot be verified as bound to the EK until the agent receives a challenge and uses the TPM
        # to produce a response (see the self.produce_ak_challenge() and self.verify_ak_response(response) methods).

    def _check_iak_idevid(self, iak_attest, iak_sign):
        # Check that the IAK/IDevID public keys from the TPM match the public keys contained in the IAK/IDevID certs
        self._check_key_against_cert("iak_tpm", "iak_cert")
        self._check_key_against_cert("idevid_tpm", "idevid_cert")
        # Check that the IAK/IDevID certificates are trusted
        self._check_cert_trust_status("iak_cert", "IAK")
        self._check_cert_trust_status("idevid_cert", "IDevID")
        # Check that the AK is bound to the IAK by way of TPM2_Certify
        self._bind_ak_to_iak(iak_attest, iak_sign)

    def _check_root_identity_presence(self):
        tpm_identity = config.get("registrar", "tpm_identity", fallback="default")

        if tpm_identity == "iak_idevid":
            self.validate_required(["iak_tpm", "idevid_tpm"], msg="is required by configuration")
        elif tpm_identity == "ek_cert":
            self.validate_required(["ek_tpm"], msg="is required by configuration")
        else:
            # If tpm_identity == "default" or tpm_identity == "ek_cert_or_iak_idevid" then either EK or IAK/IDevID is
            # allowed as the root identity, so check that either one or the other is present:

            if not self.iak_tpm and not self.ek_tpm:
                self._add_error("iak_tpm", "is required in absence of an EK")

            if not self.idevid_tpm and not self.ek_tpm:
                self._add_error("idevid_tpm", "is required in absence of an EK")

            if not self.ek_tpm and not self.iak_tpm and not self.idevid_tpm:
                self._add_error("ek_tpm", "is required in absence of an IAK and IDevID")

        # If an IAK/IDevID is provided, ensure that IAK/IDevID certificates are also present. This requirement will be
        # dropped when IAK/IDevID registration without including certs is enabled (when web hook functionality is added)
        if "iak_tpm" in self.changes or "idevid_tpm" in self.changes:
            self.validate_required(["iak_cert", "idevid_cert"])

    def _prepare_status_flags(self):
        if "ek_tpm" in self.changes or "aik_tpm" in self.changes:
            self.active = False

    def _prepare_regcount(self):
        reg_fields = ("ek_tpm", "ekcert", "aik_tpm", "iak_tpm", "iak_cert", "idevid_tpm", "idevid_cert")

        if self.regcount == None:
            self.regcount = 0

        if any(field in reg_fields for field in self.changes) and self.changes_valid:
            self.regcount += 1

    def update(self, data):
        # Bind key-value pairs ('data') to those fields which are meant to be externally changeable
        self.cast_changes(
            data,
            ["agent_id", "ek_tpm", "ekcert", "aik_tpm", "iak_tpm", "iak_cert", "idevid_tpm", "idevid_cert", "ip"]
            + ["port", "mtls_cert"],
        )

        # Verify EK as valid
        self._check_ek()
        # Verify IAK/IDevID as valid and trusted
        self._check_iak_idevid(data.get("iak_attest"), data.get("iak_sign"))
        # Ensure either an EK or IAK/IDevID is present, depending on configuration
        self._check_root_identity_presence()

        # Basic validation of values
        self.validate_required(["aik_tpm"])
        self.validate_base64(["ek_tpm", "aik_tpm", "iak_tpm", "idevid_tpm"])

        # Determine and set the 'active' flag
        self._prepare_status_flags()
        # Increment number of registrations if appropriate
        self._prepare_regcount()

    def produce_ak_challenge(self):
        if not self.ek_tpm or not self.aik_tpm:
            return None

        ek_tpm = base64.b64decode(self.ek_tpm)
        aik_tpm = base64.b64decode(self.aik_tpm)

        try:
            result = Tpm.encrypt_aik_with_ek(self.agent_id, ek_tpm, aik_tpm)

            if not result:
                return None

        except ValueError:
            return None

        (challenge, key) = result
        self.change("key", key)
        return challenge.decode("utf-8")

    def verify_ak_response(self, response):
        expected_response = crypto.do_hmac(self.key.encode(), self.agent_id)

        result = response == expected_response

        self.change("active", result)
        return result

    def render(self, only=None):
        if not only:
            only = ["agent_id", "ek_tpm", "ekcert", "aik_tpm", "mtls_cert", "ip", "port", "regcount"]

            if self.virtual:
                only.append("provider_keys")

        return super().render(only)
