from datetime import timedelta

from keylime import config, keylime_logging
from keylime.models.base import *
import keylime.models.verifier as verifier_models

logger = keylime_logging.init_logging("verifier")


class EvidenceModel(PersistableModel):
    SIGNATURE_SCHEMES = [ "rsassa", "rsapss", "ecdsa" ]
    # These are the same names as used by tpm2-tools:
    # https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#signing-schemes
    #
    # The following TPM-supported algorithms are not accepted, as these are not implemented by python-cryptography:
    #   - ecdaa (Elliptic Curve Direct Anonymous Attestation)
    #   - ecschnorr 
    #   - sm2

    KEY_ALGORITHMS = [ "rsa", "ecc" ]
    # These are the same names as used by tpm2-tools:
    # https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#asymmetric

    HASH_ALGORITHMS = [ "sha3_512", "sha3_384", "sha3_256", "sha512", "sha384", "sha256", "sm3_256", "sha1" ]
    # These are the same names as used by tpm2-tools:
    # https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/alg.md#hashing-algorithms


class EvidenceItem(EvidenceModel):
    @classmethod
    def _schema(cls):
        cls._belongs_to("attestation", verifier_models.Attestation)

        cls._field("evidence_class", OneOf("certification", "log"))
        cls._field("evidence_type", OneOf("tpm_quote", "uefi_log", "ima_log", String))

        cls._embeds_one("capabilities", Capabilities, inline=True, nullable=True)
        cls._embeds_one("chosen_parameters", ChosenParameters, inline=True, nullable=True)
        cls._embeds_one("data", EvidenceData, inline=True, nullable=True)

    def initialise(self, data):
        self.cast_changes(data, ["evidence_class", "evidence_type"])
        self.validate_required(["evidence_class", "evidence_type"])

    def receive_capabilities(self, data):
        if self.evidence_class == "certification" and not isinstance(self.capabilities, CertificationCapabilities):
            self.capabilities = CertificationCapabilities.empty()
        elif self.evidence_class == "log" and not isinstance(self.capabilities, LogCapabilities):
            self.capabilities = LogCapabilities.empty()

        self.capabilities.update(data)

    def choose_parameters(self, data):
        if self.evidence_class == "certification" and not isinstance(self.chosen_parameters, CertificationParameters):
            self.chosen_parameters = CertificationParameters.empty()
        elif self.evidence_class == "log" and not isinstance(self.chosen_parameters, LogParameters):
            self.chosen_parameters = LogParameters.empty()

        self.chosen_parameters.update(data)

    def receive_evidence(self, data):
        if self.evidence_class == "certification" and not isinstance(self.data, CertificationData):
            self.data = CertificationData.empty()
        elif self.evidence_class == "log" and not isinstance(self.data, LogData):
            self.data = LogData.empty()

        self.data.update(data)

class Capabilities(EvidenceModel):
    @classmethod
    def _schema(cls):
        # The version of the component, or the spec to which it complies, used to produce the evidence
        cls._field("component_version", String, nullable=True)
        # The version of the serialisation format used to render the evidence
        cls._field("evidence_version", String, nullable=True)

    def update(self, data):
        self.cast_changes(data, ["version"])

class CertificationCapabilities(Capabilities):
    @classmethod
    def _schema(cls):
        super()._schema()
        # A list of signature schemes the attester can use to certify information about the target environment
        cls._field("signature_schemes", List)
        # A list of hash algorithms the attester can use to produce a signature for arbitrary-length data
        cls._field("hash_algorithms", List, nullable=True)
        # A list of items for which the attester can produce a certification, e.g., a list of PCR numbers
        cls._field("available_subjects", List, nullable=True)

        # Information about the set of keys which the attester has available for certifying claims
        cls._embeds_many("certification_keys", CertificationKey)

    def update(self, data):
        super().update(data)
        self.cast_changes(data, ["signature_schemes", "hash_algorithms", "available_subjects"])

        self.validate_required("signature_schemes")
        # self.validate_required("certification_keys")

        self.validate_subset(
            "signature_schemes",
            self.SIGNATURE_SCHEMES,
            f"has an invalid entry not one of: {', '.join(self.SIGNATURE_SCHEMES)}"
        )

        self.validate_subset(
            "hash_algorithms",
            self.HASH_ALGORITHMS,
            f"has an invalid entry not one of: {', '.join(self.HASH_ALGORITHMS)}"
        )

class LogCapabilities(Capabilities):
    @classmethod
    def _schema(cls):
        super()._schema()

        # The number of entries found in the log at the time capabilities are sent to verifier
        cls._field("entry_count", Integer, nullable=True)
        # Flag indicating that the verifier may request a subset of entries from the log
        cls._field("supports_partial_access", Boolean)
        # Flag indicating it is expected that the current log may subsequently have further entries appended
        cls._field("appendable", Boolean)
        # A list of log formats the attester is able to provide, typically given as a list of IANA media types
        cls._field("formats", List, nullable=True)

    def initialise(self):
        self.supports_partial_access = False
        self.appendable = True

    def update(self, data):
        super().update(data)
        self.cast_changes(data, ["entry_count", "supports_partial_access", "appendable"])

        self.validate_required("supports_partial_access")
        self.validate_required("appendable")
        self.validate_number("entry_count", (">=", 0))

        if self.supports_partial_access:
            self.validate_required("entry_count", "is required when supports_partial_access is true")

class ChosenParameters(EvidenceModel):
    pass

class CertificationParameters(ChosenParameters):
    @classmethod
    def _schema(cls):
        # The challenge/nonce the attester should include in the certification, e.g, as qualifyingData, if supported
        cls._field("challenge", Nonce, nullable=True)
        # The signature scheme the attester should use to certify information about the target environment
        cls._field("signature_scheme", String)
        # The hash algorithm the attester should use to sign arbitrary-length data
        cls._field("hash_algorithm", String, nullable=True)
        # A list of items the attester should include in the certification, e.g., a list of PCR numbers
        cls._field("selected_subjects", List, nullable=True)

        # The key the attester should use to certify the selected claims
        cls._embeds_one("certification_key", CertificationKey)

    def update(self, data, check_against=None):
        self.cast_changes(data, ["signature_scheme", "hash_algorithm", "selected_subjects"])

        if isinstance(check_against, CertificationCapabilities):
            self.validate_inclusion("signature_scheme", check_against.signature_schemes)
            self.validate_inclusion("hash_algorithm", check_against.hash_algorithms)
            self.validate_inclusion("selected_subjects", check_against.available_subjects)
            # self.validate_inclusion("certification_key", check_against.certification_keys)

    def generate_challenge(self, bit_length):
        self.challenge = Nonce.generate(bit_length)

class LogParameters(ChosenParameters):
    @classmethod
    def _schema(cls):
        cls._field("starting_offset", Integer, nullable=True)
        cls._field("entry_count", Integer, nullable=True)
        cls._field("format", String, nullable=True)

    def update(self, data, check_against=None):
        self.cast_changes(data, ["starting_offset", "entry_count"])

        self.validate_number("starting_offset", (">=", 0))
        self.validate_number("entry_count", (">=", 0))

        if isinstance(check_against, LogCapabilities):
            self.validate_inclusion("format", check_against.formats)

            if check_against.supports_partial_access:
                self.validate_required("starting_offset")
                self.validate_number("starting_offset", ("<", check_against.entry_count))

class EvidenceData(EvidenceModel):
    pass

class CertificationData(EvidenceData):
    @classmethod
    def _schema(cls):
        # The claims, or information derived therefrom, which have been certified. Given when this information is not
        # directly contained within the 'message' field, e.g., a list of numbered TPM PCRs with their values
        cls._field("subject_data", OneOf(Dictionary, List, Binary(persist_as=String), String), nullable=True)
        # The binary data which is hashed and signed. This should derive in part from 'subject', if present. For a TPM
        # quote, e.g., this contains the TPMS_ATTEST structure which includes a hash of the PCR values concatenated
        cls._field("message", Binary)
        # The signature over the message, or over a hash of the message, produced by the chosen signature scheme
        cls._field("signature", Binary)
        # Indicates whether or not the message was hashed by the chosen hash function before being signed
        cls._field("message_hashed", Boolean)

        # Optional human-readable rendering of the data contained within the 'subject_data' and 'message' fields,
        # and/or metadata about the certification
        cls._virtual("certification_info", OneOf(Dictionary, List, String), nullable=True)

    def update(self, data):
        self.cast_changes(data, ["subject_data", "message", "signature", "message_hashed"])

        self.validate_required("message")
        self.validate_required("signature")
        self.validate_required("message_hashed")

    def update_server_data(self, data):
        self.certification_info = data

class LogData(EvidenceData):
    @classmethod
    def _schema(cls):
        cls._field("entry_count", Integer, nullable=True)
        cls._field("entries", OneOf(Binary, String))

    def update(self, data):
        self.cast_changes(data, ["entry_count", "entries"])

class CertificationKey(EvidenceModel):
    @classmethod
    def _schema(cls):
        # The class of the key, i.e., whether it is used as part of an asymmetric or symmetric cryptosystem
        cls._field("key_class", OneOf("pair", "shared"))
        # The algorithm used to generate the key (None if random)
        cls._field("key_algorithm", OneOf(*cls.KEY_ALGORITHMS), nullable=True)
        # The size of the key in bits
        cls._field("key_size", Integer)
        # A name used by the server to disambiguate the key from others belonging to the attester, e.g., "ak"
        cls._field("server_identifier", String, nullable=True)
        # A value used by the attester to identify the key, e.g., a TPM key name
        cls._field("local_identifier", OneOf(Binary, String), nullable=True)
        # The key material of the public portion of the key (for key pairs only)
        cls._field("public", Binary, nullable=True)

    def _check_identifier_presence(self):
        if self.key_class == "pair" and not (self.server_identifier or self.local_identifier or self.public):
            self._add_error(
                "server_identifier",
                "is required when key_class is 'pair' and neither local_identifier nor public has been provided"
            )

            self._add_error(
                "local_identifier",
                "is required when key_class is 'pair' and neither server_identifier nor public has been provided"
            )

            self._add_error(
                "public",
                "is required when key_class is 'pair' and neither server_identifier nor local_identifier has been"
                "provided"
            )

        elif self.key_class == "shared" and not (self.server_identifier or self.local_identifier):
            self._add_error(
                "server_identifier",
                "is required when key_class is 'shared' and local_identifier has not been provided"
            )

            self._add_error(
                "local_identifier",
                "is required when key_class is 'shared' and server_identifier has not been provided"
            )

            self.validate_absence("public", "is not allowable when key_class is 'shared'")

    def update(self, data):
        self.cast_changes(
            data,
            ["key_class", "key_algorithm", "key_size", "server_identifier", "local_identifier", "public"]
        )

        self.validate_required(["key_class", "key_size"])
        self._check_identifier_presence()

        if self.key_class == "pair":
            self.validate_required("key_algorithm", "is required when key_class is 'pair'")
