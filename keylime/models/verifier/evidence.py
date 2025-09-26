import math
from datetime import timedelta

from keylime import config, keylime_logging
from keylime.models.base import *
import keylime.models.verifier as verifier_models
from keylime.common import algorithms

logger = keylime_logging.init_logging("verifier")


class EvidenceItem(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("evidence_items")
        
        cls._belongs_to("attestation", verifier_models.Attestation)
        cls._field("agent_id", String(80), refers_to="attestation.agent_id")
        cls._field("attestation_index", Integer, refers_to="attestation.index")

        cls._field("evidence_class", OneOf("certification", "log"))
        cls._field("evidence_type", OneOf("tpm_quote", "uefi_log", "ima_log", String))

        cls._embeds_inline("capabilities", Capabilities, nullable=True)
        cls._embeds_inline("chosen_parameters", ChosenParameters, nullable=True)
        cls._embeds_inline("data", EvidenceData, nullable=True)
        cls._embeds_inline("results", Results, nullable=True)

    @classmethod
    def create(cls, data):
        if not isinstance(data, dict):
            TypeError("each item in 'evidence_supported' must be a dictionary")

        evidence_item = EvidenceItem.empty()
        evidence_item.receive_capabilities(data)
        return evidence_item

    def refresh_metadata(self):
        if self.attestation:
            self.attestation.refresh_metadata()

    def receive_capabilities(self, data):
        self.cast_changes(data, ["evidence_class", "evidence_type"])

        if self.evidence_class == "certification" and not isinstance(self.capabilities, CertificationCapabilities):
            self.capabilities = CertificationCapabilities.empty()
        elif self.evidence_class == "log" and not isinstance(self.capabilities, LogCapabilities):
            self.capabilities = LogCapabilities.empty()

        self.capabilities.initialise()
        self.capabilities.update(data.get("capabilities"))

        self.validate_required(["evidence_class", "evidence_type"])
        self.refresh_metadata()

    def initialise_parameters(self):
        if self.evidence_class == "certification" and not isinstance(self.chosen_parameters, CertificationParameters):
            self.chosen_parameters = CertificationParameters.empty()
        elif self.evidence_class == "log" and not isinstance(self.chosen_parameters, LogParameters):
            self.chosen_parameters = LogParameters.empty()

        self.chosen_parameters.initialise()

    def validate_parameters(self):
        self.chosen_parameters.validate_choices(check_against=self.capabilities)
        self.refresh_metadata()

    def generate_challenge(self, bit_length):
        if self.evidence_class != "certification":
            raise ValueError("challenge can only be generated for EvidenceItem with evidence_class 'certification'")
        
        if not isinstance(self.chosen_parameters, CertificationParameters):
            self.chosen_parameters = CertificationParameters.empty()

        self.chosen_parameters.generate_challenge(bit_length)
        self.refresh_metadata()

    def receive_evidence(self, data):
        if self.evidence_class == "certification":

            if not isinstance(self.data, CertificationData):
                self.data = CertificationData.empty()

            self.results = CertificationResults.empty()

        elif self.evidence_class == "log":

            if not isinstance(self.data, LogData):
                self.data = LogData.empty()

            self.results = LogResults.empty()

        self.data.initialise()
        self.results.initialise()
        self.data.update(data.get("data"))
        self.refresh_metadata()

    def render_evidence_requested(self):
        output = self.render(["evidence_class", "evidence_type"])

        if self.chosen_parameters:
            rendered_params = self.chosen_parameters.render()
            
            if rendered_params:
                output["chosen_parameters"] = rendered_params

        return output

    def render_evidence_acknowledged(self):
        output = self.render(["evidence_class", "evidence_type"])

        if self.capabilities:
            rendered_caps = self.capabilities.render()

            if rendered_caps:
                output["capabilities"] = rendered_caps

        if self.chosen_parameters:
            rendered_params = self.chosen_parameters.render()
            
            if rendered_params:
                output["chosen_parameters"] = rendered_params

        if self.data:
            output["data"] = self.data.render()

        return output

    def render_state(self):
        return self.render_evidence_acknowledged()

    def compatible_with(self, evidence_item):
        capabilities_compatible = (
            (not self.capabilities and not evidence_item.capabilities)
            or self.capabilities.values == evidence_item.capabilities.values
        )

        return (
            self.agent_id == evidence_item.agent_id and
            self.attestation_index == evidence_item.attestation_index and
            self.evidence_class == evidence_item.evidence_class and
            self.evidence_type == evidence_item.evidence_type and
            capabilities_compatible
        )

    @property
    def next_starting_offset(self):
        if self.evidence_class != "log":
            raise AttributeError(f"'{self.evidence_class}' evidence item has no attribute 'next_starting_offset'")

        if not self.capabilities or not self.capabilities.supports_partial_access:
            raise ValueError(
                f"cannot determine 'next_starting_offset' for '{self.evidence_type}' evidence item which doesn't "
                f"support partial access"
            )

        if not self.chosen_parameters or self.chosen_parameters.starting_offset is None:
            return None

        if not self.results or self.results.certified_entry_count is None:
            return None

        return self.chosen_parameters.starting_offset + self.results.certified_entry_count

class Capabilities(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._sub_models(CertificationCapabilities, LogCapabilities)

        # The version of the component, or the spec to which it complies, used to produce the evidence
        cls._field("component_version", String, nullable=True)
        # The version of the serialisation format used to render the evidence
        cls._field("evidence_version", String, nullable=True)
        # Additional information related to the attester's capabilities, as determined by the evidence type
        cls._field("meta", Dictionary, nullable=True)

    def initialise(self):
        if not self.meta:
            self.meta = {}

    def update(self, data):
        self.cast_changes(data, ["component_version", "evidence_version"])

    def render(self, only=None):
        if only is None:
            only = []

            if self.component_version:
                only.append("component_version")

            if self.component_version:
                only.append("evidence_version")

            if self.meta:
                only.append("meta")

        # if not only:
        #     return None

        return super().render(only)

class CertificationCapabilities(Capabilities):
    @classmethod
    def _schema(cls):
        super()._schema()
        # A list of signature schemes the attester can use to certify information about the target environment
        cls._field("signature_schemes", List)
        # A list of hash algorithms the attester can use to produce a signature for arbitrary-length data
        cls._field("hash_algorithms", List, nullable=True)
        # A list of items for which the attester can produce a certification, e.g., a list of PCR numbers
        cls._field("available_subjects", OneOf(List, Dictionary), nullable=True)

        # Information about the set of keys which the attester has available for certifying claims
        cls._embeds_many("certification_keys", CertificationKey)

    def update(self, data):
        super().update(data)
        self.cast_changes(data, ["signature_schemes", "hash_algorithms", "available_subjects"])
        cert_keys = data.get("certification_keys", [])

        if cert_keys:
            self.certification_keys.clear()

            for key in cert_keys:
                if isinstance(key, dict):
                    key = CertificationKey.create(key)

                self.certification_keys.add(key)

        self.validate_required("signature_schemes")
        self.validate_required("certification_keys")

    def render(self, only=None):
        output = super().render(only)

        if only is None:
            only = ["signature_schemes"]

            if self.hash_algorithms:
                only.append("hash_algorithms")

            if self.available_subjects:
                only.append("available_subjects")

            if self.certification_keys:
                only.append("certification_keys")

            output |= super().render(only)

        # Move "meta" to bottom, if present
        if output.get("meta"):
            rendered_meta = output["meta"]
            del output["meta"]
            output["meta"] = rendered_meta

        return output

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

    def _set_defaults(self):
        if "supports_partial_access" not in self.values:
            self.supports_partial_access = False

        if "appendable" not in self.values:
            self.appendable = False

    def update(self, data):
        super().update(data)
        self.cast_changes(data, ["entry_count", "supports_partial_access", "appendable", "formats"])
        self._set_defaults()

        self.validate_required("supports_partial_access")
        self.validate_required("appendable")
        self.validate_number("entry_count", (">=", 0))

        if self.supports_partial_access:
            self.validate_required("entry_count", "is required when supports_partial_access is true")

    def render(self, only=None):
        output = super().render(only)

        if only is None:
            only = ["supports_partial_access", "appendable"]

            if self.entry_count is not None:
                only.append("entry_count")

            if self.formats:
                only.append("formats")

            output |= super().render(only)

        # Move "meta" to bottom, if present
        if output.get("meta"):
            rendered_meta = output["meta"]
            del output["meta"]
            output["meta"] = rendered_meta

        return output

class ChosenParameters(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._sub_models(CertificationParameters, LogParameters)

        # Additional information related to the chosen parameters, as determined by the evidence type
        cls._field("meta", Dictionary, nullable=True)

    def initialise(self):
        if not self.meta:
            self.meta = {}

    def render(self, only=None):
        if only is None:
            only = []

            if self.meta:
                only.append("meta")

        return super().render(only)

class CertificationParameters(ChosenParameters):
    @classmethod
    def _schema(cls):
        # The challenge/nonce the attester should include in the certification, e.g., as qualifyingData, if supported
        cls._field("challenge", Nonce, nullable=True)
        # The signature scheme the attester should use to certify information about the target environment
        cls._field("signature_scheme", String)
        # The hash algorithm the attester should use to sign arbitrary-length data
        cls._field("hash_algorithm", String, nullable=True)
        # A list of items the attester should include in the certification, e.g., a list of PCR numbers
        cls._field("selected_subjects", OneOf(List, Dictionary), nullable=True)

        # The key the attester should use to certify the selected claims
        cls._embeds_one("certification_key", CertificationKey)

        super()._schema()

    def validate_choices(self, check_against):
        if not isinstance(check_against, CertificationCapabilities):
            raise TypeError("argument 'check_against' must be of type 'CertificationCapabilities'")

        self.validate_required("signature_scheme")
        self.validate_inclusion("signature_scheme", check_against.signature_schemes)
        self.validate_inclusion("hash_algorithm", check_against.hash_algorithms)
        self.validate_inclusion("certification_key", check_against.certification_keys)

        # NOTE: It is not possible to check selected_subjects against available_subjects as the contents of these
        # fields can vary by evidence_type (even when the evidence_types belong to the same evidence_class)

    def generate_challenge(self, bit_length):
        # self.challenge = Nonce.generate(bit_length)
        self.challenge = bytes.fromhex("49beed365aac777dae23564f5ad0ec")

    def render(self, only=None):
        output = super().render(only)

        if only is None:
            only = ["signature_scheme"]

            if self.challenge:
                only.append("challenge")

            if self.hash_algorithm:
                only.append("hash_algorithm")

            if self.selected_subjects:
                only.append("selected_subjects")

            if self.certification_key:
                only.append("certification_key")

            output |= super().render(only)

        return output

class LogParameters(ChosenParameters):
    @classmethod
    def _schema(cls):
        cls._field("starting_offset", Integer, nullable=True)
        cls._field("entry_count", Integer, nullable=True)
        cls._field("format", String, nullable=True)
        super()._schema()

    def validate_choices(self, check_against):
        if not isinstance(check_against, LogCapabilities):
            raise TypeError("argument 'check_against' must be of type 'LogCapabilities'")

        self.validate_number("starting_offset", (">=", 0))
        self.validate_number("entry_count", (">=", 0))
        self.validate_inclusion("format", check_against.formats)

        if check_against.supports_partial_access:
            self.validate_required("starting_offset")
            self.validate_number("starting_offset", ("<=", check_against.entry_count))

            # NOTE: Typically starting_offset should be < the reported entry_count as log entries are indexed by 0.
            # However, the verifier may reply with a starting_offset == entry_count when it wants the agent to send
            # any additional log entries that may appear between receipt of the capabilities negotiation and evidence
            # handling requests.

        if not check_against.supports_partial_access and self.starting_offset is not None:
            self._add_error("starting_offset", "not allowed when supports_partial_access is false")

        if not check_against.supports_partial_access and self.entry_count is not None:
            self._add_error("entry_count", "not allowed when supports_partial_access is false")

            if not check_against.supports_partial_access and self.starting_offset is not None:
                self._add_error("starting_offset", "not allowed when supports_partial_access is false")

            if not check_against.supports_partial_access and self.entry_count is not None:
                self._add_error("entry_count", "not allowed when supports_partial_access is false")

    def render(self, only=None):
        output = super().render(only)

        if only is None:
            only = []

            if self.starting_offset is not None:
                only.append("starting_offset")

            if self.entry_count is not None:
                only.append("entry_count")

            if self.format:
                only.append("format")

            output |= super().render(only)

        return output

class EvidenceData(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._sub_models(CertificationData, LogData)

        # Additional information related to the evidence data, as determined by the evidence type
        cls._field("meta", Dictionary, nullable=True)

        cls._embedded_in("evidence_item", EvidenceItem)

    def initialise(self):
        if not self.meta:
            self.meta = {}

    def render(self, only=None):
        if only is None:
            only = []

            if self.meta:
                only.append("meta")

        return super().render(only)

class CertificationData(EvidenceData):
    @classmethod
    def _schema(cls):
        # The claims, or information derived therefrom, which have been certified. Given when this information is not
        # directly contained within the 'message' field, e.g., a list of numbered TPM PCRs with their values
        cls._field("subject_data", OneOf(Dictionary, List, Binary(persist_as=String), String), nullable=True)
        # The binary data which is hashed and signed. This should derive in part from 'subject', if present. For a TPM
        # quote, e.g., this contains the TPMS_ATTEST structure which includes a hash of the PCR values concatenated
        cls._field("message", Binary)
        # The signature over the hash of the message, produced by the chosen signature scheme
        cls._field("signature", Binary)

        super()._schema()

    def update(self, data):
        self.cast_changes(data, ["subject_data", "message", "signature"])

        self.validate_required("message")
        self.validate_required("signature")

    def render(self, only=None):
        if only is None:
            only = ["message", "signature"]

            if self.subject_data:
                only.append("subject_data")

            if self.meta:
                only.append("meta")

        return super().render(only)

class LogData(EvidenceData):
    @classmethod
    def _schema(cls):
        cls._field("entry_count", Integer, nullable=True)
        cls._field("entries", OneOf(Binary(persist_as=String), String), nullable=True)

        super()._schema()

    def update(self, data):
        self.cast_changes(data, ["entry_count", "entries"])

        requested_count = self.evidence_item.chosen_parameters.entry_count or math.inf

        msg = f"must be no more than the number of entries requested ({requested_count})"
        self.validate_number("entry_count", ("<=", requested_count), msg=msg)

    def render(self, only=None):
        if only is None:
            only = ["entries"]

            if self.entry_count is not None:
                only.append("entry_count")

            if self.meta:
                only.append("meta")

        return super().render(only)

class CertificationKey(PersistableModel):
    @classmethod
    def _schema(cls):
        # The class of the key, i.e., whether it is used as part of an asymmetric or symmetric cryptosystem
        cls._field("key_class", OneOf("asymmetric", "symmetric"))
        # The algorithm used to generate the key (None if random)
        cls._field("key_algorithm", String, nullable=True)
        # The size of the key in bits
        cls._field("key_size", Integer)
        # A name used by the server to disambiguate the key from others belonging to the attester, e.g., "ak"
        cls._field("server_identifier", String, nullable=True)
        # A value used by the attester to identify the key, e.g., a TPM key name
        cls._field("local_identifier", OneOf(Binary(persist_as=String), String), nullable=True)
        # An optional restriction on the signature schemes the attester can use to certify data with this key
        cls._field("allowable_signature_schemes", List, nullable=True)
        # An optional restriction on the hash algorithms the attester can use to certify data with this key
        cls._field("allowable_hash_algorithms", List, nullable=True)
        # The key material of the public portion of the key (for asymmetric keys only)
        cls._field("public", Binary, nullable=True)

    @classmethod
    def create(cls, data):
        cert_key = CertificationKey.empty()
        cert_key.update(data)
        return cert_key

    def _check_identifier_presence(self):
        if self.key_class == "asymmetric" and not (self.server_identifier or self.local_identifier or self.public):
            self._add_error(
                "server_identifier",
                "is required when key_class is 'asymmetric' and neither local_identifier nor public has been provided"
            )

            self._add_error(
                "local_identifier",
                "is required when key_class is 'asymmetric' and neither server_identifier nor public has been provided"
            )

            self._add_error(
                "public",
                "is required when key_class is 'asymmetric' and neither server_identifier nor local_identifier has been"
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

    def _check_scheme_restriction(self):
        if not self.allowable_signature_schemes or not self.key_algorithm:
            return

        for scheme in self.allowable_signature_schemes:
            if not algorithms.Sign.is_recognized(scheme):
                continue
            
            if algorithms.Sign(scheme).key_algorithm != algorithms.Key(self.key_algorithm):
                self._add_error(
                    "allowable_signature_schemes",
                    f"must not contain schemes incompatible with key_algorithm ('{self.key_algorithm}')"
                )
                return

    def update(self, data):
        self.cast_changes(data, [
            "key_class", "key_algorithm", "key_size", "server_identifier", "local_identifier",
            "allowable_signature_schemes", "allowable_hash_algorithms", "public"
        ])

        self.validate_required(["key_class", "key_size"])
        self._check_identifier_presence()
        self._check_scheme_restriction()

        if self.key_class == "asymmetric":
            self.validate_required("key_algorithm", "is required when key_class is 'asymmetric'")

    def render(self, only=None):
        if only is None:
            only = ["key_class", "key_size"]

            if self.key_algorithm:
                only.append("key_algorithm")

            if self.server_identifier:
                only.append("server_identifier")

            if self.local_identifier:
                only.append("local_identifier")

            if self.allowable_signature_schemes is not None:
                only.append("allowable_signature_schemes")

            if self.allowable_hash_algorithms is not None:
                only.append("allowable_hash_algorithms")

            if self.public:
                only.append("public")

        return super().render(only)

class Results(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._sub_models(CertificationResults, LogResults)

        # Additional information related to the verification results, as determined by the evidence type
        cls._field("meta", Dictionary, nullable=True)

        cls._embedded_in("evidence_item", EvidenceItem)

    def initialise(self):
        if not self.meta:
            self.meta = {}

    def render(self, only=None):
        if only is None:
            only = []

            if self.meta:
                only.append("meta")

        return super().render(only)

class CertificationResults(Results):
    @classmethod
    def _schema(cls):
        super()._schema()

class LogResults(Results):
    @classmethod
    def _schema(cls):
        cls._field("certified_entry_count", Integer, nullable=True)
        super()._schema()

    def render(self, only=None):
        if only is None:
            only = []

            if self.certified_entry_count:
                only.append("certified_entry_count")

            if self.meta:
                only.append("meta")

        return super().render(only)
