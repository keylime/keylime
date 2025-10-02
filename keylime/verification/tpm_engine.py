import json
import copy
import math

from keylime import config, keylime_logging
from keylime.verification.base import VerificationEngine, EngineDriver
from keylime.tpm import tpm_util, tpm2_objects
from keylime.tpm.tpm_main import Tpm
from keylime.models.base import db_manager
from keylime.failure import Component, Failure
from keylime.agentstates import AgentAttestState, TPMClockInfo, TPMState
from keylime.ima import ima
from keylime.ima.file_signatures import ImaKeyring, ImaKeyrings
from keylime.common import algorithms

logger = keylime_logging.init_logging("verifier")


class TPMEngine(VerificationEngine):

    @classmethod
    def register_callbacks(cls):
        EngineDriver.register_parameter_mutator(cls, ("tpm_quote", "uefi_log", "ima_log"))
        EngineDriver.register_evidence_evaluator(cls, ("tpm_quote", "uefi_log", "ima_log"))

    def __init__(self, attestation):
        super().__init__(attestation)
        self._attest_state = None

    def _validate_system_info(self):
        if not self.expects_ima_log:
            return

        self.attestation.validate_required("system_info")

        if self.attestation.system_info is not None:
            self.attestation.system_info.validate_required("boot_time")

    def _validate_tpm_quote_items(self):
        allowable_sig_schemes = self.attestation.agent.accept_tpm_signing_algs
        allowable_hash_algs = self.attestation.agent.accept_tpm_hash_algs

        tpm_quote_items = (
            self.attestation.evidence.view()
            .filter(evidence_class="certification", evidence_type="tpm_quote")
        )

        for item in tpm_quote_items.result():
            item_sig_schemes = item.capabilities.signature_schemes
            item_hash_algs = item.capabilities.hash_algorithms
            pcr_banks = item.capabilities.available_subjects.keys()

            useable_key_found = False

            for key in item.capabilities.certification_keys:
                key_alg = key.key_algorithm

                if not [ scheme for scheme in item_sig_schemes if scheme.startswith(key_alg) ]:
                    key._add_error("key_algorithm", "must be compatible with a given signature schemes")

                if [ scheme for scheme in allowable_sig_schemes if scheme.startswith(key_alg) ]:
                    useable_key_found = True

            if not useable_key_found:
                msg = "must have a key usable with a signature algorithm allowable for agent"
                item.capabilities._add_error("certification_keys", msg)

            if any(pcr_bank not in item_hash_algs for pcr_bank in pcr_banks):
                msg = "may only contain PCR banks for the given hash algorithms"
                item.capabilities._add_error("available_subjects", msg)

            if not any(pcr_bank in allowable_hash_algs for pcr_bank in pcr_banks):
                msg = "must have a PCR bank for a hash algorithm allowable for agent"
                item.capabilities._add_error("available_subjects", msg)

    def _validate_ima_log_items(self):
        ima_log_items = (
            self.attestation.evidence.view()
            .filter(evidence_class="certification", evidence_type="ima_log")
        )

        for item in ima_log_items.result():
            item.validate_required("capabilities")

            if item.capabilities:
                item.capabilities.validate_required("entry_count")

    def _select_tpm_quote_item(self):
        if not self.expects_tpm_quote:
            return None

        tpm_quote_items = (
            self.attestation.evidence.view()
            .filter(evidence_class="certification", evidence_type="tpm_quote")
        )

        if not tpm_quote_items.result():
            self._add_error("evidence", "must contain a certification item of type 'tpm_quote' per agent policy")
            return None

        allowable_sig_schemes = self.attestation.agent.accept_tpm_signing_algs
        allowable_hash_algs = self.attestation.agent.accept_tpm_hash_algs

        tpm_quote_items = (
            tpm_quote_items
            .filter(lambda item: item.capabilities.component_version == "2.0")
            .result_if_empty("check 'component_version'")
            .filter(lambda item: any(alg in allowable_sig_schemes for alg in item.capabilities.signature_schemes))
            .result_if_empty("check 'signature_schemes'")
            .filter(lambda item: any(alg in allowable_hash_algs for alg in item.capabilities.hash_algorithms))
            .result_if_empty("check 'hash_algorithms'")
            .filter(lambda item: any(alg in allowable_hash_algs for alg in item.capabilities.available_subjects.keys()))
            .result_if_empty("check PCR banks in 'available_subjects'")
            .filter(lambda item: self._certification_key_choices(item))
            .result_if_empty("check schemes and algorithms in 'certification_keys'")
        )

        if isinstance(tpm_quote_items.result(), str):
            tip = tpm_quote_items.result()
            self._add_error(
                "evidence",
                f"must have 'tpm_quote' with capabilities which are valid and satisfy agent policy ({tip})"
            )
            return None

        return tpm_quote_items.to_list()[0]

    def _signature_scheme_choices(self, evidence_item):
        scheme_choices = []

        for agent_scheme in self.attestation.agent.accept_tpm_signing_algs:
            if agent_scheme not in evidence_item.capabilities.signature_schemes:
                continue

            if not algorithms.Sign.is_recognized(agent_scheme):
                continue

            if agent_scheme in scheme_choices:
                continue

            scheme_choices.append(agent_scheme)
        
        return scheme_choices

    def _key_algorithm_choices(self, evidence_item):
        algorithm_choices = []

        for scheme_choice in self._signature_scheme_choices(evidence_item):
            key_alg = algorithms.Sign(scheme_choice).key_algorithm.value

            if key_alg in algorithm_choices:
                continue

            algorithm_choices.append(key_alg)

        return algorithm_choices

    def _hash_algorithm_choices(self, evidence_item):
        algorithm_choices = []

        for agent_alg in self.attestation.agent.accept_tpm_hash_algs:
            if agent_alg not in evidence_item.capabilities.hash_algorithms:
                continue

            if not algorithms.Hash.is_recognized(agent_alg):
                continue

            if agent_alg in algorithm_choices:
                continue

            algorithm_choices.append(agent_alg)
        
        return algorithm_choices

    def _certification_key_choices(self, evidence_item):
        # Get schemes and algorithms which are supported by both the certifier and the verifier and enabled for the
        # agent, ordered according to user-configured priority
        scheme_choices = self._signature_scheme_choices(evidence_item)
        key_algorithm_choices = self._key_algorithm_choices(evidence_item)
        hash_algorithm_choices = self._hash_algorithm_choices(evidence_item)

        # Construct set of qualifying certification keys
        cert_keys = (
            evidence_item.capabilities.certification_keys.view()
            # A key's key_algorithm must be compatible with one of the possible signature scheme choices
            .filter(lambda cert_key: cert_key.key_algorithm in key_algorithm_choices)
            # A key's allowable_signature_schemes (if present) must contain at least one of the possible scheme choices
            .filter(lambda cert_key: 
                cert_key.allowable_signature_schemes is None
                or any(scheme in scheme_choices for scheme in cert_key.allowable_signature_schemes) 
            )
            # A key's allowable_hash_algorithms (if present) must contain at least one of the possible algorithm choices
            # which is also an available PCR bank
            .filter(lambda cert_key: 
                cert_key.allowable_hash_algorithms is None
                or any(
                    algorithm in hash_algorithm_choices and evidence_item.capabilities.available_subjects.get(algorithm)
                    for algorithm in cert_key.allowable_hash_algorithms
                ) 
            )
            # Prefer certification keys which have a public key (if present) equal to the ak of the agent
            .filter(lambda cert_key: cert_key.public == self.attestation.agent.ak_tpm)
            .revert_if_empty()
            # Prefer certification keys which are identified as an ak
            .filter(lambda cert_key: cert_key.server_identifier == "ak")
            .revert_if_empty()
        )

        # Determine sort priority for a given certifcation key according to user-configured scheme/algorithm preferences
        def sort_priority(cert_key):
            priority = key_algorithm_choices.index(cert_key.key_algorithm)

            if cert_key.allowable_signature_schemes:
                priority += next(scheme_choices.index(scheme) for scheme in cert_key.allowable_signature_schemes)

            if cert_key.allowable_hash_algorithms:
                priority += next(hash_algorithm_choices.index(alg) for alg in cert_key.allowable_hash_algorithms)

            return priority

        # Sort keys according to priority
        cert_keys = cert_keys.to_list()
        cert_keys.sort(key=sort_priority)

        return cert_keys

    def _select_certification_key(self, evidence_item):
        cert_keys = self._certification_key_choices(evidence_item)

        if cert_keys:
            evidence_item.chosen_parameters.certification_key = cert_keys[0]

    def _select_subjects(self, evidence_item):
        # The PCR banks which may be requested, i.e., the hash algs supported by the TPM and enabled for the agent
        alg_choices = self._hash_algorithm_choices(evidence_item)
        # The hash algorithms allowed by the TPM for use with the selected certification key
        key_allowed_algs = evidence_item.chosen_parameters.certification_key.allowable_hash_algorithms
        # The PCR numbers for which the agent can produce quotes, grouped by available PCR bank
        available_subjects = evidence_item.capabilities.available_subjects
        # The PCR numbers for each PCR bank to include in the quote (none to start)
        selected_subjects = {}
        # Whether at least one suitable PCR bank is identified or not
        found = False

        # For consistent formatting of API responses, sort PCR banks by configured algorithm preference with disallowed
        # banks at the end
        pcr_banks = list(available_subjects.keys())
        pcr_banks.sort(key=lambda pcr_bank: alg_choices.index(pcr_bank) if pcr_bank in alg_choices else math.inf)

        # For each PCR bank, select the required PCRs by number (or use None if no PCRs are required for that bank)
        for pcr_bank in pcr_banks:
            pcr_nums = available_subjects[pcr_bank]

            if (
                pcr_bank in alg_choices
                and set(self.required_pcr_nums).issubset(pcr_nums)
                and (key_allowed_algs is None or pcr_bank in key_allowed_algs)
            ):
                selected_subjects[pcr_bank] = self.required_pcr_nums or None
                found = True
            else:
                selected_subjects[pcr_bank] = None

        # If none of the allowable PCR banks contain the full list of required PCRs, produce an error
        if not found:
            msg = (
                "must have 'tpm_quote' with capabilities which satisfy agent policy (check the correct numbered PCRs "
                "are given for an allowable PCR bank)"
            )
            self.attestation._add_error("evidence", msg)

        evidence_item.chosen_parameters.selected_subjects = selected_subjects

    def _select_signature_scheme(self, evidence_item):
        if not evidence_item.chosen_parameters or not evidence_item.chosen_parameters.certification_key:
            return

        cert_key = evidence_item.chosen_parameters.certification_key

        possible_schemes = [
            scheme
            for scheme in self._signature_scheme_choices(evidence_item)
            if algorithms.Sign(scheme).key_algorithm.value == cert_key.key_algorithm
            and (cert_key.allowable_signature_schemes is None or scheme in cert_key.allowable_signature_schemes)
        ]

        if possible_schemes:
            evidence_item.chosen_parameters.signature_scheme = possible_schemes[0]

    def _select_hash_algorithm(self, evidence_item):
        params = evidence_item.chosen_parameters

        if not params or not params.certification_key or not params.selected_subjects:
            return

        cert_key = params.certification_key

        possible_algorithms = [
            algorithm
            for algorithm in self._hash_algorithm_choices(evidence_item)
            if (cert_key.allowable_hash_algorithms is None or algorithm in cert_key.allowable_hash_algorithms)
            and params.selected_subjects.get(algorithm)
        ]

        if possible_algorithms:
            evidence_item.chosen_parameters.hash_algorithm = possible_algorithms[0]

    def _select_uefi_log_item(self):
        if not self.expects_uefi_log:
            return None

        uefi_log_items = (
            self.attestation.evidence.view()
            .filter(evidence_class="log", evidence_type="uefi_log")
            .result_if_empty("must contain a log item of type 'uefi_log' per agent policy")
            .filter(lambda item: "application/octet-stream" in item.capabilities.formats)
            .result_if_empty("must have 'uefi_log' with format 'application/octet-stream'")
        )

        if isinstance(uefi_log_items.result(), str):
            self.attestation._add_error("evidence", uefi_log_items.result())
            return None

        return uefi_log_items.to_list()[0]

    def _select_ima_log_item(self):
        if not self.expects_ima_log:
            return None

        ima_log_items = (
            self.attestation.evidence.view()
            .filter(evidence_class="log", evidence_type="ima_log")
            .result_if_empty("must contain a log item of type 'ima_log' per agent policy")
            .filter(
                lambda item: "text/plain" in item.capabilities.formats and item.capabilities.supports_partial_access
            )
            .result_if_empty("must have 'ima_log' with format 'text/plain' and which supports partial access")
        )

        if isinstance(ima_log_items.result(), str):
            self.attestation._add_error("evidence", ima_log_items.result())
            return None

        return ima_log_items.to_list()[0]

    def _determine_ima_offset(self, evidence_item):
        if not self.expects_ima_log:
            return None

        if not self.attestation.system_info or not self.attestation.system_info.boot_time:
            return None

        if not evidence_item.capabilities or not evidence_item.capabilities.entry_count:
            return None

        prev_att = self.previous_passed_attestation

        if not prev_att or not prev_att.system_info or not prev_att.system_info.boot_time:
            starting_offset = 0
        elif self.attestation.system_info.boot_time > prev_att.system_info.boot_time:
            starting_offset = 0
        elif self.attestation.system_info.boot_time == prev_att.system_info.boot_time:
            starting_offset = self.previous_passed_ima_log.next_starting_offset
        elif self.attestation.system_info.boot_time < prev_att.system_info.boot_time:
            msg = "must be equal to or greater than the boot time of last attestation"
            self.attestation.system_info._add_error("boot_time", msg)
            return None
        
        if starting_offset > evidence_item.capabilities.entry_count:
            msg = f"must be greater than or equal to the calculated starting offset of '{starting_offset}'"
            evidence_item.capabilities._add_error("entry_count", msg)
            return None

        return starting_offset

    def _process_tpm_quote_capabilities(self, evidence_requested):
        selected_item = self._select_tpm_quote_item()

        if not selected_item:
            return

        selected_item.generate_challenge(128)

        self._select_certification_key(selected_item)
        self._select_subjects(selected_item)
        self._select_signature_scheme(selected_item)
        self._select_hash_algorithm(selected_item)

        evidence_requested.append(selected_item)

    def _process_uefi_log_capabilities(self, evidence_requested):
        selected_item = self._select_uefi_log_item()

        if not selected_item:
            return

        selected_item.chosen_parameters.format = "application/octet-stream"
        evidence_requested.append(selected_item)

    def _process_ima_log_capabilities(self, evidence_requested):
        selected_item = self._select_ima_log_item()

        if not selected_item:
            return

        selected_item.chosen_parameters.starting_offset = self._determine_ima_offset(selected_item)
        selected_item.chosen_parameters.format = "text/plain"

        evidence_requested.append(selected_item)

    def _get_pull_mode_quote(self, evidence_item):
        data = evidence_item.data.render(["message", "signature", "subject_data"])

        quoteblob = data["message"]
        sigblob = data["signature"]
        pcrblob = data["subject_data"]

        return f"r{quoteblob}:{sigblob}:{pcrblob}"

    def _parse_tpm_clock_info(self, evidence_item):
        quote = self._get_pull_mode_quote(evidence_item)
        clock_info_dict = Tpm._tpm2_clock_info_from_quote(quote, False)
        return TPMClockInfo.from_dict(clock_info_dict)

    def _parse_pcrs(self, evidence_item):
        pcrblob = evidence_item.data.subject_data
        pcr_select_count, tpml_pcr_selection, pcr_values = getattr(tpm_util, "__get_pcrs_from_blob")(pcrblob)

        pcrs = {}
        unknown = {}
        idx = 0

        for tpm_alg_id, pcr_mask in tpml_pcr_selection.items():
            hash_fn = tpm2_objects.HASH_FUNCS.get(tpm_alg_id)
            pcrs_for_alg = {}

            for pcr_num in range(0, 24):
                if tpml_pcr_selection[tpm_alg_id] & (1 << pcr_num) == 0:
                    continue

                pcr_hex_digits = pcr_values[idx].hex()
                pcrs_for_alg[str(pcr_num)] = f"0x{pcr_hex_digits}"
                idx = idx + 1

            if not pcrs_for_alg:
                continue

            if hash_fn:
                hash_fn_name = type(hash_fn).__name__.lower()
                pcrs[hash_fn_name] = pcrs_for_alg
            else:
                tpm_alg_hex_digits = tpm_alg_id.to_bytes(2, byteorder='big').hex()
                unknown[f"0x{tpm_alg_hex_digits}"] = pcrs_for_alg

        return (pcrs, unknown)

    def _attest_state_pcrs(self, evidence_item):
        pcrs, _ = self._parse_pcrs(evidence_item)
        hash_alg = evidence_item.chosen_parameters.hash_algorithm
        pcr_pairs = pcrs.get(hash_alg)
        return {int(num): bytes.fromhex(val[2:]) for num, val in pcr_pairs.items()}

    def _attest_state_ima_pcrs(self, evidence_item):
        return {num: val for num, val in self._attest_state_pcrs(evidence_item).items() if num == config.IMA_PCR}

    def _render_tpm_quote_info(self):
        tpm_quote_items = (
            self.attestation.evidence.view()
            .filter(evidence_class="certification", evidence_type="tpm_quote")
        )
        
        for item in tpm_quote_items.result():
            (pcrs, unknown) = self._parse_pcrs(item)
            item.data.meta["pcrs"] = pcrs

            if unknown:
                item.data.meta["unknown_banks"] = unknown

            clock_info = self._parse_tpm_clock_info(item)
            item.data.meta["clock_info"] = {
                "clock": clock_info.clock,
                "reset_count": clock_info.resetcount,
                "restart_count": clock_info.restartcount,
                "safe": clock_info.safe
            }

    def _process_tpm_quote_evidence(self):
        self._render_tpm_quote_info()
        selected_item = self._select_tpm_quote_item()

        if not selected_item:
            return

        rendered_pcrs = selected_item.data.meta.get("pcrs", {})

        for pcr_bank, selected_pcr_nums in selected_item.chosen_parameters.selected_subjects.items():
            if not selected_pcr_nums:
                continue

            selected_pcr_nums = {str(num) for num in selected_pcr_nums}
            pcr_pairs = rendered_pcrs.get(pcr_bank, {})

            if not selected_pcr_nums.issubset(pcr_pairs.keys()):
                selected_item.data._add_error("subject_data", "must contain at least the PCRs requested")
                break

    def _process_ima_log_evidence(self):
        selected_item = self._select_ima_log_item()

        if not selected_item:
            return

        entries = selected_item.data.entries or ""
        requested_entry_count = selected_item.chosen_parameters.entry_count
        expected_entry_count = selected_item.capabilities.entry_count - selected_item.chosen_parameters.starting_offset

        selected_item.data.entry_count = entries.count("\n")

        if requested_entry_count and selected_item.data.entry_count > requested_entry_count:
            selected_item.data._add_error("entries", "must not exceed the number of entries requested")

        if selected_item.data.entry_count < expected_entry_count:
            msg = (
                f"must contain at least {expected_entry_count} entries based on the total reported log length and "
                f"chosen starting offset"
            )
            selected_item.data._add_error("entries", msg)

    def _determine_failure_reason(self, failure):
        if not failure:
            logger.info("Attestation %s for agent '%s' successfully passed verification", self.index, self.agent_id)
            return

        for event in failure.events:
            # Note: "qoute_validation" below is spelt incorrectly on purpose
            if event.event_id == "qoute_validation.quote_validation":
                self.failure_reason = "broken_evidence_chain"
                msg = (
                    "Attestation %s for agent '%s' failed verification because the TPM quote could not be authenticated"
                )
                logger.warning(msg, self.index, self.agent_id)
                return

            if event.event_id.startswith("measured_boot.invalid_pcr_"):
                self.failure_reason = "broken_evidence_chain"
                msg = (
                    "Attestation %s for agent '%s' failed verification because the UEFI log could not be authenticated "
                    "against the TPM quote"
                )
                logger.warning(msg, self.index, self.agent_id)
                return

            if event.event_id == "ima.pcr_mismatch":
                self.failure_reason = "broken_evidence_chain"
                msg = (
                    "Attestation %s for agent '%s' failed verification because the IMA log could not be authenticated "
                    "against the TPM quote"
                )
                logger.warning(msg, self.index, self.agent_id)
                return

        self.failure_reason = "policy_violation"
        msg = "Attestation %s for agent '%s' failed verification due to policy violations (see above)"
        logger.warning(msg, self.index, self.agent_id)

    def _get_pcr_policy(self, pcr_bank):
        policy = {}
        pcr_size = algorithms.Hash(pcr_bank).get_hex_size()

        for pcr_num, allowed_vals in self.agent.tpm_policy.items():
            if not pcr_num.isdigit():
                continue

            if not allowed_vals:
                allowed_vals = []

            if not isinstance(allowed_vals, list):
                continue

            allowed_vals = [ val.removeprefix("0x") for val in allowed_vals if len(val.removeprefix("0x")) == pcr_size ]

            policy[int(pcr_num)] = allowed_vals

        return policy

    def _clear_agent_fields(self):
        if self.previous_authenticated_attestation:
            return

        self.agent.boottime = None
        self.agent.hash_alg = None
        self.agent.enc_alg = None
        self.agent.sign_alg = None
        self.agent.operational_state = None
        self.agent.ima_sign_verification_keys = None
        self.agent.ima_pcrs = None  # This is ignored by Tpm.check_quote()
        self.agent.pcr10 = None
        self.agent.next_ima_ml_entry = None
        self.agent.severity_level = None
        self.agent.last_event_id = None
        self.agent.supported_version = "None"
        self.agent.tpm_clockinfo = None
        self.agent.tpm_version = None
        self.agent.last_received_quote = None
        self.agent.last_successful_attestation = None

    def _process_results(self, failure):
        ima_log_item = self._select_ima_log_item()

        if ima_log_item:
            starting_offset = ima_log_item.chosen_parameters.starting_offset
            ima_log_item.results.certified_entry_count = self.attest_state.next_ima_ml_entry - starting_offset

        if not failure: 
            self.attestation.evaluation = "pass"
            self.agent.attestation_count += 1
        else:
            self.attestation.evaluation = "fail"
            self.agent.accept_attestations = False

        self.attestation.refresh_metadata()
        self._determine_failure_reason(failure)

        # Only save new learned keyrings if quote was authenticated
        if self.failure_reason != "broken_evidence_chain":
            self.agent.learned_ima_keyrings = self.attest_state.get_ima_keyrings().to_json()

    def process_capabilities(self, evidence_requested):
        self._validate_system_info()
        self._validate_tpm_quote_items()
        self._validate_ima_log_items()
        self._process_tpm_quote_capabilities(evidence_requested)
        self._process_uefi_log_capabilities(evidence_requested)
        self._process_ima_log_capabilities(evidence_requested)

    def process_evidence(self):
        self._process_tpm_quote_evidence()
        self._process_ima_log_evidence()

    def verify_evidence(self):
        logger.info("Starting verification of attestation %s for agent '%s'...", self.index, self.agent_id)

        tpm_quote_item = self._select_tpm_quote_item()
        uefi_log_item = self._select_uefi_log_item()
        ima_log_item = self._select_ima_log_item()

        ima_entries = ima_log_item.data.entries or "" if ima_log_item else None
        uefi_entries = uefi_log_item.data.entries if uefi_log_item else None

        failure = Failure(Component.QUOTE_VALIDATION)

        # Note: there is no need to call self.attest_state.reset_ima_attestation() after reboot as the IMA-relevant
        # values are already properly initialised by self.attest_state

        result = Tpm().check_quote(
            self.attest_state,
            nonce = tpm_quote_item.chosen_parameters.challenge,
            data = None,
            quote = self._get_pull_mode_quote(tpm_quote_item),
            aikTpmFromRegistrar = self.agent.ak_tpm,
            tpm_policy = self._get_pcr_policy(tpm_quote_item.chosen_parameters.hash_algorithm),
            ima_measurement_list = ima_entries,
            runtime_policy = self.ima_policy,
            hash_alg = algorithms.Hash(tpm_quote_item.chosen_parameters.hash_algorithm),
            ima_keyrings = self.attest_state.get_ima_keyrings(),
            mb_measurement_list = uefi_entries,
            mb_policy = self.uefi_ref_state,
            compressed = False,
            count = self.agent.attestation_count
        )
        failure.merge(result)

        # Note: self.attest_state now reflects the verification outcome including the next expected IMA entry

        # Clear any fields from the agent record which were previously used for pull-mode attestation
        self._clear_agent_fields()
        self._process_results(failure)

        # with db_manager.session_context_for(self.attestation, self.attestation.evidence, self.agent) as session:
        #     self.agent.commit_changes(session)
        #     self.attestation.commit_changes(session)

        #     for item in self.attestation.evidence:
        #         item.commit_changes(session)

        #     if (
        #         self.evaluation == "pass"
        #         and self.previous_attestation
        #         and self.previous_attestation.evaluation == "pass"
        #         and self.previous_ima_log.chosen_parameters.starting_offset != 0
        #     ):
        #         self.previous_attestation.delete()

    @property
    def uefi_ref_state(self):
        return self.agent.mb_policy.mb_policy

    @property
    def ima_policy(self):
        return self.agent.ima_policy.ima_policy

    @property
    def required_pcr_nums(self):
        # Get PCRs with list of allowable values in tpm_policy
        pcrs = { int(num) for num, allowed_vals in self.agent.tpm_policy.items() if num.isdigit() and allowed_vals }

        # Add UEFI log PCRs
        if self.expects_uefi_log:
            pcrs.update(config.MEASUREDBOOT_PCRS)

        # Add IMA PCR
        if self.expects_ima_log:
            pcrs.add(config.IMA_PCR)

        return sorted(list(pcrs))

    @property
    def expects_tpm_quote(self):
        return bool(self.required_pcr_nums)

    @property
    def expects_uefi_log(self):
        return self.agent.mb_policy and self.agent.mb_policy.mb_policy

    @property
    def expects_ima_log(self):
        return (
            self.agent.ima_policy and
            self.agent.ima_policy.ima_policy and
            self.agent.ima_policy.generator and
            self.agent.ima_policy.generator > ima.RUNTIME_POLICY_GENERATOR.EmptyAllowList
        )

    @property
    def previous_authenticated_tpm_quote(self):
        return TPMEngine(self.previous_authenticated_attestation)._select_tpm_quote_item()

    @property
    def previous_passed_tpm_quote(self):
        return TPMEngine(self.previous_passed_attestation)._select_tpm_quote_item()

    @property
    def previous_authenticated_ima_log(self):
        return TPMEngine(self.previous_authenticated_attestation)._select_ima_log_item()

    @property
    def previous_passed_ima_log(self):
        return TPMEngine(self.previous_passed_attestation)._select_ima_log_item()

    @property
    def previous_ima_log(self):
        return TPMEngine(self.previous_attestation)._select_ima_log_item()

    @property
    def attest_state(self):
        """The most current verification state of the attested system as understood by the verifier, returned as an
        AgentAttestState object. This object contains the parameters which are used as input to Keylime's low-level 
        verification functions in ``keylime.tpm``. During verification, these functions update the AgentAttestState
        object to reflect the processed evidence.

        The verification parameters are initialised from values contained in the relevant ``Attestation`` and
        ``VerifierAgent`` records and are often referred to by different names within the higher-level classes in
        ``keylime.web``, ``keylime.models`` and ``keylime.verifcation``. At point of verification, this method
        prepares this information in the format expected by the lower-level libraries.

        Prior to verification of an attestation, the AgentAttestState object includes the following paramaters:

            * ``boottime``: the last boot time of the attester as reported by the agent
              (obtained from ``attestation.boot_time``)

            * ``tpm_clockinfo``: the decoded clock data contained within the previous TPM quote, to be compared against
              the clock data from the newly received quote
              (obtained from ``tpm_quote.data.message`` within ``previous_authenticated_attestation.evidence``)

            * ``ima_keyring``: an object containing the IMA keys trusted by the agent's IMA policy plus those learned
              by processing earlier IMA logs
              (obtained from ``agent.ima_policy`` and ``agent.learned_ima_keyrings``)

            * ``next_ima_ml_entry``: the entry at which the IMA log is expected to begin
              (obtained from ``ima_log.chosen_parameters.starting_offset`` within ``attestation.evidence``)

            * ``tpm_state``: an object containing the IMA PCR value received in the last verified attestation; used to
              resume verification from the last known-good state rather than sending the entire log every attestation
              (obtained from ``tpm_quote.data.message`` within ``previous_passed_attestation.evidence``)

            * ``quote_progress``: a 2-tuple of the number of IMA log entries received in the last verified attestation
              which were reflected in the TPM quote and the total number of entries received; used to track whether the
              IMA log is growing faster than the TPM can measure it and determine the next starting offset
              (obtained from ``ima_log.results.certified_entry_count`` and ``ima_log.data.entry_count``
              within ``previous_passed_attestation.evidence``)

        During the course of verification, these values (with the exception of ``bootime``) are updated in memory to
        reflect the parameters to be used to verify the next received attestation. This is done by ``keylime.tpm`` by
        mutating the AgentAttestState object directly.

        Where appropriate, ``self._process_results()`` ensures that these new values are persisted in the database so
        that the complete state can be reconstructed on the next incoming attestation.
        """
        tpm_quote_item = self._select_tpm_quote_item()
        ima_log_item = self._select_ima_log_item()

        if not tpm_quote_item.chosen_parameters or (ima_log_item and not ima_log_item.chosen_parameters):
            return None

        if self._attest_state:
            return self._attest_state

        state = AgentAttestState(self.attestation.agent_id)
        state.set_boottime(int(self.attestation.system_info.boot_time.timestamp()))

        # Retrieve clock info from previous quote
        if self.previous_authenticated_attestation:
            state.set_tpm_clockinfo(self._parse_tpm_clock_info(self.previous_authenticated_tpm_quote))
        elif self.agent.tpm_clockinfo:
            # The agent has a tpm_clockinfo value, so it recently changed from pull to push mode
            state.set_tpm_clockinfo(TPMClockInfo.from_dict(self.agent.tpm_clockinfo))

        # If IMA log is being verified, update state with IMA-relevant parameters
        if ima_log_item:
            # Retrieve trusted keys from IMA policy
            ima_keyrings = state.get_ima_keyrings()
            ima_keyrings.set_tenant_keyring(ImaKeyring.from_string(self.ima_policy.get("verification-keys") or ""))

            # Retrieve keys learned from ima-buf entries received in prior IMA logs
            if ima_log_item.chosen_parameters.starting_offset != 0:
                ima_keyrings.update(ImaKeyrings.from_json(self.agent.learned_ima_keyrings or {}))

            # Set starting offset of IMA log
            state.set_next_ima_ml_entry(ima_log_item.chosen_parameters.starting_offset)

            # Retrieve IMA PCR value from previous attestation which passed verification
            if self.previous_passed_attestation:
                state.set_ima_pcrs(self._attest_state_ima_pcrs(self.previous_passed_tpm_quote))
            elif self.agent.pcr10:
                # The agent has a pcr10 value, so it recently changed from pull to push mode
                state.set_ima_pcrs({10: self.agent.pcr10})

            # Retrieve IMA log progress from previous attestation which passed verification
            if self.previous_passed_attestation:
                certified_count = self.previous_passed_ima_log.results.certified_entry_count
                received_count = self.previous_passed_ima_log.data.entry_count
                state.quote_progress = (certified_count, received_count)

            # NOTE: The IMA PCR and IMA log progress are set based on the last attestation which passed verification
            # rather than the last attestation which could be authenticated. This is because process_measurement_list()
            # in keylime.ima resets these values whenever a verification failure occurs, causing the log entries from a
            # failed attestation to be repeated and re-verified in a subsequent attestation.

        self._attest_state = state
        return state
