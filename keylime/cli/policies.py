import base64
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

from keylime import config, keylime_logging
from keylime.cmd import convert_runtime_policy
from keylime.ima import file_signatures, ima
from keylime.mba import mba
from keylime.tpm import tpm_util

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


# Dictionary specification for parameter to process_policy()
class ArgsType(TypedDict):
    tpm_policy: Optional[str]
    mask: str
    ima_sign_verification_keys: List[str]
    allowlist: str
    allowlist_name: str
    ima_exclude: str
    runtime_policy: str
    runtime_policy_name: str
    runtime_policy_sig_key: Optional[str]
    runtime_policy_checksum: str
    mb_policy: Optional[str]
    mb_policy_name: str


logger = keylime_logging.init_logging("cli.policies")


class UserError(Exception):
    pass


def enforce_pcrs(tpm_policy: Dict[str, Any], protected_pcrs: List[int], pcr_use: str) -> None:
    policy_pcrs = list(tpm_policy.keys())
    policy_pcrs.remove("mask")

    for _pcr in policy_pcrs:
        if int(_pcr) in protected_pcrs:
            logger.error(
                'WARNING: PCR %s is specified in "tpm_policy", but will in fact be used by %s. Please remove it from policy',
                _pcr,
                pcr_use,
            )
            sys.exit(1)


def process_policy(args: ArgsType) -> Tuple[Dict[str, Any], Optional[str], str, str, Optional[str], str, str]:
    tpm_policy_str = "{}"
    runtime_policy_name = ""
    mb_policy = None
    mb_policy_name = ""
    ima_sign_verification_keys: Optional[str] = ""
    runtime_policy = ""
    runtime_policy_key = ""

    # Set up PCR values
    if "tpm_policy" in args and args["tpm_policy"] is not None:
        tpm_policy_str = args["tpm_policy"]

    tpm_policy = tpm_util.readPolicy(tpm_policy_str)
    logger.info("TPM PCR Mask from policy is %s", tpm_policy["mask"])

    if len(args["ima_sign_verification_keys"]) > 0:
        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

        logger.warning(
            "WARNING: Verification key support in the Keylime tenant is deprecated. Provide "
            "verification keys as part of a runtime policy instead."
        )

        # Add all IMA file signing verification keys to a keyring
        tenant_keyring = file_signatures.ImaKeyring()
        for filename in args["ima_sign_verification_keys"]:
            try:
                pubkey, keyidv2 = file_signatures.get_pubkey_from_file(filename)
            except ValueError as e:
                raise UserError(f"File '{filename}' does not have a supported key: {e}") from e
            if not pubkey:
                raise UserError(f"File '{filename}' is not a file with a key")
            tenant_keyring.add_pubkey(pubkey, keyidv2)
        ima_sign_verification_keys = tenant_keyring.to_string()

    # Read command-line path string legacy policy and warn about deprecation.
    if "allowlist" in args and args["allowlist"] is not None:
        logger.warning(
            "WARNING: --allowlist is deprecated."
            "Keylime has implemented support for a unified policy format, and will no longer accept separate allow/exclude lists in the near future."
            "A conversion script to upgrade legacy allow/exclude lists to the new format is available under keylime/cmd/convert_runtime_policy.py."
        )

        enforce_pcrs(tpm_policy, [config.IMA_PCR], "IMA")

        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

        # Pass exclusion list to conversion script, if provided
        excl_path = None
        if "ima_exclude" in args and args["ima_exclude"] is not None:
            excl_path = args["ima_exclude"]

        # Convert legacy allow/exclude lists to IMA policy and encode as base64
        runtime_policy_dict = convert_runtime_policy.convert_legacy_allowlist(args["allowlist"])
        runtime_policy_raw = json.dumps(
            convert_runtime_policy.update_runtime_policy(runtime_policy_dict, excl_path)
        ).encode()
        runtime_policy = base64.b64encode(runtime_policy_raw).decode()

    # Warn about `--exclude` deprecation regardless of other args
    if "ima_exclude" in args and args["ima_exclude"] is not None:
        logger.warning(
            "WARNING: --exclude is deprecated."
            "Keylime has implemented support for a unified policy format, and will no longer accept separate allow/exclude lists in the near future."
            "A conversion script to upgrade legacy allow/exclude lists to the new format is available under keylime/cmd/convert_runtime_policy.py."
        )

    # Read command-line path string IMA policy
    if "runtime_policy" in args and args["runtime_policy"] is not None:
        enforce_pcrs(tpm_policy, [config.IMA_PCR], "IMA")

        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

        try:
            runtime_policy_bytes, runtime_policy_key_bytes = ima.read_runtime_policy(
                args["runtime_policy"],
                args["runtime_policy_checksum"],
                args["runtime_policy_sig_key"],
            )
            runtime_policy = base64.b64encode(runtime_policy_bytes).decode()
            runtime_policy_key = base64.b64encode(runtime_policy_key_bytes).decode()
        except Exception as ima_e:
            raise UserError(str(ima_e)) from ima_e

    # Store allowlist name
    if "allowlist_name" in args and args["allowlist_name"] is not None:
        runtime_policy_name = args["allowlist_name"]
        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

    # Store IMA policy name
    if "runtime_policy_name" in args and args["runtime_policy_name"] is not None:
        runtime_policy_name = args["runtime_policy_name"]
        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

    # Read command-line path string for measured boot policy
    mb_policy_data = None
    if "mb_policy" in args and args["mb_policy"] is not None:
        enforce_pcrs(tpm_policy, config.MEASUREDBOOT_PCRS, "measured boot")

        # Auto-enable TPM event log mesured boot (or-bit mask)
        for _pcr in config.MEASUREDBOOT_PCRS:
            tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << _pcr))

        logger.info("TPM PCR Mask automatically modified is %s to include IMA/Event log PCRs", tpm_policy["mask"])

        if isinstance(args["mb_policy"], str):
            if args["mb_policy"] == "default":
                args["mb_policy"] = config.get("tenant", "mb_refstate")
            mb_policy_data = mba.policy_load(args["mb_policy"])
        else:
            raise UserError("Invalid measured boot policy provided")

    # Set up measured boot (TPM event log) reference state
    if tpm_util.check_mask(tpm_policy["mask"], config.MEASUREDBOOT_PCRS[2]):
        # Process measured boot policy
        mb_policy = mb_policy_data

    # Store measured boot policy name
    if "mb_policy_name" in args and args["mb_policy_name"] is not None:
        mb_policy_name = args["mb_policy_name"]
        # Auto-enable TPM event log mesured boot (or-bit mask)
        for _pcr in config.MEASUREDBOOT_PCRS:
            tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << _pcr))

    return (
        tpm_policy,
        mb_policy,
        mb_policy_name,
        runtime_policy_name,
        ima_sign_verification_keys,
        runtime_policy,
        runtime_policy_key,
    )
