import sys
from typing import Any, Dict, List, Optional, Tuple

from keylime import config, keylime_logging, measured_boot
from keylime.ima import file_signatures, ima
from keylime.tpm.tpm_abstract import TPM_Utilities

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

# Dictionary specification for parameter to process_allowlist()
class ArgsType(TypedDict):
    tpm_policy: Optional[str]
    mask: str
    ima_sign_verification_keys: List[str]
    allowlist: str
    allowlist_name: str
    allowlist_sig: Optional[str]
    allowlist_sig_key: Optional[str]
    allowlist_checksum: str
    ima_exclude: str
    mb_refstate: Optional[str]


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


def process_allowlist(args: ArgsType) -> Tuple[Dict[str, Any], Optional[str], str, Optional[str], Dict[str, Any]]:
    tpm_policy_str = "{}"
    ima_policy_name = ""
    mb_refstate = None
    ima_sign_verification_keys: Optional[str] = None
    allowlist = {}

    # Set up PCR values
    if "tpm_policy" in args and args["tpm_policy"] is not None:
        tpm_policy_str = args["tpm_policy"]

    tpm_policy = TPM_Utilities.readPolicy(tpm_policy_str)
    logger.info("TPM PCR Mask from policy is %s", tpm_policy["mask"])

    if len(args["ima_sign_verification_keys"]) > 0:
        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

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

    # Read command-line path string allowlist
    al_data: Dict[str, List[str]] = {"excllist": []}

    if "allowlist" in args and args["allowlist"] is not None:

        enforce_pcrs(tpm_policy, [config.IMA_PCR], "IMA")

        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

        try:
            al_data = ima.read_allowlist(
                args["allowlist"], args["allowlist_checksum"], args["allowlist_sig"], args["allowlist_sig_key"]
            )
        except Exception as ima_e:
            raise UserError(str(ima_e)) from ima_e

    # Read command-line path string IMA exclude list
    excl_data = []
    if "ima_exclude" in args and args["ima_exclude"] is not None:
        if isinstance(args["ima_exclude"], str):
            excl_data = ima.read_excllist(args["ima_exclude"])
        elif isinstance(args["ima_exclude"], list):
            excl_data = args["ima_exclude"]
        else:
            raise UserError("Invalid exclude list provided")

    # Set up IMA
    if TPM_Utilities.check_mask(tpm_policy["mask"], config.IMA_PCR):
        # Process allowlists
        al_data["excllist"] = excl_data
        allowlist = al_data

    # Store allowlist name
    if "allowlist_name" in args and args["allowlist_name"] is not None:
        ima_policy_name = args["allowlist_name"]
        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

    # Read command-line path string TPM event log (measured boot) reference state
    mb_refstate_data = None
    if "mb_refstate" in args and args["mb_refstate"] is not None:

        enforce_pcrs(tpm_policy, config.MEASUREDBOOT_PCRS, "measured boot")

        # Auto-enable TPM event log mesured boot (or-bit mask)
        for _pcr in config.MEASUREDBOOT_PCRS:
            tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << _pcr))

        logger.info("TPM PCR Mask automatically modified is %s to include IMA/Event log PCRs", tpm_policy["mask"])

        if isinstance(args["mb_refstate"], str):
            if args["mb_refstate"] == "default":
                args["mb_refstate"] = config.get("tenant", "mb_refstate")
            mb_refstate_data = measured_boot.read_mb_refstate(args["mb_refstate"])
        else:
            raise UserError("Invalid measured boot reference state (intended state) provided")

    # Set up measured boot (TPM event log) reference state
    if TPM_Utilities.check_mask(tpm_policy["mask"], config.MEASUREDBOOT_PCRS[2]):
        # Process measured boot reference state
        mb_refstate = mb_refstate_data

    return tpm_policy, mb_refstate, ima_policy_name, ima_sign_verification_keys, allowlist
