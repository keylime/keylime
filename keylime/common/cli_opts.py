import sys

from keylime import config, keylime_logging, measured_boot
from keylime.ima import file_signatures, ima
from keylime.tpm.tpm_abstract import TPM_Utilities

logger = keylime_logging.init_logging("cli_opts")


class UserError(Exception):
    pass


def enforce_pcrs(tpm_policy, policy_pcrs, protected_pcrs, pcr_use):
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


def get_opts_error(args):
    if args.ima_exclude and not args.allowlist:
        return True, "--exclude cannot be used without an --allowlist"
    if args.allowlist and args.allowlist_url:
        return True, "--allowlist and --allowlist-url cannot be specified at the same time"
    if args.allowlist_url and not (args.allowlist_sig or args.allowlist_sig_url or args.allowlist_checksum):
        return (
            True,
            "--allowlist-url must have either --allowlist-sig, --allowlist-sig-url or --allowlist-checksum to verifier integrity",
        )
    if args.allowlist_sig and not (args.allowlist_url or args.allowlist):
        return True, "--allowlist-sig must have either --allowlist or --allowlist-url"
    if args.allowlist_sig_url and not (args.allowlist_url or args.allowlist):
        return True, "--allowlist-sig-url must have either --allowlist or --allowlist-url"
    if args.allowlist_checksum and not (args.allowlist_url or args.allowlist):
        return True, "--allowlist-checksum must have either --allowlist or --allowlist-url"
    if args.allowlist_sig and not args.allowlist_sig_key:
        return True, "--allowlist-sig must also have --allowlist-sig-key"
    if args.allowlist_sig_url and not args.allowlist_sig_key:
        return True, "--allowlist-sig-url must also have --allowlist-sig-key"
    if args.allowlist_sig_key and not (args.allowlist_sig or args.allowlist_sig_url):
        return True, "--allowlist-sig-key must have either --allowlist-sig or --allowlist-sig-url"
    return False, None


def process_allowlist(args):
    tpm_policy = "{}"
    ima_policy_name = ""
    mb_refstate = None
    ima_sign_verification_keys = []
    allowlist = {}

    # Set up PCR values
    if "tpm_policy" in args and args["tpm_policy"] is not None:
        tpm_policy = args["tpm_policy"]

    tpm_policy = TPM_Utilities.readPolicy(tpm_policy)
    logger.info("TPM PCR Mask from policy is %s", tpm_policy["mask"])

    if len(args.get("ima_sign_verification_keys")) > 0:
        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

        # Add all IMA file signing verification keys to a keyring
        tenant_keyring = file_signatures.ImaKeyring()
        for filename in args["ima_sign_verification_keys"]:
            pubkey, keyidv2 = file_signatures.get_pubkey_from_file(filename)
            if not pubkey:
                raise UserError(f"File '{filename}' is not a file with a key")
            tenant_keyring.add_pubkey(pubkey, keyidv2)
        ima_sign_verification_keys = tenant_keyring.to_string()

    # Read command-line path string allowlist
    al_data = None

    if "allowlist" in args and args["allowlist"] is not None:

        enforce_pcrs(tpm_policy, list(tpm_policy.keys()), [config.IMA_PCR], "IMA")

        # Auto-enable IMA (or-bit mask)
        tpm_policy["mask"] = hex(int(tpm_policy["mask"], 0) | (1 << config.IMA_PCR))

        try:
            al_data = ima.read_allowlist(
                args["allowlist"], args["allowlist_checksum"], args["allowlist_sig"], args["allowlist_sig_key"]
            )
        except Exception as ima_e:
            raise UserError(str(ima_e)) from ima_e

    # Read command-line path string IMA exclude list
    excl_data = None
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

        enforce_pcrs(tpm_policy, list(tpm_policy.keys()), config.MEASUREDBOOT_PCRS, "measured boot")

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
