import os
from typing import Any, Tuple

from keylime import keylime_logging

logger = keylime_logging.init_logging("cli.options")


class UserError(Exception):
    pass


def extract_password(pwstring: str) -> str:
    # First we check if "pwstring" points to a file on the fs which contains the pw
    pwstring = os.path.expanduser(pwstring)
    if os.path.exists(pwstring):
        with open(pwstring, encoding="utf-8") as fp:
            pwstring = fp.read().strip()
    # Second, check if "pwstring" is an environment variable defined to hold the pw
    if pwstring in os.environ:
        pwstring = os.environ[pwstring]

    # Finally, just return the contents of the (potentially modified) pwstring
    return pwstring


def get_opts_error(args: Any) -> Tuple[bool, str]:
    if args.command in ["addallowlist", "addruntimepolicy"] and not (
        args.allowlist or args.allowlist_url or args.runtime_policy or args.runtime_policy_url
    ):
        return True, "--allowlist or --runtime_policy is required to add a runtime policy"
    if args.ima_exclude and not args.allowlist:
        return True, "--exclude cannot be used without an --allowlist"
    if args.allowlist and args.allowlist_url:
        return True, "--allowlist and --allowlist-url cannot be specified at the same time"
    if args.runtime_policy and args.runtime_policy_url:
        return True, "--runtime_policy and --runtime_policy-url cannot be specified at the same time"
    if args.runtime_policy_url and not args.runtime_policy_checksum:
        return True, "--runtime_policy-url must have --runtime_policy-checksum to verifier integrity"
    if args.runtime_policy_checksum and not (args.runtime_policy_url or args.runtime_policy):
        return True, "--runtime_policy-checksum must have either --runtime_policy or --runtime_policy-url"
    return False, ""
