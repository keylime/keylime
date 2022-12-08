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
    return False, ""
