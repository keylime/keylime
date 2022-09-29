from keylime import keylime_logging

logger = keylime_logging.init_logging("cli_opts")


class UserError(Exception):
    pass


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
