#!/usr/bin/env python3

"""
Utility to assist with runtime policies.
"""

import argparse
import logging
import os
import sys

try:
    import argcomplete
except ModuleNotFoundError:
    argcomplete = None


from keylime.policy import create_runtime_policy

logger = logging.getLogger("keylime-policy")


def main() -> None:
    """keylime-policy entry point."""
    if os.geteuid() != 0:
        logger.critical("Please, run this program as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(add_help=False)

    main_parser = argparse.ArgumentParser()

    action_subparsers = main_parser.add_subparsers(title="actions")

    create_parser = action_subparsers.add_parser("create", help="create policy", parents=[parser])
    create_subparser = create_parser.add_subparsers(title="create")
    create_subparser.required = True

    create_runtime_policy.get_arg_parser(create_subparser, parser)

    if argcomplete:
        # This should happen before parse_args()
        argcomplete.autocomplete(main_parser)

    args = main_parser.parse_args()
    if "func" not in args:
        main_parser.print_help()
        main_parser.exit()

    args.func(args)


if __name__ == "__main__":
    main()
