import argparse
import json
import sys

from keylime.mba import mba
from keylime.mba.elparsing import tpm2_tools_elparser

from . import policies

# This main module is just for command-line based testing.
# It implements a command to do one test.
# Invoke it with `python3 -m $packagename`, for some value of
# `$packagename` that works with your `$PYTHONPATH`.

mba.load_imports()
parser = argparse.ArgumentParser()
parser.add_argument("policy_name", choices=policies.get_policy_names())
parser.add_argument("refstate_file", type=str)
parser.add_argument("eventlog_file", nargs="?", type=str, default=None)
args = parser.parse_args()
policy = policies.get_policy(args.policy_name)
if policy is None:
    print(
        f"Specified policy '{args.policy_name}' does not exist. Options are: {policies.get_policy_names()}.",
        file=sys.stderr,
    )
    sys.exit(1)
# Read refstate file with error handling
try:
    with open(args.refstate_file, "rt", encoding="utf-8") as refstate_file:
        refstate_str = refstate_file.read()
except FileNotFoundError:
    print(f"Error: Reference state file '{args.refstate_file}' not found.", file=sys.stderr)
    sys.exit(1)
except PermissionError:
    print(f"Error: Permission denied reading reference state file '{args.refstate_file}'.", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    print(f"Error: Failed to read reference state file '{args.refstate_file}': {e}", file=sys.stderr)
    sys.exit(1)

# Parse refstate JSON with error handling
try:
    refstate = json.loads(refstate_str)
except json.JSONDecodeError as e:
    print(f"Error: Invalid JSON in reference state file '{args.refstate_file}': {e}", file=sys.stderr)
    sys.exit(1)

# Read eventlog file or stdin with error handling
try:
    if args.eventlog_file:
        with open(args.eventlog_file, "rb") as eventlog_file:
            log_bin = eventlog_file.read()
    else:
        # Read from stdin in binary mode
        log_bin = sys.stdin.buffer.read()
except FileNotFoundError:
    print(f"Error: Event log file '{args.eventlog_file}' not found.", file=sys.stderr)
    sys.exit(1)
except PermissionError:
    print(f"Error: Permission denied reading event log file '{args.eventlog_file}'.", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    source = args.eventlog_file if args.eventlog_file else "stdin"
    print(f"Error: Failed to read event log from {source}: {e}", file=sys.stderr)
    sys.exit(1)
_, log_data = tpm2_tools_elparser.parse_binary_bootlog(log_bin)
with open("/tmp/parsed.json", "wt", encoding="utf-8") as log_data_file:
    log_data_file.write(json.dumps(log_data, indent=True))
why_not = policy.evaluate(refstate, log_data)
if why_not:
    print(why_not, file=sys.stderr)
    sys.exit(1)
print("AOK")
