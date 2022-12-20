import argparse
import json
import sys

from ..tpm import tpm_main
from . import policies

policies.load_policies()
# This main module is just for command-line based testing.
# It implements a command to do one test.
# Invoke it with `python3 -m $packagename`, for some value of
# `$packagename` that works with your `$PYTHONPATH`.


parser = argparse.ArgumentParser()
parser.add_argument("policy_name", choices=policies.get_policy_names())
parser.add_argument("refstate_file", type=argparse.FileType("rt"))
parser.add_argument("eventlog_file", type=argparse.FileType("rb"), default=sys.stdin)
args = parser.parse_args()
policy = policies.get_policy(args.policy_name)
if policy is None:
    print(
        f"Specified policy '{args.policy_name}' does not exist. Options are: {policies.get_policy_names()}.",
        file=sys.stderr,
    )
    sys.exit(1)
refstate_str = args.refstate_file.read()
refstate = json.loads(refstate_str)
log_bin = args.eventlog_file.read()
tpm = tpm_main.tpm()
_, log_data = tpm.parse_binary_bootlog(log_bin)
with open("/tmp/parsed.json", "wt", encoding="utf-8") as log_data_file:
    log_data_file.write(json.dumps(log_data, indent=True))
why_not = policy.evaluate(refstate, log_data)
if why_not:
    print(why_not, file=sys.stderr)
    sys.exit(1)
print("AOK")
