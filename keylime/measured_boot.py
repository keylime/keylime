'''
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2021 IBM Corp.
'''

import json
import sys
import argparse
import traceback

from keylime import config
from keylime import keylime_logging

logger = keylime_logging.init_logging('measured_boot')

def read_mb_refstate(mb_path=None):
    if mb_path is None:
        mb_path = config.get('tenant', 'mb_refstate')

    mb_data = None
    # Purposefully die if path doesn't exist
    with open(mb_path, 'r') as f:
        mb_data = json.load(f)

    logger.debug("Loaded measured boot reference state from %s", mb_path)

    return mb_data

def process_refstate(mb_refstate_data=None) :
    if isinstance(mb_refstate_data, dict) :
        return mb_refstate_data
    return mb_refstate_data

def get_policy(mb_refstate_str):
    """ Convert the mb_refstate_str to JSON and get the measured boot policy.
    :param mb_refstate_str: String representation of measured boot reference state
    :returns: Returns the JSON object of the measured boot reference state and the measured boot policy;
              both can be None if mb_refstate_str was empty
    """

    if mb_refstate_str:
        mb_refstate_data = json.loads(mb_refstate_str)
    else:
        mb_refstate_data = None

    if mb_refstate_data:
        mb_policy_name = config.MEASUREDBOOT_POLICYNAME
        #pylint: disable=import-outside-toplevel
        from keylime.elchecking import policies as eventlog_policies
        #pylint: enable=import-outside-toplevel
        mb_policy = eventlog_policies.get_policy(mb_policy_name)
        if mb_policy is None:
            logger.warning(
                "Invalid measured boot policy name %s -- using accept-all instead.", mb_policy_name)
            mb_policy = eventlog_policies.AcceptAll()

        mb_pcrs_config = frozenset(config.MEASUREDBOOT_PCRS)
        mb_pcrs_policy = mb_policy.get_relevant_pcrs()
        if not mb_pcrs_policy <= mb_pcrs_config:
            logger.error("Measured boot policy considers PCRs %s, which are not among the configured set %s",
                        set(mb_pcrs_policy - mb_pcrs_config), set(mb_pcrs_config))
    else:
        mb_policy = None

    return mb_refstate_data, mb_policy

def evaluate_policy(mb_policy, mb_refstate_data, mb_measurement_data, pcrsInQuote, pcrPrefix, agent_id):
    missing = list(set(config.MEASUREDBOOT_PCRS).difference(pcrsInQuote))
    if len(missing) > 0:
        logger.error("%sPCRs specified for measured boot not in quote: %s", pcrPrefix, missing)
        return False
    try:
        reason = mb_policy.evaluate(mb_refstate_data, mb_measurement_data)
    except Exception as exn:
        logger.error("Boot attestation for agent %s, configured policy %s, refstate=%s, raised Exception %s",
            agent_id, config.MEASUREDBOOT_POLICYNAME, json.dumps(mb_refstate_data), str(exn))
        reason = ''
    if reason:
        logger.error("Boot attestation failed for agent %s, configured policy %s, refstate=%s, reason=%s",
            agent_id, config.MEASUREDBOOT_POLICYNAME, json.dumps(mb_refstate_data), reason)
        return False
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', default="mbtest.txt")
    args = parser.parse_args()
    try:
        read_mb_refstate(args.infile)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
