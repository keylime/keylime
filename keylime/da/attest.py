#!/usr/bin/python3

import argparse
import sys

from keylime import cloud_verifier_common, config, keylime_logging
from keylime.da import record

logger = keylime_logging.init_logging("attestation")


def main(argv=sys.argv):  # pylint: disable=dangerous-default-value
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument(
        "-u", "--uuid", action="store", dest="agent_uuid", default="all", help="UUID for the agent to attest"
    )

    args = parser.parse_args(argv[1:])

    rmc = record.get_record_mgt_class(config.get("registrar", "durable_attestation_import", fallback=""))("registrar")

    if args.agent_uuid.lower() == "all":
        print("=> Getting a list of agents registered on the persistent store")
        _agent_list = []
        rmc.agent_list_retrieval(_agent_list, "auto", "registration")
    else:
        print('=> Focusing on the agent "' + args.agent_uuid + '" on the persistent store.')
        _agent_list = [args.agent_uuid]
        print()

    for _agent_uuid in _agent_list:
        _ak_list = []
        print('===> Getting all existing registration records for agent "' + _agent_uuid + '"...')
        print()

        rmc.build_key_list(_agent_uuid, _ak_list)

        rmc = record.get_record_mgt_class(config.get("cloud_verifier", "durable_attestation_import", fallback=""))(
            "registrar"
        )

        _attestation_record_list = []
        print('===> Getting all existing attestation records for agent "' + _agent_uuid + '"...')
        print()
        rmc.record_read(_attestation_record_list, _agent_uuid, "cloud_verifier")
        print()

        print('=====> Verifing the state of agent "' + _agent_uuid + '" over time...')

        _p_tpm_ts = None
        _d_tpm_ts = 0

        agentAttestState = None
        for _record in _attestation_record_list:
            agent = _record["agent"]
            json_response = _record["json_response"]
            ima_policy = _record["ima_policy"]

            _v_id = (
                'verifier "' + agent["verifier_id"] + "(" + agent["verifier_ip"] + ":" + agent["verifier_port"] + ")"
            )

            _msg_id = ' agent "' + _agent_uuid + '", captured by ' + _v_id
            print()
            print("---------- Attesting data (quote and logs) from " + _msg_id + " ----------")

            if not agentAttestState:
                agentAttestState = cloud_verifier_common.get_AgentAttestStates().get_by_agent_id(agent["agent_id"])

            if "tpm_clockinfo" in agent:
                if "clock" in agent["tpm_clockinfo"]:
                    _p_tpm_ts = agent["tpm_clockinfo"]["clock"]

            failure = cloud_verifier_common.process_quote_response(
                agent, ima_policy, json_response["results"], agentAttestState
            )

            if "tpm_clockinfo" in agent:
                if "clock" in agent["tpm_clockinfo"]:
                    _c_tpm_ts = agent["tpm_clockinfo"]["clock"]

            if _p_tpm_ts:
                _d_tpm_ts = _c_tpm_ts - _p_tpm_ts

            if failure.events:
                print(
                    '---------- Agent "'
                    + _agent_uuid
                    + '" was NOT in "attested" state at "'
                    + _record["cloud_verifier" + "_timestamp"]
                    + '"  (TPM delta: '
                    + str(_d_tpm_ts)
                    + ") : "
                    + str(failure.highest_severity_event.event_id)
                    + " "
                    + str(failure.highest_severity_event.context)
                    + " ----------"
                )
            else:
                print(
                    '---------- Agent "'
                    + _agent_uuid
                    + '" was in "attested" state at "'
                    + _record["cloud_verifier" + "_timestamp"]
                    + '" (TPM delta: '
                    + str(_d_tpm_ts)
                    + ") ----------"
                )
