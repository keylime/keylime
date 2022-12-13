#!/usr/bin/python3
import argparse
from datetime import datetime

from keylime import cloud_verifier_common, config, keylime_logging
from keylime.da import record

logger = keylime_logging.init_logging("durable_attestation_fetch_and_replay")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--uuid",
        action="store",
        dest="agent_uuid",
        default="all",
        help='UUID for the agent to attest (default "all")',
    )
    parser.add_argument(
        "-s",
        "--start",
        action="store",
        dest="start_date",
        default="first",
        help='start date for attestation window in either IS0 8601 format (e.g., "2008-09-03T20:56:35"), or keyworkd "first"/"none"',
    )
    parser.add_argument(
        "-e",
        "--end",
        action="store",
        dest="end_date",
        default="last",
        help='end date for attestation window in IS0 8601 format (e.g., "2008-09-03T21:56:35"), or keyworkd "last"',
    )

    args = parser.parse_args()

    rmcb = config.get("registrar", "durable_attestation_import", fallback="")
    rmc = record.get_record_mgt_class(rmcb)
    if not rmc:
        return

    rmc = rmc("registrar")

    if args.end_date == "last":
        end_date = rmc.end_of_times
    else:
        end_date = int(datetime.fromisoformat(args.end_date).strftime("%s"))

    if args.start_date == "first":
        start_date = rmc.start_of_times
    elif args.start_date == "none":
        start_date = end_date - 1
    else:
        start_date = int(datetime.fromisoformat(args.start_date).strftime("%s"))

    if end_date != rmc.end_of_times or start_date != rmc.end_of_times - 1:
        logger.info(
            "=> Selected date range for attestation records is: start %d (%s) and end %d (%s)",
            start_date,
            datetime.fromtimestamp(start_date).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            end_date,
            datetime.fromtimestamp(end_date).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        )
    else:
        logger.info("=> Will only extract the very last attestation record found on the persistent store")

    if args.agent_uuid.lower() == "all":
        logger.info("=> Getting a list of agents registered on the persistent store")
        agent_list = rmc.agent_list_retrieval()
    else:
        logger.info("=> Focusing on the agent %s on the persistent store.", args.agent_uuid)
        agent_list = [args.agent_uuid]

    for agent_uuid in agent_list:
        logger.info("===> Getting all existing registration records for agent %s...", agent_uuid)

        ak_list = rmc.build_key_list(agent_uuid, "registrar")

        if not ak_list:
            logger.error("Unable to assemble a list of AKs for the agent agent %s", agent_uuid)
            return

        logger.info("===> Getting all existing attestation records for agent %s ...", agent_uuid)
        attestation_record_list = rmc.record_read(agent_uuid, start_date, end_date, "verifier")

        logger.info("=====> Verifing the state of agent %s over time...", agent_uuid)

        p_tpm_ts = 0
        c_tpm_ts = 0
        d_tpm_ts = 0

        agentAttestState = None
        for attestation_record in attestation_record_list:
            agent = attestation_record["agent"]
            json_response = attestation_record["json_response"]
            ima_policy = attestation_record["ima_policy"]

            logger.info(
                "----------- Attesting data (quote and logs from %s, captured by verifier %s (%s:%s)",
                agent_uuid,
                agent["verifier_id"],
                agent["verifier_ip"],
                agent["verifier_port"],
            )

            if not agentAttestState:
                agentAttestState = cloud_verifier_common.get_AgentAttestStates().get_by_agent_id(agent["agent_id"])

            if "tpm_clockinfo" in agent:
                if "clock" in agent["tpm_clockinfo"]:
                    p_tpm_ts = agent["tpm_clockinfo"]["clock"]

            failure = cloud_verifier_common.process_quote_response(
                agent, ima_policy, json_response["results"], agentAttestState
            )

            if "tpm_clockinfo" in agent:
                if "clock" in agent["tpm_clockinfo"]:
                    c_tpm_ts = agent["tpm_clockinfo"]["clock"]

            if p_tpm_ts and c_tpm_ts:
                d_tpm_ts = c_tpm_ts - p_tpm_ts

            quote_failed = False
            if failure:
                if failure.events:
                    quote_failed = True

            if quote_failed:
                f_e_id = "NA"
                f_e_ctx = "NA"
                if failure.highest_severity_event:
                    f_e_id = failure.highest_severity_event.event_id
                    f_e_ctx = failure.highest_severity_event.context

                    logger.info(
                        '---------- Agent %s was NOT in "attested" state at %s (TPM delta: %s): %s %s',
                        agent_uuid,
                        attestation_record["verifier" + "_timestamp"],
                        d_tpm_ts,
                        f_e_id,
                        f_e_ctx,
                    )
                    return
            else:
                logger.info(
                    '---------- Agent %s was in "attested" state at %s (TPM delta: %s)',
                    agent_uuid,
                    attestation_record["verifier" + "_timestamp"],
                    d_tpm_ts,
                )
