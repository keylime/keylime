import asyncio
import functools
import os
import signal
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
from typing import Any, Dict, Optional, cast

import tornado.httpserver
import tornado.ioloop
import tornado.netutil
import tornado.process
import tornado.web
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.exc import NoResultFound

from keylime import api_version as keylime_api_version
from keylime import (
    cloud_verifier_common,
    config,
    json,
    keylime_logging,
    revocation_notifier,
    tornado_requests,
    web_util,
)
from keylime.agentstates import AgentAttestState, AgentAttestStates
from keylime.common import retry, states, validators
from keylime.da import record
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist
from keylime.elchecking import policies
from keylime.failure import MAX_SEVERITY_LABEL, Component, Event, Failure, set_severity_config
from keylime.ima import ima

logger = keylime_logging.init_logging("verifier")

GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

set_severity_config(config.getlist("verifier", "severity_labels"), config.getlist("verifier", "severity_policy"))

try:
    engine = DBEngineManager().make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1)

try:
    rmc = record.get_record_mgt_class(config.get("registrar", "durable_attestation_import", fallback=""))
    if rmc:
        rmc = rmc("verifier")
except record.RecordManagementException as rme:
    logger.error("Error initializing Durable Attestation: %s", rme)
    sys.exit(1)


def get_session() -> Session:
    return SessionManager().make_session(engine)


def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()


# The "exclude_db" dict values are removed from the response before adding the dict to the DB
# This is because we want these values to remain ephemeral and not stored in the database.
exclude_db: Dict[str, Any] = {
    "registrar_data": "",
    "nonce": "",
    "b64_encrypted_V": "",
    "provide_V": True,
    "num_retries": 0,
    "pending_event": None,
    # the following 3 items are updated to VerifierDB only when the AgentState is stored
    "boottime": "",
    "ima_pcrs": [],
    "pcr10": "",
    "next_ima_ml_entry": 0,
    "learned_ima_keyrings": {},
    "ssl_context": None,
}


def _from_db_obj(agent_db_obj: VerfierMain) -> Dict[str, str]:
    fields = [
        "agent_id",
        "v",
        "ip",
        "port",
        "operational_state",
        "public_key",
        "tpm_policy",
        "meta_data",
        "mb_refstate",
        "ima_sign_verification_keys",
        "revocation_key",
        "accept_tpm_hash_algs",
        "accept_tpm_encryption_algs",
        "accept_tpm_signing_algs",
        "hash_alg",
        "enc_alg",
        "sign_alg",
        "boottime",
        "ima_pcrs",
        "pcr10",
        "next_ima_ml_entry",
        "learned_ima_keyrings",
        "supported_version",
        "mtls_cert",
        "ak_tpm",
        "attestation_count",
        "last_received_quote",
        "tpm_clockinfo",
    ]
    agent_dict = {}
    for field in fields:
        agent_dict[field] = getattr(agent_db_obj, field, None)

    # add default fields that are ephemeral
    for key, val in exclude_db.items():
        agent_dict[key] = val

    return agent_dict


def verifier_read_policy_from_cache(stored_agent: VerfierMain) -> str:
    if stored_agent.agent_id not in GLOBAL_POLICY_CACHE:
        GLOBAL_POLICY_CACHE[stored_agent.agent_id] = {}

    if stored_agent.ima_policy.checksum not in GLOBAL_POLICY_CACHE[stored_agent.agent_id]:
        if GLOBAL_POLICY_CACHE[stored_agent.agent_id]:
            # Perform a cleanup of the contents, IMA policy checksum changed
            GLOBAL_POLICY_CACHE[stored_agent.agent_id] = {}

        logger.debug(
            "IMA policy with checksum %s, used by agent %s is not present on policy cache on this verifier, performing SQLAlchemy load",
            stored_agent.ima_policy.checksum,
            stored_agent.agent_id,
        )
        # Actually contacts the database and load the (large) ima_policy column for "allowlists" table
        GLOBAL_POLICY_CACHE[stored_agent.agent_id][
            stored_agent.ima_policy.checksum
        ] = stored_agent.ima_policy.ima_policy

    return GLOBAL_POLICY_CACHE[stored_agent.agent_id][stored_agent.ima_policy.checksum]


def verifier_db_delete_agent(session: Session, agent_id: str) -> None:
    get_AgentAttestStates().delete_by_agent_id(agent_id)
    session.query(VerfierMain).filter_by(agent_id=agent_id).delete()
    session.query(VerifierAllowlist).filter_by(name=agent_id).delete()
    session.commit()


def store_attestation_state(agentAttestState: AgentAttestState) -> None:
    # Only store if IMA log was evaluated
    if agentAttestState.get_ima_pcrs():
        agent_id = agentAttestState.agent_id
        session = get_session()
        try:
            update_agent = session.query(VerfierMain).get(agentAttestState.get_agent_id())
            update_agent.boottime = agentAttestState.get_boottime()
            update_agent.next_ima_ml_entry = agentAttestState.get_next_ima_ml_entry()
            ima_pcrs_dict = agentAttestState.get_ima_pcrs()
            update_agent.ima_pcrs = list(ima_pcrs_dict.keys())
            for pcr_num, value in ima_pcrs_dict.items():
                setattr(update_agent, f"pcr{pcr_num}", value)
            update_agent.learned_ima_keyrings = agentAttestState.get_ima_keyrings().to_json()
            try:
                session.add(update_agent)
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error on storing attestation state for agent %s: %s", agent_id, e)
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error on storing attestation state for agent %s: %s", agent_id, e)


class BaseHandler(tornado.web.RequestHandler):
    def prepare(self) -> None:  # pylint: disable=W0235
        super().prepare()

    def write_error(self, status_code: int, **kwargs) -> None:

        self.set_header("Content-Type", "text/json")
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            self.finish(
                json.dumps(
                    {
                        "code": status_code,
                        "status": self._reason,
                        "traceback": lines,
                        "results": {},
                    }
                )
            )
        else:
            self.finish(
                json.dumps(
                    {
                        "code": status_code,
                        "status": self._reason,
                        "results": {},
                    }
                )
            )

    def data_received(self, chunk):
        raise NotImplementedError()


class MainHandler(tornado.web.RequestHandler):
    def head(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def get(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def delete(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def post(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def put(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

    def data_received(self, chunk):
        raise NotImplementedError()


class VersionHandler(BaseHandler):
    def head(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def get(self):
        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented")
            return

        if "version" not in rest_params:
            web_util.echo_json_response(self, 400, "URI not supported")
            logger.warning("GET returning 400 response. URI not supported: %s", self.request.path)
            return

        version_info = {
            "current_version": keylime_api_version.current_version(),
            "supported_versions": keylime_api_version.all_versions(),
        }

        web_util.echo_json_response(self, 200, "Success", version_info)

    def delete(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def post(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def put(self):
        web_util.echo_json_response(self, 405, "Not Implemented: Use GET interface instead")

    def data_received(self, chunk):
        raise NotImplementedError()


class AgentsHandler(BaseHandler):
    def head(self):
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def get(self):
        """This method handles the GET requests to retrieve status on agents from the Cloud Verifier.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. Agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.  If the agent_id
        was not found, it either completed successfully, or failed.  If found, the agent_id is still polling
        to contact the Cloud Agent.
        """
        session = get_session()
        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "uri not supported")
            logger.warning("GET returning 400 response. uri not supported: %s", self.request.path)
            return

        agent_id = rest_params["agents"]

        if (agent_id is not None) and (agent_id != ""):
            # If the agent ID is not valid (wrong set of characters),
            # just do nothing.
            if not validators.valid_agent_id(agent_id):
                web_util.echo_json_response(self, 400, "agent_id not not valid")
                logger.error("GET received an invalid agent ID: %s", agent_id)
                return

            agent = None
            try:
                agent = (
                    session.query(VerfierMain)
                    .options(
                        joinedload(VerfierMain.ima_policy).load_only(
                            VerifierAllowlist.checksum, VerifierAllowlist.generator
                        )
                    )
                    .filter_by(agent_id=agent_id)
                    .one_or_none()
                )
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

            if agent is not None:
                response = cloud_verifier_common.process_get_status(agent)
                web_util.echo_json_response(self, 200, "Success", response)
            else:
                web_util.echo_json_response(self, 404, "agent id not found")
        else:
            json_response = None
            if "bulk" in rest_params:
                agent_list = None

                if ("verifier" in rest_params) and (rest_params["verifier"] != ""):
                    agent_list = (
                        session.query(VerfierMain)
                        .options(
                            joinedload(VerfierMain.ima_policy).load_only(
                                VerifierAllowlist.checksum, VerifierAllowlist.generator
                            )
                        )
                        .filter_by(verifier_id=rest_params["verifier"])
                        .all()
                    )
                else:
                    agent_list = (
                        session.query(VerfierMain)
                        .options(
                            joinedload(VerfierMain.ima_policy).load_only(
                                VerifierAllowlist.checksum, VerifierAllowlist.generator
                            )
                        )
                        .all()
                    )

                json_response = {}
                for agent in agent_list:
                    json_response[agent.agent_id] = cloud_verifier_common.process_get_status(agent)

                web_util.echo_json_response(self, 200, "Success", json_response)
            else:
                if ("verifier" in rest_params) and (rest_params["verifier"] != ""):
                    json_response = (
                        session.query(VerfierMain.agent_id).filter_by(verifier_id=rest_params["verifier"]).all()
                    )
                else:
                    json_response = session.query(VerfierMain.agent_id).all()

                web_util.echo_json_response(self, 200, "Success", {"uuids": json_response})

            logger.info("GET returning 200 response for agent_id list")

    def delete(self):
        """This method handles the DELETE requests to remove agents from the Cloud Verifier.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        session = get_session()
        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "uri not supported")
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            web_util.echo_json_response(self, 400, "uri not supported")
            logger.warning("DELETE returning 400 response. uri not supported: %s", self.request.path)
            return

        # If the agent ID is not valid (wrong set of characters), just
        # do nothing.
        if not validators.valid_agent_id(agent_id):
            web_util.echo_json_response(self, 400, "agent_id not not valid")
            logger.error("DELETE received an invalid agent ID: %s", agent_id)
            return

        agent = None
        try:
            agent = session.query(VerfierMain).filter_by(agent_id=agent_id).first()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

        if agent is None:
            web_util.echo_json_response(self, 404, "agent id not found")
            logger.info("DELETE returning 404 response. agent id: %s not found.", agent_id)
            return

        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        if verifier_id != agent.verifier_id:
            web_util.echo_json_response(self, 404, "agent id associated to this verifier")
            logger.info("DELETE returning 404 response. agent id: %s not associated to this verifer.", agent_id)
            return

        # Cleanup the cache when the agent is deleted. Do it early.
        if agent_id in GLOBAL_POLICY_CACHE:
            del GLOBAL_POLICY_CACHE[agent_id]
            logger.debug(
                "Cleaned up policy cache from all entries used by agent %s",
                agent_id,
            )

        op_state = agent.operational_state
        if op_state in (states.SAVED, states.FAILED, states.TERMINATED, states.TENANT_FAILED, states.INVALID_QUOTE):
            try:
                verifier_db_delete_agent(session, agent_id)
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
            web_util.echo_json_response(self, 200, "Success")
            logger.info("DELETE returning 200 response for agent id: %s", agent_id)
        else:
            try:
                update_agent = session.query(VerfierMain).get(agent_id)
                update_agent.operational_state = states.TERMINATED
                try:
                    session.add(update_agent)
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                session.commit()
                web_util.echo_json_response(self, 202, "Accepted")
                logger.info("DELETE returning 202 response for agent id: %s", agent_id)
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

    def post(self):
        """This method handles the POST requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's will return errors.
        agents requests require a json block sent in the body
        """
        session = get_session()
        # TODO: exception handling needs fixing
        # Maybe handle exceptions with if/else if/else blocks ... simple and avoids nesting
        try:  # pylint: disable=too-many-nested-blocks
            rest_params = web_util.get_restful_params(self.request.uri)
            if rest_params is None:
                web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
                return

            if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
                return

            if "agents" not in rest_params:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported: %s", self.request.path)
                return

            agent_id = rest_params["agents"]

            if agent_id is not None:
                # If the agent ID is not valid (wrong set of
                # characters), just do nothing.
                if not validators.valid_agent_id(agent_id):
                    web_util.echo_json_response(self, 400, "agent_id not not valid")
                    logger.error("POST received an invalid agent ID: %s", agent_id)
                    return

                content_length = len(self.request.body)
                if content_length == 0:
                    web_util.echo_json_response(self, 400, "Expected non zero content length")
                    logger.warning("POST returning 400 response. Expected non zero content length.")
                else:
                    json_body = json.loads(self.request.body)
                    agent_data = {}
                    agent_data["v"] = json_body["v"]
                    agent_data["ip"] = json_body["cloudagent_ip"]
                    agent_data["port"] = int(json_body["cloudagent_port"])
                    agent_data["operational_state"] = states.START
                    agent_data["public_key"] = ""
                    agent_data["tpm_policy"] = json_body["tpm_policy"]
                    agent_data["meta_data"] = json_body["metadata"]
                    agent_data["mb_refstate"] = json_body["mb_refstate"]
                    agent_data["ima_sign_verification_keys"] = json_body["ima_sign_verification_keys"]
                    agent_data["revocation_key"] = json_body["revocation_key"]
                    agent_data["accept_tpm_hash_algs"] = json_body["accept_tpm_hash_algs"]
                    agent_data["accept_tpm_encryption_algs"] = json_body["accept_tpm_encryption_algs"]
                    agent_data["accept_tpm_signing_algs"] = json_body["accept_tpm_signing_algs"]
                    agent_data["supported_version"] = json_body["supported_version"]
                    agent_data["ak_tpm"] = json_body["ak_tpm"]
                    agent_data["mtls_cert"] = json_body.get("mtls_cert", None)
                    agent_data["hash_alg"] = ""
                    agent_data["enc_alg"] = ""
                    agent_data["sign_alg"] = ""
                    agent_data["agent_id"] = agent_id
                    agent_data["boottime"] = 0
                    agent_data["ima_pcrs"] = []
                    agent_data["pcr10"] = None
                    agent_data["next_ima_ml_entry"] = 0
                    agent_data["learned_ima_keyrings"] = {}
                    agent_data["verifier_id"] = config.get(
                        "verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID
                    )
                    agent_data["verifier_ip"] = config.get("verifier", "ip")
                    agent_data["verifier_port"] = config.get("verifier", "port")
                    agent_data["attestation_count"] = 0
                    agent_data["last_received_quote"] = 0

                    agent_mtls_cert_enabled = config.getboolean("verifier", "enable_agent_mtls", fallback=False)

                    # TODO: Always error for v1.0 version after initial upgrade
                    if all(
                        [
                            agent_data["supported_version"] != "1.0",
                            agent_mtls_cert_enabled,
                            (agent_data["mtls_cert"] is None or agent_data["mtls_cert"] == "disabled"),
                        ]
                    ):
                        web_util.echo_json_response(self, 400, "mTLS certificate for agent is required!")
                        return

                    # Handle allowlists/IMA policies

                    # How each pair of inputs should be handled:
                    # - No name, no policy: use default empty policy using agent UUID as name
                    # - Name, no policy: fetch existing policy from DB
                    # - No name, policy: store policy using agent UUID as name
                    # - Name, policy: store policy using name

                    ima_policy_name = json_body.get("ima_policy_name")
                    ima_policy_bundle = json.loads(json_body.get("ima_policy_bundle", "{}"))

                    # Get policy from payload if present
                    if ima_policy_bundle:
                        try:
                            allowlist = ima.unbundle_ima_policy(
                                ima_policy_bundle,
                                verify=config.getboolean("verifier", "require_allow_list_signatures", fallback=False),
                            )
                            ima_policy = json.dumps(ima.process_ima_policy(allowlist, ima_policy_bundle["excllist"]))
                        except ima.SignatureValidationError as e:
                            web_util.echo_json_response(self, e.code, e.message)
                            logger.warning(e.message)
                            return
                    else:
                        ima_policy = json_body.get("allowlist", None)

                    if ima_policy_name:
                        try:
                            ima_policy_stored = (
                                session.query(VerifierAllowlist).filter_by(name=ima_policy_name).one_or_none()
                            )
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                            raise

                        # Prevent overwriting existing IMA policies with name provided in request
                        if ima_policy and ima_policy_stored:
                            web_util.echo_json_response(
                                self,
                                409,
                                f"Allowlist with name {ima_policy_name} already exists. Please use a different name or delete the allowlist from the verifier.",
                            )
                            logger.warning("Allowlist with name %s already exists", ima_policy_name)
                            return

                        # Return an error code if the named allowlist does not exist in the database
                        if not ima_policy and not ima_policy_stored:
                            web_util.echo_json_response(
                                self, 404, f"Could not find IMA policy with name {ima_policy_name}!"
                            )
                            logger.warning("Could not find IMA policy with name %s", ima_policy_name)
                            return

                    # Prevent overwriting existing agents with UUID provided in request
                    try:
                        new_agent_count = session.query(VerfierMain).filter_by(agent_id=agent_id).count()
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                        raise e

                    if new_agent_count > 0:
                        web_util.echo_json_response(
                            self,
                            409,
                            f"Agent of uuid {agent_id} already exists. Please use delete or update.",
                        )
                        logger.warning("Agent of uuid %s already exists", agent_id)
                        return

                    # Write IMA policy to database if needed
                    if not ima_policy_name and not ima_policy:
                        logger.info("Allowlist data not provided with request! Using default empty allowlist.")
                        ima_policy = json.dumps(ima.process_ima_policy(ima.EMPTY_ALLOWLIST, []))

                    if ima_policy:
                        err_msg = cloud_verifier_common.validate_ima_policy_data(ima_policy)
                        if err_msg:
                            web_util.echo_json_response(self, 400, err_msg)
                            logger.warning(err_msg)
                            return

                        if not ima_policy_name:
                            ima_policy_name = agent_id

                        ima_policy_db_format = ima.ima_policy_db_contents(ima_policy_name, ima_policy)

                        try:
                            ima_policy_stored = (
                                session.query(VerifierAllowlist).filter_by(name=ima_policy_name).one_or_none()
                            )
                        except SQLAlchemyError as e:
                            logger.error(
                                "SQLAlchemy Error while retrieving stored ima policy for agent ID %s: %s", agent_id, e
                            )
                            raise
                        try:
                            if ima_policy_stored is None:
                                ima_policy_stored = VerifierAllowlist(**ima_policy_db_format)
                                session.add(ima_policy_stored)
                                session.commit()
                        except SQLAlchemyError as e:
                            logger.error("SQLAlchemy Error while updating ima policy for agent ID %s: %s", agent_id, e)
                            raise

                    # Write the agent to the database, attaching associated stored policy
                    try:
                        session.add(VerfierMain(**agent_data, ima_policy=ima_policy_stored))
                        session.commit()
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                        raise e

                    # add default fields that are ephemeral
                    for key, val in exclude_db.items():
                        agent_data[key] = val

                    # Prepare SSLContext for mTLS connections
                    agent_data["ssl_context"] = None
                    if agent_mtls_cert_enabled:
                        agent_data["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent_data["mtls_cert"], logger=logger
                        )

                    if agent_data["ssl_context"] is None:
                        logger.warning("Connecting to agent without mTLS: %s", agent_id)

                    asyncio.ensure_future(process_agent(agent_data, states.GET_QUOTE))
                    web_util.echo_json_response(self, 200, "Success")
                    logger.info("POST returning 200 response for adding agent id: %s", agent_id)
            else:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
        except Exception as e:
            web_util.echo_json_response(self, 400, f"Exception error: {str(e)}")
            logger.warning("POST returning 400 response. Exception error: %s", e)
            logger.exception(e)

    def put(self):
        """This method handles the PUT requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's will return errors.
        agents requests require a json block sent in the body
        """
        session = get_session()
        try:
            rest_params = web_util.get_restful_params(self.request.uri)
            if rest_params is None:
                web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
                return

            if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
                return

            if "agents" not in rest_params:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported: %s", self.request.path)
                return

            agent_id = rest_params["agents"]

            if agent_id is None:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")

            # If the agent ID is not valid (wrong set of characters),
            # just do nothing.
            if not validators.valid_agent_id(agent_id):
                web_util.echo_json_response(self, 400, "agent_id not not valid")
                logger.error("PUT received an invalid agent ID: %s", agent_id)
                return

            try:
                verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
                db_agent = session.query(VerfierMain).filter_by(agent_id=agent_id, verifier_id=verifier_id).one()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                raise e

            if db_agent is None:
                web_util.echo_json_response(self, 404, "agent id not found")
                logger.info("PUT returning 404 response. agent id: %s not found.", agent_id)
                return

            if "reactivate" in rest_params:
                agent = cast(Dict[str, Any], _from_db_obj(db_agent))

                if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                    agent["ssl_context"] = web_util.generate_agent_tls_context(
                        "verifier", agent["mtls_cert"], logger=logger
                    )
                if agent["ssl_context"] is None:
                    logger.warning("Connecting to agent without mTLS: %s", agent_id)

                agent["operational_state"] = states.START
                asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
                web_util.echo_json_response(self, 200, "Success")
                logger.info("PUT returning 200 response for agent id: %s", agent_id)
            elif "stop" in rest_params:
                # do stuff for terminate
                logger.debug("Stopping polling on %s", agent_id)
                try:
                    session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update(
                        {"operational_state": states.TENANT_FAILED}
                    )
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)

                web_util.echo_json_response(self, 200, "Success")
                logger.info("PUT returning 200 response for agent id: %s", agent_id)
            else:
                web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")

        except Exception as e:
            web_util.echo_json_response(self, 400, f"Exception error: {str(e)}")
            logger.warning("PUT returning 400 response. Exception error: %s", e)
            logger.exception(e)

    def data_received(self, chunk):
        raise NotImplementedError()


class AllowlistHandler(BaseHandler):
    def head(self):
        web_util.echo_json_response(self, 400, "Allowlist handler: HEAD Not Implemented")

    def get(self):
        """Get an allowlist

        GET /allowlists/{name}
        """

        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None or "allowlists" not in rest_params:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        allowlist_name = rest_params["allowlists"]
        if allowlist_name is None:
            web_util.echo_json_response(self, 400, "Invalid URL")
            logger.warning("GET returning 400 response: %s", self.request.path)
            return

        session = get_session()
        try:
            allowlist = session.query(VerifierAllowlist).filter_by(name=allowlist_name).one()
        except NoResultFound:
            web_util.echo_json_response(self, 404, f"Allowlist {allowlist_name} not found")
            return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            web_util.echo_json_response(self, 500, "Failed to get allowlist")
            raise

        response = {}
        for field in ("name", "tpm_policy", "ima_policy"):
            response[field] = getattr(allowlist, field, None)
        web_util.echo_json_response(self, 200, "Success", response)

    def delete(self):
        """Delete an allowlist

        DELETE /allowlists/{name}
        """

        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None or "allowlists" not in rest_params:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        allowlist_name = rest_params["allowlists"]
        if allowlist_name is None:
            web_util.echo_json_response(self, 400, "Invalid URL")
            logger.warning("DELETE returning 400 response: %s", self.request.path)
            return

        session = get_session()
        try:
            ima_policy = session.query(VerifierAllowlist).filter_by(name=allowlist_name).one()
        except NoResultFound:
            web_util.echo_json_response(self, 404, f"Allowlist {allowlist_name} not found")
            return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            web_util.echo_json_response(self, 500, "Failed to get allowlist")
            raise

        try:
            agent = session.query(VerfierMain).filter_by(ima_policy_id=ima_policy.id).one_or_none()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise
        if agent is not None:
            web_util.echo_json_response(
                self,
                409,
                f"Can't delete allowlist as it's currently in use by agent {agent.agent_id}",
            )
            return

        try:
            session.query(VerifierAllowlist).filter_by(name=allowlist_name).delete()
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            session.close()
            web_util.echo_json_response(self, 500, f"Database error: {e}")
            raise

        # NOTE(kaifeng) 204 Can not have response body, but current helper
        # doesn't support this case.
        self.set_status(204)
        self.set_header("Content-Type", "application/json")
        self.finish()
        logger.info("DELETE returning 204 response for allowlist: %s", allowlist_name)

    def post(self):
        """Create an allowlist

        POST /allowlists/{name}
        body: {"tpm_policy": {..} ...
        """

        rest_params = web_util.get_restful_params(self.request.uri)
        if rest_params is None or "allowlists" not in rest_params:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        allowlist_name = rest_params["allowlists"]
        if allowlist_name is None:
            web_util.echo_json_response(self, 400, "Invalid URL")
            return

        content_length = len(self.request.body)
        if content_length == 0:
            web_util.echo_json_response(self, 400, "Expected non zero content length")
            logger.warning("POST returning 400 response. Expected non zero content length.")
            return

        ima_policy = "{}"

        json_body = json.loads(self.request.body)

        ima_policy_bundle = json.loads(json_body.get("ima_policy_bundle"))
        if ima_policy_bundle:
            try:
                allowlist = ima.unbundle_ima_policy(
                    ima_policy_bundle,
                    verify=config.getboolean("verifier", "require_allow_list_signatures", fallback=False),
                )
                ima_policy = json.dumps(ima.process_ima_policy(allowlist, ima_policy_bundle["excllist"]))
            except ima.SignatureValidationError as e:
                web_util.echo_json_response(self, e.code, e.message)
                logger.warning(e.message)
                return

        tpm_policy = json_body.get("tpm_policy")

        ima_policy_db_format = ima.ima_policy_db_contents(allowlist_name, ima_policy, tpm_policy)

        session = get_session()
        # don't allow overwritting
        try:
            ima_policy_count = session.query(VerifierAllowlist).filter_by(name=allowlist_name).count()
            if ima_policy_count > 0:
                web_util.echo_json_response(self, 409, f"Allowlist with name {allowlist_name} already exists")
                logger.warning("Allowlist with name %s already exists", allowlist_name)
                return
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        try:
            # Add the agent and data
            session.add(VerifierAllowlist(**ima_policy_db_format))
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error: %s", e)
            raise

        web_util.echo_json_response(self, 201)
        logger.info("POST returning 201")

    def put(self):
        web_util.echo_json_response(self, 400, "Allowlist handler: PUT Not Implemented")

    def data_received(self, chunk):
        raise NotImplementedError()


async def invoke_get_quote(
    agent: Dict[str, Any], ima_policy: VerifierAllowlist, need_pubkey: bool, timeout: float = 60.0
) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])
    if agent is None:
        raise Exception("agent deleted while being processed")
    params = cloud_verifier_common.prepare_get_quote(agent)

    partial_req = "1"
    if need_pubkey:
        partial_req = "0"

    # TODO: remove special handling after initial upgrade
    if agent["ssl_context"]:
        res = tornado_requests.request(
            "GET",
            f"https://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/quotes/integrity"
            f"?nonce={params['nonce']}&mask={params['mask']}"
            f"&partial={partial_req}&ima_ml_entry={params['ima_ml_entry']}",
            context=agent["ssl_context"],
            timeout=timeout,
        )
    else:
        res = tornado_requests.request(
            "GET",
            f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/quotes/integrity"
            f"?nonce={params['nonce']}&mask={params['mask']}"
            f"&partial={partial_req}&ima_ml_entry={params['ima_ml_entry']}",
            timeout=timeout,
        )
    response = await res

    if response.status_code != 200:
        # this is a connection error, retry get quote
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(process_agent(agent, states.GET_QUOTE_RETRY))
        else:
            # catastrophic error, do not continue
            logger.critical(
                "Unexpected Get Quote response error for cloud agent %s, Error: %s",
                agent["agent_id"],
                response.status_code,
            )
            failure.add_event("no_quote", "Unexpected Get Quote reponse from agent", False)
            asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
    else:
        try:
            json_response = json.loads(response.body)

            # validate the cloud agent response
            if "provide_V" not in agent:
                agent["provide_V"] = True
            agentAttestState = get_AgentAttestStates().get_by_agent_id(agent["agent_id"])

            if rmc:
                rmc.record_create(agent, json_response, ima_policy)

            failure = cloud_verifier_common.process_quote_response(
                agent, ima_policy, json_response["results"], agentAttestState
            )
            if not failure:
                if agent["provide_V"]:
                    asyncio.ensure_future(process_agent(agent, states.PROVIDE_V))
                else:
                    asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
            else:
                asyncio.ensure_future(process_agent(agent, states.INVALID_QUOTE, failure))

            # store the attestation state
            store_attestation_state(agentAttestState)

        except Exception as e:
            logger.exception(e)
            failure.add_event(
                "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
            )
            asyncio.ensure_future(process_agent(agent, states.FAILED, failure))


async def invoke_provide_v(agent: Optional[Dict[str, Any]], timeout=60.0) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])
    if agent is None:
        raise Exception("Agent deleted while being processed")
    try:
        if agent["pending_event"] is not None:
            agent["pending_event"] = None
    except KeyError:
        pass
    v_json_message = cloud_verifier_common.prepare_v(agent)

    # TODO: remove special handling after initial upgrade
    if agent["ssl_context"]:
        res = tornado_requests.request(
            "POST",
            f"https://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/keys/vkey",
            data=v_json_message,
            context=agent["ssl_context"],
            timeout=timeout,
        )
    else:
        res = tornado_requests.request(
            "POST",
            f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/keys/vkey",
            data=v_json_message,
            timeout=timeout,
        )

    response = await res

    if response.status_code != 200:
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(process_agent(agent, states.PROVIDE_V_RETRY))
        else:
            # catastrophic error, do not continue
            logger.critical(
                "Unexpected Provide V response error for cloud agent %s, Error: %s",
                agent["agent_id"],
                response.status_code,
            )
            failure.add_event("no_v", {"message": "Unexpected provide V response", "data": response.status_code}, False)
            asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
    else:
        asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))


async def invoke_notify_error(agent: Optional[Dict[str, Any]], tosend: Dict[str, Any], timeout: float = 60.0) -> None:
    if agent is None:
        logger.warning("Agent deleted while being processed")
        return
    kwargs = {
        "data": tosend,
    }
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "POST",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/notifications/revocation",
        **kwargs,
        timeout=timeout,
    )
    response = await res

    if response is None:
        logger.warning(
            "Empty Notify Revocation response from cloud agent %s",
            agent["agent_id"],
        )
    elif response.status_code != 200:
        logger.warning(
            "Unexpected Notify Revocation response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )


async def notify_error(
    agent: Dict[str, Any], msgtype: str = "revocation", event: Optional[Event] = None, timeout: float = 60.0
) -> None:
    notifiers = revocation_notifier.get_notifiers()
    if len(notifiers) == 0:
        return

    tosend = cloud_verifier_common.prepare_error(agent, msgtype, event)
    if "webhook" in notifiers:
        revocation_notifier.notify_webhook(tosend)
    if "zeromq" in notifiers:
        revocation_notifier.notify(tosend)
    if "agent" in notifiers:
        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        session = get_session()
        agents = session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
        futures = []
        loop = asyncio.get_event_loop()
        # Notify all agents asynchronously through a thread pool
        with ThreadPoolExecutor() as pool:
            for agent_db_obj in agents:
                if agent_db_obj.agent_id != agent["agent_id"]:
                    agent = _from_db_obj(agent_db_obj)
                    if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                        agent["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent["mtls_cert"], logger=logger
                        )
                func = functools.partial(invoke_notify_error, agent, tosend, timeout=timeout)
                futures.append(await loop.run_in_executor(pool, func))
            # Wait for all tasks complete in 60 seconds
            try:
                for f in asyncio.as_completed(futures, timeout=60):
                    await f
            except asyncio.TimeoutError as e:
                logger.error("Timeout during notifying error to agents: %s", e)


async def process_agent(
    agent: Dict[str, Any], new_operational_state, failure: Failure = Failure(Component.INTERNAL, ["verifier"])
):
    # Convert to dict if the agent arg is a db object
    if not isinstance(agent, dict):
        agent = _from_db_obj(agent)

    session = get_session()
    try:  # pylint: disable=R1702
        main_agent_operational_state = agent["operational_state"]
        stored_agent = None
        try:
            stored_agent = (
                session.query(VerfierMain)
                .options(joinedload(VerfierMain.ima_policy).load_only(VerifierAllowlist.checksum))
                .filter_by(agent_id=str(agent["agent_id"]))
                .first()
            )
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent["agent_id"], e)

        # if the stored agent could not be recovered from the database, stop polling
        if not stored_agent:
            logger.warning("Unable to retrieve agent %s from database. Stopping polling", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            return

        # if the user did terminated this agent
        if stored_agent.operational_state == states.TERMINATED:
            logger.warning("Agent %s terminated by user.", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            verifier_db_delete_agent(session, agent["agent_id"])
            return

        # if the user tells us to stop polling because the tenant quote check failed
        if stored_agent.operational_state == states.TENANT_FAILED:
            logger.warning("Agent %s has failed tenant quote. Stopping polling", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            return

        # Get request timeout from configuration file
        timeout = config.getfloat("verifier", "request_timeout", fallback=60.0)

        # If failed during processing, log regardless and drop it on the floor
        # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).
        if new_operational_state in (states.FAILED, states.INVALID_QUOTE):
            assert failure, "States FAILED and INVALID QUOTE should only be reached with a failure message"
            assert failure.highest_severity

            if agent.get("severity_level") is None or agent["severity_level"] < failure.highest_severity.severity:
                assert failure.highest_severity_event
                agent["severity_level"] = failure.highest_severity.severity
                agent["last_event_id"] = failure.highest_severity_event.event_id
                agent["operational_state"] = new_operational_state

                # issue notification for invalid quotes
                if new_operational_state == states.INVALID_QUOTE:
                    await notify_error(agent, event=failure.highest_severity_event, timeout=timeout)

                # When the failure is irrecoverable we stop polling the agent
                if not failure.recoverable or failure.highest_severity == MAX_SEVERITY_LABEL:
                    if agent["pending_event"] is not None:
                        tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
                    for key in exclude_db:
                        if key in agent:
                            del agent[key]
                    session.query(VerfierMain).filter_by(agent_id=agent["agent_id"]).update(agent)
                    session.commit()

        # propagate all state, but remove none DB keys first (using exclude_db)
        try:
            agent_db = dict(agent)
            for key in exclude_db:
                if key in agent_db:
                    del agent_db[key]

            session.query(VerfierMain).filter_by(agent_id=agent_db["agent_id"]).update(agent_db)
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent["agent_id"], e)

        # Load agent's IMA policy
        ima_policy = verifier_read_policy_from_cache(stored_agent)

        # If agent was in a failed state we check if we either stop polling
        # or just add it again to the event loop
        if new_operational_state in [states.FAILED, states.INVALID_QUOTE]:
            if not failure.recoverable or failure.highest_severity == MAX_SEVERITY_LABEL:
                logger.warning("Agent %s failed, stopping polling", agent["agent_id"])
                return

            await invoke_get_quote(agent, ima_policy, False, timeout=timeout)
            return

        # if new, get a quote
        if main_agent_operational_state == states.START and new_operational_state == states.GET_QUOTE:
            agent["num_retries"] = 0
            agent["operational_state"] = states.GET_QUOTE
            await invoke_get_quote(agent, ima_policy, True, timeout=timeout)
            return

        if main_agent_operational_state == states.GET_QUOTE and new_operational_state == states.PROVIDE_V:
            agent["num_retries"] = 0
            agent["operational_state"] = states.PROVIDE_V
            await invoke_provide_v(agent)
            return

        if (
            main_agent_operational_state in (states.PROVIDE_V, states.GET_QUOTE)
            and new_operational_state == states.GET_QUOTE
        ):
            agent["num_retries"] = 0
            interval = config.getfloat("verifier", "quote_interval")
            agent["operational_state"] = states.GET_QUOTE
            if interval == 0:
                await invoke_get_quote(agent, ima_policy, False, timeout=timeout)
            else:
                logger.debug(
                    "Setting up callback to check agent ID %s again in %f seconds", agent["agent_id"], interval
                )

                # set up a call back to check again
                async def cb():
                    await invoke_get_quote(agent, ima_policy, False, timeout=timeout)

                pending = tornado.ioloop.IOLoop.current().call_later(interval, cb)
                agent["pending_event"] = pending
            return

        maxr = config.getint("verifier", "max_retries")
        interval = config.getfloat("verifier", "retry_interval")
        exponential_backoff = config.getboolean("verifier", "exponential_backoff")

        if main_agent_operational_state == states.GET_QUOTE and new_operational_state == states.GET_QUOTE_RETRY:
            if agent["num_retries"] >= maxr:
                logger.warning(
                    "Agent %s was not reachable for quote in %d tries, setting state to FAILED", agent["agent_id"], maxr
                )
                failure.add_event("not_reachable", "agent was not reachable from verifier", False)
                if agent["attestation_count"] > 0:  # only notify on previously good agents
                    await notify_error(
                        agent, msgtype="comm_error", event=failure.highest_severity_event, timeout=timeout
                    )
                else:
                    logger.debug("Communication error for new agent. No notification will be sent")
                await process_agent(agent, states.FAILED, failure)
            else:
                agent["operational_state"] = states.GET_QUOTE

                async def cb_quote_retry():
                    await invoke_get_quote(agent, ima_policy, True, timeout=timeout)

                agent["num_retries"] += 1
                next_retry = retry.retry_time(exponential_backoff, interval, agent["num_retries"], logger)
                logger.info(
                    "Connection to %s refused after %d/%d tries, trying again in %f seconds",
                    agent["ip"],
                    agent["num_retries"],
                    maxr,
                    next_retry,
                )
                tornado.ioloop.IOLoop.current().call_later(next_retry, cb_quote_retry)
            return

        if main_agent_operational_state == states.PROVIDE_V and new_operational_state == states.PROVIDE_V_RETRY:
            if agent["num_retries"] >= maxr:
                logger.warning(
                    "Agent %s was not reachable to provide v in %d tries, setting state to FAILED",
                    agent["agent_id"],
                    maxr,
                )
                failure.add_event("not_reachable_v", "agent was not reachable to provide V", False)
                await notify_error(agent, msgtype="comm_error", event=failure.highest_severity_event, timeout=timeout)
                await process_agent(agent, states.FAILED, failure)
            else:
                agent["operational_state"] = states.PROVIDE_V

                async def cb_vprov_retry():
                    await invoke_provide_v(agent)

                agent["num_retries"] += 1
                next_retry = retry.retry_time(exponential_backoff, interval, agent["num_retries"], logger)
                logger.info(
                    "Connection to %s refused after %d/%d tries, trying again in %f seconds",
                    agent["ip"],
                    agent["num_retries"],
                    maxr,
                    next_retry,
                )
                tornado.ioloop.IOLoop.current().call_later(next_retry, cb_vprov_retry)
            return
        raise Exception("nothing should ever fall out of this!")

    except Exception as e:
        logger.error("Polling thread error for agent ID %s: %s", agent["agent_id"], e)
        logger.exception(e)
        failure.add_event(
            "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
        )
        await process_agent(agent, states.FAILED, failure)


async def activate_agents(verifier_id: str, verifier_ip: str, verifier_port: str) -> None:
    session = get_session()
    aas = get_AgentAttestStates()
    try:
        agents = session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
        for agent in agents:
            agent.verifier_ip = verifier_ip
            agent.verifier_host = verifier_port
            agent_run = _from_db_obj(agent)
            if agent_run["mtls_cert"] and agent_run["mtls_cert"] != "disabled":
                agent_run["ssl_context"] = web_util.generate_agent_tls_context(
                    "verifier", agent_run["mtls_cert"], logger=logger
                )

            if agent.operational_state == states.START:
                asyncio.ensure_future(process_agent(agent_run, states.GET_QUOTE))
            if agent.boottime:
                ima_pcrs_dict = {}
                for pcr_num in agent.ima_pcrs:
                    ima_pcrs_dict[pcr_num] = getattr(agent, f"pcr{pcr_num}")
                aas.add(
                    agent.agent_id, agent.boottime, ima_pcrs_dict, agent.next_ima_ml_entry, agent.learned_ima_keyrings
                )
        session.commit()
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)


def main() -> None:
    """Main method of the Cloud Verifier Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    config.check_version("verifier", logger=logger)

    verifier_port = config.get("verifier", "port")
    verifier_host = config.get("verifier", "ip")
    verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)

    # Check if measured boot was configured correctly
    mb_policy_name = config.get("verifier", "measured_boot_policy_name", fallback="accept-all")
    if mb_policy_name and policies.get_policy(mb_policy_name) is None:
        logger.error('Measured boot policy "%s" could not be found!', mb_policy_name)
        raise Exception(f'Measued boot policy "{mb_policy_name}" could not be found!')

    # allow tornado's max upload size to be configurable
    max_upload_size = None
    if config.has_option("verifier", "max_upload_size"):
        max_upload_size = int(config.get("verifier", "max_upload_size"))

    # set a conservative general umask
    os.umask(0o077)

    VerfierMain.metadata.create_all(engine, checkfirst=True)
    session = get_session()
    try:
        query_all = session.query(VerfierMain).all()
        for row in query_all:
            if row.operational_state in states.APPROVED_REACTIVATE_STATES:
                row.operational_state = states.START
        session.commit()
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)

    num = session.query(VerfierMain.agent_id).count()
    if num > 0:
        agent_ids = session.query(VerfierMain.agent_id).all()
        logger.info("Agent ids in db loaded from file: %s", agent_ids)

    logger.info("Starting Cloud Verifier (tornado) on port %s, use <Ctrl-C> to stop", verifier_port)

    # print out API versions we support
    keylime_api_version.log_api_versions(logger)

    # Get the server TLS context
    ssl_ctx = web_util.init_mtls("verifier", logger=logger)

    app = tornado.web.Application(
        [
            (r"/v?[0-9]+(?:\.[0-9]+)?/agents/.*", AgentsHandler),
            (r"/v?[0-9]+(?:\.[0-9]+)?/allowlists/.*", AllowlistHandler),
            (r"/versions?", VersionHandler),
            (r".*", MainHandler),
        ]
    )

    sockets = tornado.netutil.bind_sockets(int(verifier_port), address=verifier_host)

    def server_process(task_id: int) -> None:
        logger.info("Starting server of process %s", task_id)
        assert isinstance(engine, Engine)
        engine.dispose()
        server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_ctx, max_buffer_size=max_upload_size)
        server.add_sockets(sockets)

        def server_sig_handler(*_):
            logger.info("Shutting down server %s..", task_id)
            # Stop server to not accept new incoming connections
            server.stop()

            # Wait for all connections to be closed and then stop ioloop
            async def stop():
                await server.close_all_connections()
                tornado.ioloop.IOLoop.current().stop()

            asyncio.ensure_future(stop())

        # Attach signal handler to ioloop.
        # Do not use signal.signal(..) for that because it does not work!
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, server_sig_handler)
        loop.add_signal_handler(signal.SIGTERM, server_sig_handler)

        server.start()
        if task_id == 0:
            # Reactivate agents
            asyncio.ensure_future(activate_agents(verifier_id, verifier_host, verifier_port))
        tornado.ioloop.IOLoop.current().start()
        logger.debug("Server %s stopped.", task_id)
        sys.exit(0)

    processes = []

    run_revocation_notifier = "zeromq" in revocation_notifier.get_notifiers()

    def sig_handler(*_):
        if run_revocation_notifier:
            revocation_notifier.stop_broker()
        for p in processes:
            p.join()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    if run_revocation_notifier:
        logger.info(
            "Starting service for revocation notifications on port %s",
            config.getint("verifier", "zmq_port", section="revocations"),
        )
        revocation_notifier.start_broker()

    num_workers = config.getint("verifier", "num_workers")
    if num_workers <= 0:
        num_workers = tornado.process.cpu_count()
    for task_id in range(0, num_workers):
        process = Process(target=server_process, args=(task_id,))
        process.start()
        processes.append(process)
