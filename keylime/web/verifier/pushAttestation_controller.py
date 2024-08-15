import sys, time, json
from typing import Any, Dict

from keylime.web.base import Controller
from keylime import web_util
from keylime.tpm import tpm_util
from keylime import (
    keylime_logging,
    config
)

from keylime.models.verifier import Attestation

from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAttestations, VerifierAllowlist, VerifierMbpolicy
from keylime.agentstates import AgentAttestState, AgentAttestStates
from keylime.attestationstatus import AttestationStatusEnum

logger = keylime_logging.init_logging("verifier")

#GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

try:
    engine = DBEngineManager().make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1) 

def get_session() -> Session:
    return SessionManager().make_session(engine)

class PushAttestation(Controller):
    # GET /v2[.:minor]/agents/
    def index(self, **params):
        results = Attestation.all_ids()

        self.respond(200, "Sucess", {"uuids": results})
    
    # GET /v2[.:minor]/agents/:agent_id/attestations
    def show(self, agent_id, **params):
        last_attestation = Attestation.get_last(agent_id=agent_id)

        if not last_attestation:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        self.respond(200, "Success", last_attestation.render())

    # POST /v2[.:minor]/agents/:agent_id/attestations
    def create(self, agent_id, **params):

        #get agent from verifiermain
        session = get_session()
        agent = session.query(VerfierMain).filter(VerifierAttestations.agent_id == agent_id).one_or_none()
        
        # get last attestation entry for the agent
        last_attestation = Attestation.get_last(agent_id = agent_id)

        current_timestamp = int(time.time())

        # wait_time is the time interval between attestations 
        wait_time = last_attestation.quote_received + config.getint("verifier","quote_interval")
        
        if not agent:
            self.respond(404)
            return
        
        if current_timestamp < wait_time:
                retry_after = wait_time - current_timestamp
                self.action_handler.set_header("Retry-After", retry_after)
                self.respond(429)
                return
        
        if last_attestation.status == AttestationStatusEnum.FAILED:
            self.respond(503)
            return
        
        new_attestation = Attestation.create(agent_id)

        # Compare new_attestation.nonce_created against last_attestation.quote_receivedz

        new_attestation.commit_changes()
        self.respond(200, "Success", {"nonce":new_attestation.nonce, 
                                     "accept_hash_algs": agent.accept_tpm_hash_algs,
                                     "accept_enc_algs": agent.accept_tpm_encryption_algs,
                                     "accept_sign_algs": agent.accept_tpm_signing_algs 
                                     })
        
        # TODO (for Jean): Add a field called something like "starting_ima_offset" in the response here so that the agent knows
        # what ima events to send

    def update(self, agent_id, **params):
        last_attestation = Attestation.get_last(agent_id = agent_id)
        #last_attestation = Attestation.get_one(agent_id = agent_id, status = "RECEIVED")
        current_timestamp = int(time.time())

        # TODO: Replace with calls to VerifierAgent.get(...) and IMAPolicy.get(...)
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()
        allowlist = session.query(VerifierAllowlist).filter(VerifierAllowlist.id == agent.ima_policy_id).one_or_none()
        mbpolicies = session.query(VerifierMbpolicy).filter(VerifierMbpolicy.id == agent.mb_policy_id).one_or_none()

        if not last_attestation:
            self.respond(404)
            return
        
        if last_attestation.status != AttestationStatusEnum.WAITING:
            self.respond(503)
            return
        
        if last_attestation.nonce_expires < current_timestamp:
            self.respond(400, "too many request")
            return
        
        last_attestation.update({"agent_id": agent_id, **params}, agent)

        # last_attestation will contain errors if the JSON request is malformed/invalid (e.g., if an unrecognised hash algorithm is provided)
        # but not if the quote verification fails (including if the quote cannot be verified as authentic, if the IMA/MB logs cannot be verified as
        # authentic, or if the logs do not meet policy)
        if not last_attestation.changes_valid:
            msgs = []
            for field, errors in last_attestation.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return
        
        # TODO add last_successful_attestation to verifiermain
        
        session.add(agent)
        session.commit()
        last_attestation.commit_changes()
        self.respond(200, "Success")

        # Verify attestation after response is sent, so that the agent does not need to wait for the verification to complete
        # Ideally, in the future, we would want to create a pool of verification worker processes (separate from the web server workers) which will call this method whenever a new verification task is added to a queue
        last_attestation.verify_quote({"agent_id": agent_id, **params}, allowlist.ima_policy, mbpolicies.mb_policy, agent)



        
        

