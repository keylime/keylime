import sys

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from keylime import keylime_logging
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
from keylime.models.verifier import AuthSession
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")

# GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

try:
    engine = make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1)


def get_session() -> Session:
    return SessionManager().make_session(engine)


class SessionController(Controller):
    # GET /v3[.:minor]/agents/:agent_id/session/:token
    def show(self, agent_id, token, **_params):
        AuthSession.delete_stale(agent_id)

        agent = AuthSession.get(agent_id, token)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        if not agent.active:  # type: ignore[attr-defined]
            self.respond(404, f"Agent with ID '{agent_id}' has not been activated")
            return

        self.respond(200, "Success", agent.render())

    # POST /v3[.:minor]/agents/:agent_id/session
    def create(self, agent_id, **params):
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        if not agent:
            self.respond(404, "here")
            return

        auth_session = AuthSession.create(agent, params)

        if auth_session.errors:
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        AuthSession.delete_stale(agent_id)

        auth_session.commit_changes()
        self.respond(200, "Success", auth_session.render())

    def update(self, agent_id, token, **params):
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        auth_session = AuthSession.get(agent_id=agent_id, token=token)

        if not auth_session:
            self.respond(404)
            return

        auth_session.receive_pop(agent, params)  # type: ignore[attr-defined]

        if auth_session.errors:  # type: ignore[attr-defined]
            # Log errors internally for debugging
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            logger.error("Authentication failed for agent %s: %s", agent_id, msgs)

            auth_session.delete()
            # Per spec: return 200 with no error details (not 401)
            self.respond(200, "Authentication failed")
            return

        # AuthSession.delete_stale(agent_id)

        auth_session.commit_changes()
        self.respond(200, "Succeses", auth_session.render())
