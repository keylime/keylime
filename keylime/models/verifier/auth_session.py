import base64
import random
import secrets
import string
from datetime import timedelta
from typing import Any, Dict, Optional, Sequence

from sqlalchemy.orm import Session

from keylime import config
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
from keylime.models.base import *
from keylime.tpm.errors import (
    HashAlgorithmMismatch,
    IncorrectSignature,
    ObjectNameMismatch,
    QualifyingDataMismatch,
    SignatureAlgorithmMismatch,
)
from keylime.tpm.tpm_main import Tpm

engine = make_engine("cloud_verifier")


def get_session() -> Session:
    return SessionManager().make_session(engine)


class AuthSession(PersistableModel):
    # Explicit attribute declarations for type checkers
    active: bool
    agent_id: str
    nonce: bytes
    nonce_created_at: Any
    nonce_expires_at: Any
    hash_algorithm: str
    signing_scheme: str
    ak_attest: bytes
    ak_sign: bytes
    pop_received_at: Any
    token_expires_at: Any

    @classmethod
    def _schema(cls):
        # TODO: Uncomment
        # cls._belongs_to("agent", VerifierAgent, inverse_of="sessions", preload = False)

        cls._persist_as("sessions")
        cls._id("token", String(64))  # Updated to match migration: secrets.token_urlsafe(32) generates ~43 char tokens
        cls._field("active", Boolean)
        cls._field("agent_id", String(80))
        cls._field("nonce", Nonce)
        cls._field("nonce_created_at", Timestamp)
        cls._field("nonce_expires_at", Timestamp)
        cls._virtual("supported_hash_algorithms", List)
        cls._virtual("supported_signing_schemes", List)
        cls._field("hash_algorithm", String(10))
        cls._field("signing_scheme", String(10))
        cls._field("ak_attest", Binary)
        cls._field("ak_sign", Binary)
        cls._field("pop_received_at", Timestamp)
        cls._field("token_expires_at", Timestamp)

    @classmethod
    def authenticate_agent(cls, token: str):  # type: ignore[no-untyped-def]
        """Authenticate an agent using their session token.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            token: The session token to verify

        Returns:
            VerfierMain object if authenticated, False otherwise
        """
        # Get all active sessions and compare tokens in constant time
        # to prevent timing attacks that could leak token values
        session = get_session()
        # Filter for active sessions - SQLAlchemy converts bool fields to proper SQL WHERE clause
        all_sessions = session.query(AuthSession).filter(AuthSession.active).all()  # type: ignore[arg-type]

        auth_session = None
        for candidate in all_sessions:
            if secrets.compare_digest(str(candidate.token), str(token)):  # type: ignore[attr-defined]
                auth_session = candidate
                # No break - must check all sessions to maintain constant time

        if not auth_session:
            return False

        agent = (
            session.query(VerfierMain)
            .filter(VerfierMain.agent_id == auth_session.agent_id)  # type: ignore[attr-defined]
            .one_or_none()
        )

        return agent

    @classmethod
    def create(cls, agent: VerfierMain, data: Dict[str, Any]) -> "AuthSession":
        session = AuthSession.empty()  # type: ignore[return-value]
        session.initialise(agent.agent_id)  # type: ignore[attr-defined]
        session.receive_capabilities(data, agent)  # type: ignore[attr-defined]
        return session  # type: ignore[return-value]

    @classmethod
    def delete_stale(cls, agent_id: str) -> None:
        agent_sessions = AuthSession.all(agent_id=agent_id)

        for session in agent_sessions:
            if session.nonce_expires_at >= Timestamp.now() or session.token_expires_at >= Timestamp.now():  # type: ignore[attr-defined]
                session.delete()

    def initialise(self, agent_id: str) -> None:
        if "agent_id" not in self.values:
            self.agent_id = agent_id

        if "token" not in self.values:
            charset = string.ascii_uppercase + string.ascii_lowercase + string.digits
            self.token = "".join(random.SystemRandom().choice(charset) for _ in range(64))

        if "active" not in self.values:
            self.active = False

    def receive_capabilities(self, data: Dict[str, Any], agent: VerfierMain) -> None:
        if self.nonce:  # type: ignore[attr-defined]
            raise ValueError("AuthSession object cannot be updated as it has already received agent capabilities")

        # Set fields from capabilities reported by the agent
        self.cast_changes(data, ["supported_hash_algorithms", "supported_signing_schemes"])
        self.validate_required(["supported_hash_algorithms", "supported_signing_schemes"])

        # Generate the nonce the agent should use in the call to TPM2_Certify
        self._set_nonce()  # type: ignore[no-untyped-call]
        # Select algorithms from the list given by the agent
        self._set_algs(data, agent)  # type: ignore[no-untyped-call]

        self._set_timestamps()  # type: ignore[no-untyped-call]

    def receive_pop(self, agent: VerfierMain, data: Dict[str, Any]) -> None:
        if not agent or not agent.agent_id == self.agent_id:  # type: ignore[attr-defined]
            return

        ak_tpm = base64.b64decode(agent.ak_tpm)  # type: ignore[arg-type]
        self.cast_changes(data, ["ak_attest", "ak_sign"])

        try:
            Tpm.verify_tpm_object(
                ak_tpm,
                ak_tpm,
                self.ak_attest,  # type: ignore[attr-defined]
                self.ak_sign,  # type: ignore[attr-defined]
                qual=self.nonce,  # type: ignore[attr-defined]
                _hash_alg=self.hash_algorithm,  # type: ignore[attr-defined,arg-type]
                _sign_alg=self.signing_scheme,  # type: ignore[attr-defined,arg-type]
            )
        except QualifyingDataMismatch:
            self._add_error("ak_attest", "must include the nonce as qualifying data")
        except ObjectNameMismatch:
            self._add_error("ak_attest", "must include the AK of the agent as the certified object")
        except HashAlgorithmMismatch:
            self._add_error("ak_attest", f"must specify {self.hash_algorithm} as the hash algorithm")
        except SignatureAlgorithmMismatch:
            self._add_error("ak_attest", f"must specify {self.signing_scheme} as the signature scheme")
        except IncorrectSignature:
            self._add_error("ak_sign", "must verify against ak_attest using the agent's AK")

        session_lifetime = config.getint("verifier", "session_lifetime")
        self.token_expires_at = Timestamp.now() + timedelta(session_lifetime)
        self.active = True

    def _set_nonce(self):
        if "nonce" not in self.values:
            self.nonce = Nonce.generate(128)

    def _set_algs(self, data, agent):
        # pylint: disable=no-else-break

        supported_hash_algorithms = data.get("supported_hash_algorithms")
        supported_signing_schemes = data.get("supported_signing_schemes")

        # Set hashing algorithm that is first match from the list of hashing supported by the agent tpm
        # and the list of accpeted hashing algorithm
        for hash_alg in agent.accept_tpm_hash_algs:
            if hash_alg in supported_hash_algorithms:
                self.hash_algorithm = hash_alg
                break

        if not self.hash_algorithm:
            self._add_error(
                "supported_hash_algorithms",
                f"does not contain any accepted hashing algorithm for agent '{agent.agent_id}'",
            )

        # Set signing algorithm that is first match from the list of signing supported by the agent tpm
        # and the list of accpeted signing algorithm
        for signing_scheme in agent.accept_tpm_signing_algs:
            if signing_scheme in supported_signing_schemes:
                self.signing_scheme = signing_scheme
                break

        if not self.signing_scheme:
            self._add_error(
                "supported_signing_schemes",
                f"does not contain any accepeted signing scheme for agent '{agent.agent_id}'",
            )

    def _set_timestamps(self):
        nonce_lifetime = config.getint("verifier", "nonce_lifetime")

        if self.changes.get("nonce"):
            self.nonce_created_at = Timestamp.now()
            self.nonce_expires_at = self.nonce_created_at + timedelta(nonce_lifetime)

        if self.changes.get("ak_attest", "ak_sign"):
            self.pop_received_at = Timestamp.now()

    def render(self, only: Optional[Sequence[str]] = None) -> Dict[str, Any]:  # type: ignore[override]
        if not only:
            only = ["token", "active", "nonce", "agent_id", "token_expires_at"]

        output = super().render(only)
        return output
