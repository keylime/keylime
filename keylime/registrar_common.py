import base64
import http.server
import ipaddress
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import cast

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound

from keylime import api_version as keylime_api_version
from keylime import cert_utils, config, crypto, json, keylime_logging, web_util
from keylime.common import validators
from keylime.da import record
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.registrar_db import RegistrarMain
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import tpm

logger = keylime_logging.init_logging("registrar")


try:
    engine = DBEngineManager().make_engine("registrar")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine: %s", err)
    sys.exit(1)

try:
    rmc = record.get_record_mgt_class(config.get("registrar", "durable_attestation_import", fallback=""))
    if rmc:
        rmc = rmc("registrar")
except record.RecordManagementException as rme:
    logger.error("Error initializing Durable Attestation: %s", rme)
    sys.exit(1)


class ProtectedHandler(BaseHTTPRequestHandler, SessionManager):
    def do_HEAD(self):
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def do_PATCH(self):
        """PATCH not supported"""
        web_util.echo_json_response(self, 405, "PATCH not supported")

    def do_GET(self):
        """This method handles the GET requests to retrieve status on agents from the Registrar Server.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.
        """
        session = SessionManager().make_session(engine)
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "uri not supported")
            logger.warning("GET returning 400 response. uri not supported: %s", self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            # If the agent ID is not valid (wrong set of characters),
            # just do nothing.
            if not validators.valid_agent_id(agent_id):
                web_util.echo_json_response(self, 400, "agent_id not not valid")
                logger.error("GET received an invalid agent ID: %s", agent_id)
                return

            agent = None
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                return

            if agent is None:
                web_util.echo_json_response(self, 404, f"agent {agent_id} not found")
                logger.warning("GET returning 404 response. agent %s not found.", agent_id)
                return

            if not bool(agent.active):
                web_util.echo_json_response(self, 404, f"agent {agent_id} not yet active")
                logger.warning("GET returning 404 response. agent %s not yet active.", agent_id)
                return

            response = {
                "aik_tpm": agent.aik_tpm,
                "ek_tpm": agent.ek_tpm,
                "ekcert": agent.ekcert,
                "mtls_cert": agent.mtls_cert,
                "ip": agent.ip,
                "port": agent.port,
                "regcount": agent.regcount,
            }

            if agent.virtual:
                response["provider_keys"] = agent.provider_keys

            web_util.echo_json_response(self, 200, "Success", response)
            logger.info("GET returning 200 response for agent_id: %s", agent_id)
        else:
            # return the available registered uuids from the DB
            json_response = session.query(RegistrarMain.agent_id).all()
            return_response = [item[0] for item in json_response]
            web_util.echo_json_response(self, 200, "Success", {"uuids": return_response})
            logger.info("GET returning 200 response for agent_id list")

        return

    def do_POST(self):
        """POST not supported"""
        web_util.echo_json_response(self, 405, "POST not supported via TLS interface")

    def do_PUT(self):
        """PUT not supported"""
        web_util.echo_json_response(self, 405, "PUT not supported via TLS interface")

    def do_DELETE(self):
        """This method handles the DELETE requests to remove agents from the Registrar Server.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        session = SessionManager().make_session(engine)
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "URI not supported")
            logger.warning("DELETE agent returning 400 response. uri not supported: %s", self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            # If the agent ID is not valid (wrong set of characters),
            # just do nothing.
            if not validators.valid_agent_id(agent_id):
                web_util.echo_json_response(self, 400, "agent_id not not valid")
                logger.error("DELETE received an invalid agent ID: %s", agent_id)
                return

            if session.query(RegistrarMain).filter_by(agent_id=agent_id).delete():
                # send response
                try:
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                web_util.echo_json_response(self, 200, "Success")
                return

            # send response
            web_util.echo_json_response(self, 404)
            return

        web_util.echo_json_response(self, 404)

    # pylint: disable=W0622
    def log_message(self, format, *args):
        return


class UnprotectedHandler(BaseHTTPRequestHandler, SessionManager):
    def do_HEAD(self):
        """HEAD not supported"""
        web_util.echo_json_response(self, 405, "HEAD not supported")

    def do_PATCH(self):
        """PATCH not supported"""
        web_util.echo_json_response(self, 405, "PATCH not supported")

    def do_GET(self):
        """This method handles the GET requests to the unprotected side of the Registrar Server

        Currently the only supported path is /versions which shows the supported API versions
        """
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /version/ interface")
            return

        if "version" not in rest_params:
            web_util.echo_json_response(self, 400, "URI not supported")
            logger.warning("GET agent returning 400 response. URI not supported: %s", self.path)
            return

        version_info = {
            "current_version": keylime_api_version.current_version(),
            "supported_versions": keylime_api_version.all_versions(),
        }

        web_util.echo_json_response(self, 200, "Success", version_info)

    def do_POST(self):
        """This method handles the POST requests to add agents to the Registrar Server.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's
        will return errors. POST requests require an an agent_id identifying the agent to add, and json
        block sent in the body with 2 entries: ek and aik.
        """
        session = SessionManager().make_session(engine)
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "uri not supported")
            logger.warning("POST agent returning 400 response. uri not supported: %s", self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            web_util.echo_json_response(self, 400, "agent id not found in uri")
            logger.warning("POST agent returning 400 response. agent id not found in uri %s", self.path)
            return

        # If the agent ID is not valid (wrong set of characters), just
        # do nothing.
        if not validators.valid_agent_id(agent_id):
            web_util.echo_json_response(self, 400, "agent id not valid")
            logger.error("POST received an invalid agent ID: %s", agent_id)
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                web_util.echo_json_response(self, 400, "Expected non zero content length")
                logger.warning("POST for %s returning 400 response. Expected non zero content length.", agent_id)
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            ekcert = json_body["ekcert"]
            aik_tpm = json_body["aik_tpm"]

            initialize_tpm = tpm()

            if ekcert is None or ekcert == "emulator":
                logger.warning("Agent %s did not submit an ekcert", agent_id)
                ek_tpm = json_body["ek_tpm"]
            else:
                if "ek_tpm" in json_body:
                    # This would mean the agent submitted both a non-None ekcert, *and*
                    #  an ek_tpm... We can deal with it by just ignoring the ek_tpm they sent
                    logger.warning("Overriding ek_tpm for agent %s from ekcert", agent_id)
                # If there's an EKCert, we just overwrite their ek_tpm
                # Note, we don't validate the EKCert here, other than the implicit
                #  "is it a valid x509 cert" check. So it's still untrusted.
                # This will be validated by the tenant.
                cert = cert_utils.x509_der_cert(base64.b64decode(ekcert))
                pubkey = cert.public_key()
                assert isinstance(pubkey, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))
                ek_tpm = base64.b64encode(tpm2_objects.ek_low_tpm2b_public_from_pubkey(pubkey)).decode()

            aik_attrs = tpm2_objects.get_tpm2b_public_object_attributes(
                base64.b64decode(aik_tpm),
            )
            if aik_attrs != tpm2_objects.AK_EXPECTED_ATTRS:
                web_util.echo_json_response(self, 400, "Invalid AK attributes")
                logger.warning(
                    "Agent %s submitted AIK with invalid attributes! %s (provided) != %s (expected)",
                    agent_id,
                    tpm2_objects.object_attributes_description(aik_attrs),
                    tpm2_objects.object_attributes_description(tpm2_objects.AK_EXPECTED_ATTRS),
                )
                return

            # try to encrypt the AIK
            aik_enc = initialize_tpm.encryptAIK(
                agent_id,
                base64.b64decode(ek_tpm),
                base64.b64decode(aik_tpm),
            )
            if aik_enc is not None:
                (blob, key) = aik_enc
            else:
                logger.warning("Agent %s failed encrypting AIK", agent_id)
                web_util.echo_json_response(self, 400, "Error: failed encrypting AK")
                return

            # special behavior if we've registered this uuid before
            regcount = 1
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except NoResultFound:
                agent = None
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            if agent is not None:

                # keep track of how many ek-ekcerts have registered on this uuid
                regcount = agent.regcount
                if agent.ek_tpm != ek_tpm or agent.ekcert != ekcert:
                    logger.warning("WARNING: Overwriting previous registration for this UUID with new ek-ekcert pair!")
                    regcount += 1

                # force overwrite
                logger.info("Overwriting previous registration for this UUID.")
                try:
                    session.query(RegistrarMain).filter_by(agent_id=agent_id).delete()
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                    raise
            # Check for ip and port
            contact_ip = json_body.get("ip", None)
            contact_port = json_body.get("port", None)

            # Validate ip and port
            if contact_ip is not None:
                try:
                    # Use parser from the standard library instead of implementing our own
                    ipaddress.ip_address(contact_ip)
                except ValueError:
                    logger.warning("Contact ip for agent %s is not a valid ip got: %s.", agent_id, contact_ip)
                    contact_ip = None
            if contact_port is not None:
                try:
                    contact_port = int(contact_port)
                    if contact_port < 1 or contact_port > 65535:
                        logger.warning(
                            "Contact port for agent %s is not a number between 1 and got: %s.", agent_id, contact_port
                        )
                        contact_port = None
                except ValueError:
                    logger.warning("Contact port for agent %s is not a valid number got: %s.", agent_id, contact_port)
                    contact_port = None

            # Check for mTLS cert
            mtls_cert = json_body.get("mtls_cert", None)
            if mtls_cert is None or mtls_cert == "disabled":
                logger.warning("Agent %s did not send a mTLS certificate. Most operations will not work!", agent_id)

            # Add values to database
            d = {}
            d["agent_id"] = agent_id
            d["ek_tpm"] = ek_tpm
            d["aik_tpm"] = aik_tpm
            d["ekcert"] = ekcert
            d["ip"] = contact_ip
            d["mtls_cert"] = mtls_cert
            d["port"] = contact_port
            d["virtual"] = int(ekcert == "virtual")
            d["active"] = int(False)
            d["key"] = key
            d["provider_keys"] = {}
            d["regcount"] = regcount

            try:
                session.add(RegistrarMain(**d))
                session.commit()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            if rmc:
                try:
                    rmc.record_create(d, None, None)

                except Exception as e:
                    logger.error("Durable Attestation Error: %s", e)
                    raise

            response = {
                "blob": blob,
            }
            web_util.echo_json_response(self, 200, "Success", response)

            logger.info("POST returning key blob for agent_id: %s", agent_id)
        except Exception as e:
            web_util.echo_json_response(self, 400, f"Error: {str(e)}")
            logger.warning("POST for %s returning 400 response. Error: %s", agent_id, e)
            logger.exception(e)

    def do_PUT(self):
        """This method handles the PUT requests to add agents to the Registrar Server.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's
        will return errors.
        """
        session = SessionManager().make_session(engine)
        rest_params = web_util.get_restful_params(self.path)
        if rest_params is None:
            web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if not web_util.validate_api_version(self, cast(str, rest_params["api_version"]), logger):
            return

        if "agents" not in rest_params:
            web_util.echo_json_response(self, 400, "uri not supported")
            logger.warning("PUT agent returning 400 response. uri not supported: %s", self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            web_util.echo_json_response(self, 400, "agent id not found in uri")
            logger.warning("PUT agent returning 400 response. agent id not found in uri %s", self.path)
            return

        # If the agent ID is not valid (wrong set of characters), just
        # do nothing.
        if not validators.valid_agent_id(agent_id):
            web_util.echo_json_response(self, 400, "agent_id not not valid")
            logger.error("PUT received an invalid agent ID: %s", agent_id)
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                web_util.echo_json_response(self, 400, "Expected non zero content length")
                logger.warning("PUT for %s returning 400 response. Expected non zero content length.", agent_id)
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            auth_tag = json_body["auth_tag"]
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except NoResultFound as e:
                raise Exception("attempting to activate agent before requesting " f"registrar for {agent_id}") from e
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            ex_mac = crypto.do_hmac(agent.key.encode(), agent_id)
            if ex_mac == auth_tag:
                try:
                    session.query(RegistrarMain).filter(RegistrarMain.agent_id == agent_id).update(
                        {"active": int(True)}
                    )
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)
                    raise
            else:
                raise Exception(f"Auth tag {auth_tag} does not match expected value {ex_mac}")

            web_util.echo_json_response(self, 200, "Success")
            logger.info("PUT activated: %s", agent_id)
        except Exception as e:
            web_util.echo_json_response(self, 400, f"Error: {str(e)}")
            logger.warning("PUT for %s returning 400 response. Error: %s", agent_id, e)
            logger.exception(e)
            return

    def do_DELETE(self):
        """DELETE not supported"""
        web_util.echo_json_response(self, 405, "DELETE not supported")

    # pylint: disable=W0622
    def log_message(self, format, *args):
        return


# consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn


class RegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    def __init__(self, server_address, RequestHandlerClass):
        """Constructor overridden to provide ability to read file"""
        http.server.HTTPServer.__init__(self, server_address, RequestHandlerClass)

    def shutdown(self):
        http.server.HTTPServer.shutdown(self)


def start(host: str, tlsport: int, port: int) -> None:
    """Main method of the Registrar Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    # set a conservative general umask
    os.umask(0o077)

    RegistrarMain.metadata.create_all(engine, checkfirst=True)
    session = SessionManager().make_session(engine)
    try:
        count = session.query(RegistrarMain.agent_id).count()
        if count > 0:
            logger.info("Loaded %d public keys from database", count)
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)

    # Set up the protected registrar server
    protected_server = RegistrarServer((host, tlsport), ProtectedHandler)
    context = web_util.init_mtls("registrar", logger=logger)
    if context is not None:
        protected_server.socket = context.wrap_socket(protected_server.socket, server_side=True)
    thread_protected_server = threading.Thread(target=protected_server.serve_forever)

    # Set up the unprotected registrar server
    unprotected_server = RegistrarServer((host, port), UnprotectedHandler)
    thread_unprotected_server = threading.Thread(target=unprotected_server.serve_forever)

    logger.info("Starting Cloud Registrar Server on ports %s and %s (TLS) use <Ctrl-C> to stop", port, tlsport)
    keylime_api_version.log_api_versions(logger)
    thread_protected_server.start()
    thread_unprotected_server.start()

    def signal_handler(signum, frame):
        del signum, frame
        logger.info("Shutting down Registrar Server...")
        protected_server.shutdown()
        unprotected_server.shutdown()
        sys.exit(0)

    # Catch these signals.  Note that a SIGKILL cannot be caught, so
    # killing this process with "kill -9" may result in improper shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    thread_protected_server.join()
    thread_unprotected_server.join()
