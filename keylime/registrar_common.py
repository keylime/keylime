'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import os
import threading
import sys
import signal
import time
import hashlib
import http.server
try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

from keylime import registrar_client
from keylime import crypto
from keylime import cloud_verifier_common
from keylime.tpm import tpm_obj
from keylime import common
from keylime import keylime_logging

# Database imports
from keylime.db.registrar_db import RegistrarMain
from keylime.db.keylime_db import SessionManager
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL

logger = keylime_logging.init_logging('registrar-common')
# setup config
config = common.get_config()

drivername = config.get('registrar', 'drivername')


if drivername == 'sqlite':
    database = "%s/%s" % (common.WORK_DIR,
                          config.get('registrar', 'database'))
    url = URL(
        drivername=drivername,
        username='',
        password='',
        host='',
        database=(database)
    )
else:
    url = URL(
        drivername=drivername,
        username=config.get('registrar', 'username'),
        password=config.get('registrar', 'password'),
        host=config.get('registrar', 'host'),
        database=config.get('registrar', 'database')
    )

try:
    engine = create_engine(url,
                           connect_args={'check_same_thread': False},)
except SQLAlchemyError as e:
    logger.error(f'Error creating SQL engine: {e}')
    exit(1)


class ProtectedHandler(BaseHTTPRequestHandler, SessionManager):

    def do_HEAD(self):
        """HEAD not supported"""
        common.echo_json_response(self, 405, "HEAD not supported")
        return

    def do_PATCH(self):
        """PATCH not supported"""
        common.echo_json_response(self, 405, "PATCH not supported")
        return

    def do_GET(self):
        """This method handles the GET requests to retrieve status on agents from the Registrar Server.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.
        """
        session = SessionManager().make_session(engine)
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'GET returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            try:
                agent = session.query(RegistrarMain).filter_by(agent_id=agent_id).first()
            except SQLAlchemyError as e:
                logger.error(f'SQLAlchemy Error: {e}')

            if agent is None:
                common.echo_json_response(self, 404, "agent_id not found")
                logger.warning(
                    'GET returning 404 response. agent_id ' + agent_id + ' not found.')
                return

            if not agent.active:
                common.echo_json_response(self, 404, "agent_id not yet active")
                logger.warning(
                    'GET returning 404 response. agent_id ' + agent_id + ' not yet active.')
                return

            response = {
                'aik': agent.aik,
                'ek': agent.ek,
                'ekcert': agent.ekcert,
                'regcount': agent.regcount,
            }

            if agent.virtual:
                response['provider_keys'] = agent.provider_keys

            common.echo_json_response(self, 200, "Success", response)
            logger.info('GET returning 200 response for agent_id:' + agent_id)
        else:
            # return the available registered uuids from the DB
            json_response = session.query(RegistrarMain.agent_id).all()
            return_response = [item[0] for item in json_response]
            common.echo_json_response(self, 200, "Success", {
                                      'uuids': return_response})
            logger.info('GET returning 200 response for agent_id list')

        return

    def do_POST(self):
        """POST not supported"""
        common.echo_json_response(
            self, 405, "POST not supported via TLS interface")
        return

    def do_PUT(self):
        """PUT not supported"""
        common.echo_json_response(
            self, 405, "PUT not supported via TLS interface")
        return

    def do_DELETE(self):
        """This method handles the DELETE requests to remove agents from the Registrar Server.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        session = SessionManager().make_session(engine)
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'DELETE agent returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            if session.query(RegistrarMain).filter_by(agent_id=agent_id).delete():
                # send response
                try:
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error(f'SQLAlchemy Error: {e}')
                common.echo_json_response(self, 200, "Success")
                return
            else:
                # send response
                common.echo_json_response(self, 404)
                return
        else:
            common.echo_json_response(self, 404)
            return

    def log_message(self, logformat, *args):
        return


class UnprotectedHandler(BaseHTTPRequestHandler, SessionManager):

    def do_HEAD(self):
        """HEAD not supported"""
        common.echo_json_response(self, 405, "HEAD not supported")
        return

    def do_PATCH(self):
        """PATCH not supported"""
        common.echo_json_response(self, 405, "PATCH not supported")
        return

    def do_GET(self):
        """GET not supported"""
        common.echo_json_response(self, 405, "GET not supported")
        return

    def do_POST(self):
        """This method handles the POST requests to add agents to the Registrar Server.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's
        will return errors. POST requests require an an agent_id identifying the agent to add, and json
        block sent in the body with 2 entries: ek and aik.
        """
        session = SessionManager().make_session(engine)
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'POST agent returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            common.echo_json_response(self, 400, "agent id not found in uri")
            logger.warning(
                'POST agent returning 400 response. agent id not found in uri ' + self.path)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                common.echo_json_response(
                    self, 400, "Expected non zero content length")
                logger.warning(
                    'POST for ' + agent_id + ' returning 400 response. Expected non zero content length.')
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            ek = json_body['ek']
            ek_tpm = json_body['ek_tpm']
            ekcert = json_body['ekcert']
            aik = json_body['aik']
            aik_name = json_body['aik_name']
            tpm_version = int(json_body['tpm_version'])

            # try to encrypt the AIK
            tpm = tpm_obj.getTPM(need_hw_tpm=False, tpm_version=tpm_version)
            (blob, key) = tpm.encryptAIK(agent_id, aik, ek, ek_tpm, aik_name)
            # special behavior if we've registered this uuid before
            regcount = 1
            try:
                agent = session.query(RegistrarMain).filter_by(
                    agent_id=agent_id).first()
            except SQLAlchemyError as e:
                logger.error(f'SQLAlchemy Error: {e}')

            if agent is not None:

                # keep track of how many ek-ekcerts have registered on this uuid
                regcount = agent.regcount
                if agent.ek != ek or agent.ekcert != ekcert:
                    logger.warning(
                        'WARNING: Overwriting previous registration for this UUID with new ek-ekcert pair!')
                    regcount += 1

                # force overwrite
                logger.info('Overwriting previous registration for this UUID.')
                try:
                    session.query(RegistrarMain).filter_by(
                        agent_id=agent_id).delete()
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error(f'SQLAlchemy Error: {e}')

            # Add values to database
            d = {}
            d['agent_id'] = agent_id
            d['ek'] = ek
            d['aik'] = aik
            d['ekcert'] = ekcert
            d['virtual'] = int(ekcert == 'virtual')
            d['active'] = int(False)
            d['key'] = key
            d['provider_keys'] = {}
            d['regcount'] = regcount

            try:
                session.add(RegistrarMain(**d))
                session.commit()
            except SQLAlchemyError as e:
                logger.error(f'SQLAlchemy Error: {e}')

            response = {
                'blob': blob,
            }
            common.echo_json_response(self, 200, "Success", response)

            logger.info('POST returning key blob for agent_id: ' + agent_id)
            return
        except Exception as e:
            common.echo_json_response(self, 400, "Error: %s" % e)
            logger.warning("POST for " + agent_id +
                           " returning 400 response. Error: %s" % e)
            logger.exception(e)
            return

    def do_PUT(self):
        """This method handles the PUT requests to add agents to the Registrar Server.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's
        will return errors.
        """
        session = SessionManager().make_session(engine)
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'PUT agent returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            common.echo_json_response(self, 400, "agent id not found in uri")
            logger.warning(
                'PUT agent returning 400 response. agent id not found in uri ' + self.path)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                common.echo_json_response(
                    self, 400, "Expected non zero content length")
                logger.warning(
                    'PUT for ' + agent_id + ' returning 400 response. Expected non zero content length.')
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            if "activate" in rest_params:
                auth_tag = json_body['auth_tag']
                try:
                    agent = session.query(RegistrarMain).filter_by(
                        agent_id=agent_id).first()
                except SQLAlchemyError as e:
                    logger.error(f'SQLAlchemy Error: {e}')

                if agent is None:
                    raise Exception(
                        "attempting to activate agent before requesting registrar for %s" % agent_id)

                if agent.virtual:
                    raise Exception(
                        "attempting to activate virtual AIK using physical interface for %s" % agent_id)

                if common.STUB_TPM:
                    try:
                        session.query(RegistrarMain).filter(agent_id == agent_id).update(
                            {'active': True})
                        session.commit()
                    except SQLAlchemyError as e:
                        logger.error(f'SQLAlchemy Error: {e}')
                else:
                    ex_mac = crypto.do_hmac(agent.key, agent_id)
                    if ex_mac == auth_tag:
                        try:
                            session.query(RegistrarMain).filter(agent_id == agent_id).update(
                                {'active': True})
                            session.commit()
                        except SQLAlchemyError as e:
                            logger.error(f'SQLAlchemy Error: {e}')
                    else:
                        raise Exception(
                            "Auth tag %s does not match expected value %s" % (auth_tag, ex_mac))

                common.echo_json_response(self, 200, "Success")
                logger.info('PUT activated: ' + agent_id)
            elif "vactivate" in rest_params:
                deepquote = json_body.get('deepquote', None)
                try:
                    agent = session.query(RegistrarMain).filter_by(
                        agent_id=agent_id).first()
                except SQLAlchemyError as e:
                    logger.error(f'SQLAlchemy Error: {e}')
                if agent is None:
                    raise Exception(
                        "attempting to activate agent before requesting registrar for %s" % agent_id)

                if not agent['virtual']:
                    raise Exception(
                        "attempting to activate physical AIK using virtual interface for %s" % agent_id)

                # get an physical AIK for this host
                registrar_client.init_client_tls(config, 'registrar')
                provider_keys = registrar_client.getKeys(config.get('registrar', 'provider_registrar_ip'), config.get(
                    'registrar', 'provider_registrar_tls_port'), agent_id)
                # we already have the vaik
                tpm = tpm_obj.getTPM(
                    need_hw_tpm=False, tpm_version=agent['tpm_version'])
                if not tpm.check_deep_quote(agent_id,
                                            hashlib.sha1(
                                                agent['key']).hexdigest(),
                                            agent_id+agent['aik']+agent['ek'],
                                            deepquote,
                                            agent['aik'],
                                            provider_keys['aik']):
                    raise Exception("Deep quote invalid")
                try:
                    session.query(RegistrarMain).filter(agent_id == agent_id).update(
                        {'active': True})
                except SQLAlchemyError as e:
                    logger.error(f'SQLAlchemy Error: {e}')
                try:
                    session.query(RegistrarMain).filter(agent_id == agent_id).update(
                        {'provider_keys': provider_keys})
                except SQLAlchemyError as e:
                    logger.error(f'SQLAlchemy Error: {e}')

                common.echo_json_response(self, 200, "Success")
                logger.info('PUT activated: ' + agent_id)
            else:
                pass
        except Exception as e:
            common.echo_json_response(self, 400, "Error: %s" % e)
            logger.warning("PUT for " + agent_id +
                           " returning 400 response. Error: %s" % e)
            logger.exception(e)
            return

    def do_DELETE(self):
        """DELETE not supported"""
        common.echo_json_response(self, 405, "DELETE not supported")
        return

    def log_message(self, logformat, *args):
        return

# consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn


class ProtectedRegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    def __init__(self, server_address, RequestHandlerClass):
        """Constructor overridden to provide ability to read file"""
        http.server.HTTPServer.__init__(
            self, server_address, RequestHandlerClass)

    def shutdown(self):
        http.server.HTTPServer.shutdown(self)


class UnprotectedRegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    def __init__(self, server_address, RequestHandlerClass):
        """Constructor overridden to provide ability to read file"""
        http.server.HTTPServer.__init__(
            self, server_address, RequestHandlerClass)

    def shutdown(self):
        http.server.HTTPServer.shutdown(self)


def do_shutdown(servers):
    for server in servers:
        server.shutdown()


def start(tlsport, port):
    """Main method of the Registrar Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    threads = []
    servers = []
    serveraddr = ('', tlsport)

    os.umask(0o077)
    kl_dir = os.path.dirname(os.path.abspath(database))
    if not os.path.exists(kl_dir):
        os.makedirs(kl_dir, 0o700)
    RegistrarMain.metadata.create_all(engine, checkfirst=True)
    session = SessionManager().make_session(engine)
    try:
        count = session.query(RegistrarMain.agent_id).count()
    except SQLAlchemyError as e:
        logger.error(f'SQLAlchemy Error: {e}')
    if count > 0:
        logger.info("Loaded %d public keys from database" % count)

    server = ProtectedRegistrarServer(serveraddr, ProtectedHandler)
    context = cloud_verifier_common.init_mtls(section='registrar',
                                              generatedir='reg_ca')
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever)
    threads.append(thread)

    # start up the unprotected registrar server
    serveraddr2 = ('', port)
    server2 = UnprotectedRegistrarServer(serveraddr2, UnprotectedHandler)
    thread2 = threading.Thread(target=server2.serve_forever)
    threads.append(thread2)

    servers.append(server)
    servers.append(server2)

    logger.info(
        'Starting Cloud Registrar Server on ports %s and %s (TLS) use <Ctrl-C> to stop' % (port, tlsport))
    for thread in threads:
        thread.start()

    def signal_handler(signal, frame):
        do_shutdown(servers)
        sys.exit(0)

    # Catch these signals.  Note that a SIGKILL cannot be caught, so
    # killing this process with "kill -9" may result in improper shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # keep the main thread active, so it can process the signals and gracefully shutdown
    while True:
        if not any([thread.isAlive() for thread in threads]):
            # All threads have stopped
            break
        else:
            # Some threads are still going
            time.sleep(1)

    for thread in threads:
        thread.join()
