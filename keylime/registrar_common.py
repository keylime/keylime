'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

import threading
import sys
import base64
import configparser
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
from urllib.parse import urlparse

from keylime import registrar_client
from keylime import crypto
from keylime import cloud_verifier_common
from keylime import keylime_sqlite
from keylime import tpm_obj
from keylime import common
from keylime import keylime_logging

logger = keylime_logging.init_logging('registrar-common')

# setup config
config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

class ProtectedHandler(BaseHTTPRequestHandler):

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
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('GET returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            agent = self.server.db.get_agent(agent_id)

            if agent is None:
                common.echo_json_response(self, 404, "agent_id not found")
                logger.warning('GET returning 404 response. agent_id ' + agent_id + ' not found.')
                return

            if not agent['active']:
                common.echo_json_response(self, 404, "agent_id not yet active")
                logger.warning('GET returning 404 response. agent_id ' + agent_id + ' not yet active.')
                return

            response = {
                'aik': agent['aik'],
                'ek': agent['ek'],
                'ekcert': agent['ekcert'],
                'regcount': agent['regcount'],
            }

            if agent['virtual']:
                response['provider_keys']= agent['provider_keys']

            common.echo_json_response(self, 200, "Success", response)
            logger.info('GET returning 200 response for agent_id:' + agent_id)
        else:
            # return the available registered uuids from the DB
            json_response = self.server.db.get_agent_ids()
            common.echo_json_response(self, 200, "Success", {'uuids':json_response})
            logger.info('GET returning 200 response for agent_id list')

        return


    def do_POST(self):
        """POST not supported"""
        common.echo_json_response(self, 405, "POST not supported via TLS interface")
        return

    def do_PUT(self):
        """PUT not supported"""
        common.echo_json_response(self, 405, "PUT not supported via TLS interface")
        return

    def do_DELETE(self):
        """This method handles the DELETE requests to remove agents from the Registrar Server.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('DELETE agent returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            if self.server.db.remove_agent(agent_id):
                #send response
                common.echo_json_response(self, 200, "Success")
                return
            else:
                #send response
                common.echo_json_response(self, 404)
                return
        else:
            common.echo_json_response(self, 404)
            return
    def log_message(self, logformat, *args):
        return


class UnprotectedHandler(BaseHTTPRequestHandler):

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
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('POST agent returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            common.echo_json_response(self, 400, "agent id not found in uri")
            logger.warning('POST agent returning 400 response. agent id not found in uri ' + self.path)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                common.echo_json_response(self, 400, "Expected non zero content length")
                logger.warning('POST for ' + agent_id + ' returning 400 response. Expected non zero content length.')
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
            tpm = tpm_obj.getTPM(need_hw_tpm=False,tpm_version=tpm_version)
            (blob,key) = tpm.encryptAIK(agent_id,aik,ek,ek_tpm,aik_name)
            # special behavior if we've registered this uuid before
            regcount = 1
            agent =  self.server.db.get_agent(agent_id)

            if agent is not None:

                # keep track of how many ek-ekcerts have registered on this uuid
                regcount = agent['regcount']
                if agent['ek'] != ek or agent['ekcert'] != ekcert:
                    logger.warning('WARNING: Overwriting previous registration for this UUID with new ek-ekcert pair!')
                    regcount += 1

                # force overwrite
                logger.info('Overwriting previous registration for this UUID.')
                # self.server.db.remove_agent(agent_id)
                self.server.db.remove_agent(agent_id)
            # Add values to database
            d={}
            d['ek']=ek
            d['aik']=aik
            d['ekcert']=ekcert
            d['virtual']=int(ekcert=='virtual')
            d['active']=int(False)
            d['key']=key
            d['tpm_version']=tpm_version
            d['provider_keys']={}
            d['regcount']=regcount
            self.server.db.add_agent(agent_id, d)
            response = {
                    'blob': blob,
            }
            common.echo_json_response(self, 200, "Success", response)

            logger.info('POST returning key blob for agent_id: ' + agent_id)
            return
        except Exception as e:
            common.echo_json_response(self, 400, "Error: %s"%e)
            logger.warning("POST for " + agent_id + " returning 400 response. Error: %s"%e)
            logger.exception(e)
            return

    def do_PUT(self):
        """This method handles the PUT requests to add agents to the Registrar Server.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's
        will return errors.
        """
        rest_params = common.get_restful_params(self.path)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('PUT agent returning 400 response. uri not supported: ' + self.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            common.echo_json_response(self, 400, "agent id not found in uri")
            logger.warning('PUT agent returning 400 response. agent id not found in uri ' + self.path)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                common.echo_json_response(self, 400, "Expected non zero content length")
                logger.warning('PUT for ' + agent_id + ' returning 400 response. Expected non zero content length.')
                return

            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)

            if "activate" in rest_params:
                auth_tag=json_body['auth_tag']

                agent = self.server.db.get_agent(agent_id)
                if agent is None:
                    raise Exception("attempting to activate agent before requesting registrar for %s"%agent_id)

                if agent['virtual']:
                    raise Exception("attempting to activate virtual AIK using physical interface for %s"%agent_id)

                if common.STUB_TPM:
                    self.server.db.update_agent(agent_id, 'active',True)
                else:
                    ex_mac = crypto.do_hmac(agent['key'],agent_id)
                    if ex_mac == auth_tag:
                        self.server.db.update_agent(agent_id, 'active',True)
                    else:
                        raise Exception("Auth tag %s does not match expected value %s"%(auth_tag,ex_mac))

                common.echo_json_response(self, 200, "Success")
                logger.info('PUT activated: ' + agent_id)
            elif "vactivate" in rest_params:
                deepquote = json_body.get('deepquote',None)

                agent = self.server.db.get_agent(agent_id)
                if agent is None:
                    raise Exception("attempting to activate agent before requesting registrar for %s"%agent_id)

                if not agent['virtual']:
                    raise Exception("attempting to activate physical AIK using virtual interface for %s"%agent_id)

                # get an physical AIK for this host
                registrar_client.init_client_tls(config, 'registrar')
                provider_keys = registrar_client.getKeys(config.get('general', 'provider_registrar_ip'), config.get('general', 'provider_registrar_tls_port'), agent_id)
                # we already have the vaik
                tpm = tpm_obj.getTPM(need_hw_tpm=False,tpm_version=agent['tpm_version'])
                if not tpm.check_deep_quote(hashlib.sha1(agent['key']).hexdigest(),
                                                  agent_id+agent['aik']+agent['ek'],
                                                  deepquote,
                                                  agent['aik'],
                                                  provider_keys['aik']):
                    raise Exception("Deep quote invalid")

                self.server.db.update_agent(agent_id, 'active',True)
                self.server.db.update_agent(agent_id, 'provider_keys',provider_keys)

                common.echo_json_response(self, 200, "Success")
                logger.info('PUT activated: ' + agent_id)
            else:
                pass
        except Exception as e:
            common.echo_json_response(self, 400, "Error: %s"%e)
            logger.warning("PUT for " + agent_id + " returning 400 response. Error: %s"%e)
            logger.exception(e)
            return


    def do_DELETE(self):
        """DELETE not supported"""
        common.echo_json_response(self, 405, "DELETE not supported")
        return

    def log_message(self, logformat, *args):
        return

#consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn
class ProtectedRegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    db = None

    def __init__(self, server_address, db,RequestHandlerClass):
        """Constructor overridden to provide ability to read file"""
        self.db = db
        http.server.HTTPServer.__init__(self, server_address, RequestHandlerClass)

    def shutdown(self):
        http.server.HTTPServer.shutdown(self)

class UnprotectedRegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    db = None

    def __init__(self, server_address,db,RequestHandlerClass):
        """Constructor overridden to provide ability to read file"""
        self.db = db
        http.server.HTTPServer.__init__(self, server_address, RequestHandlerClass)

    def shutdown(self):
        http.server.HTTPServer.shutdown(self)

def init_db(dbname):
    # in the form key, SQL type
    cols_db = {
        'agent_id': 'TEXT PRIMARY_KEY',
        'key': 'TEXT',
        'aik': 'TEXT',
        'ek': 'TEXT',
        'ekcert': 'TEXT',
        'virtual': 'INT',
        'active': 'INT',
        'provider_keys': 'TEXT',
        'regcount': 'INT',
        }

    # these are the columns that contain json data and need marshalling
    json_cols_db = ['provider_keys']

    # in the form key : default value
    exclude_db = {}

    return keylime_sqlite.KeylimeDB(dbname,cols_db,json_cols_db,exclude_db)

def do_shutdown(servers):
        for server in servers:
            server.shutdown()

def start(tlsport,port,dbfile):
    """Main method of the Registrar Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    threads = []
    servers = []
    serveraddr = ('', tlsport)


    db = init_db("%s/%s"%(common.WORK_DIR,dbfile))

    count = db.count_agents()
    if count>0:
        logger.info("Loaded %d public keys from database"%count)

    server = ProtectedRegistrarServer(serveraddr, db, ProtectedHandler)
    context = cloud_verifier_common.init_mtls(section='registrar',
                                             generatedir='reg_ca')
    if context is not None:
        server.socket = context.wrap_socket (server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever)
    threads.append(thread)

    # start up the unprotected registrar server
    serveraddr2 = ('',port)
    server2 = UnprotectedRegistrarServer(serveraddr2,db,UnprotectedHandler)
    thread2 = threading.Thread(target=server2.serve_forever)
    threads.append(thread2)

    servers.append(server)
    servers.append(server2)

    logger.info('Starting Cloud Registrar Server on ports %s and %s (TLS) use <Ctrl-C> to stop'%(port,tlsport))
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
