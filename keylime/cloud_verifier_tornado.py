#!/usr/bin/python3
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

import configparser
import traceback
import sys
import functools
import asyncio
import requests

import tornado.ioloop
import tornado.web
from tornado import httpserver
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import url_concat

from keylime import common
from keylime import keylime_logging
from keylime import cloud_verifier_common
from keylime import revocation_notifier

logger = keylime_logging.init_logging('cloudverifier')

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

# ===============test parameter===============
provider_ip = "http://10.0.2.4:8881"
tenant_ip = "http://10.0.2.15:8881"
identity = input("Enter your identity: provider or tenant: ")
# ============================================

class BaseHandler(tornado.web.RequestHandler):

    def write_error(self, status_code, **kwargs):

        self.set_header('Content-Type', 'text/json')
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            self.finish(json.dumps({
                'code': status_code,
                'status': self._reason,
                'traceback': lines,
                'results': {},
            }))
        else:
            self.finish(json.dumps({
                'code': status_code,
                'status': self._reason,
                'results': {},
            }))

# ================ adding handler =================================
class VerifierHandler_provider(tornado.web.RequestHandler):
    """
    communicate with other verifier
    testing
    """
    def get(self, msg):
        logger.info('msaage from tenant: %s'%msg)
        URL = tenant_ip
        requests.get(url=URL+"/verifier/here_is_quote")
    pass

        
class VerifierHandler_tenant(tornado.web.RequestHandler):
    """
    communicate with other verifier
    testing
    """
    def get(self, msg):
        logger.info('msaage from provider: %s'%msg)
        # URL = provider_ip
        # requests.get(url=URL)
    pass
# ============================================================
        

class MainHandler(tornado.web.RequestHandler):
    def head(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")
    def get(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")
        logger.info("405 error")
    def delete(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")
    def post(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")
    def put(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")

class AgentsHandler(BaseHandler):
    db = None
    def initialize(self, db):
        self.db = db

    def head(self):
        """HEAD not supported"""
        common.echo_json_response(self, 405, "HEAD not supported")

    def get(self):
        """This method handles the GET requests to retrieve status on agents from the Cloud Verifier.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. Agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.  If the agent_id
        was not found, it either completed successfully, or failed.  If found, the agent_id is still polling
        to contact the Cloud Agent.
        """
        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('GET returning 400 response. uri not supported: ' + self.request.path)
            return

        agent_id = rest_params["agents"]

        if agent_id is not None:
            agent = self.db.get_agent(agent_id)
            if agent != None:
                response = cloud_verifier_common.process_get_status(agent)
                common.echo_json_response(self, 200, "Success", response)
                #logger.info('GET returning 200 response for agent_id: ' + agent_id)

            else:
                #logger.info('GET returning 404 response. agent id: ' + agent_id + ' not found.')
                common.echo_json_response(self, 404, "agent id not found")
        else:
            # return the available keys in the DB
            json_response = self.db.get_agent_ids()
            common.echo_json_response(self, 200, "Success", {'uuids':json_response})
            logger.info('GET returning 200 response for agent_id list')

    def delete(self):
        """This method handles the DELETE requests to remove agents from the Cloud Verifier.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('DELETE returning 400 response. uri not supported: ' + self.request.path)

        agent = self.db.get_agent(agent_id)

        if agent is None:
            common.echo_json_response(self, 404, "agent id not found")
            logger.info('DELETE returning 404 response. agent id: ' + agent_id + ' not found.')
            return

        op_state =  agent['operational_state']
        if op_state == cloud_verifier_common.CloudAgent_Operational_State.SAVED or \
        op_state == cloud_verifier_common.CloudAgent_Operational_State.FAILED or \
        op_state == cloud_verifier_common.CloudAgent_Operational_State.TERMINATED or \
        op_state == cloud_verifier_common.CloudAgent_Operational_State.TENANT_FAILED or \
        op_state == cloud_verifier_common.CloudAgent_Operational_State.INVALID_QUOTE:
            self.db.remove_agent(agent_id)
            common.echo_json_response(self, 200, "Success")
            logger.info('DELETE returning 200 response for agent id: ' + agent_id)
        else:
            self.db.update_agent(agent_id, 'operational_state',cloud_verifier_common.CloudAgent_Operational_State.TERMINATED)
            common.echo_json_response(self, 202, "Accepted")
            logger.info('DELETE returning 202 response for agent id: ' + agent_id)

    # @tornado.web.asynchronous
    def post(self):
        """This method handles the POST requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's will return errors.
        agents requests require a json block sent in the body
        """
        try:
            rest_params = common.get_restful_params(self.request.uri)
            if rest_params is None:
                common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
                return

            if "agents" not in rest_params:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning('POST returning 400 response. uri not supported: ' + self.request.path)
                return

            agent_id = rest_params["agents"]

            if agent_id is not None: # this is for new items
                content_length = len(self.request.body)
                if content_length==0:
                    common.echo_json_response(self, 400, "Expected non zero content length")
                    logger.warning('POST returning 400 response. Expected non zero content length.')
                else:
                    json_body = json.loads(self.request.body)
                    d = {}
                    d['v'] = json_body['v']
                    d['ip'] = json_body['cloudagent_ip']
                    d['port'] = int(json_body['cloudagent_port'])
                    d['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.START
                    d['public_key'] = ""
                    d['tpm_policy'] = json_body['tpm_policy']
                    d['vtpm_policy'] = json_body['vtpm_policy']
                    d['metadata'] = json_body['metadata']
                    d['ima_whitelist'] = json_body['ima_whitelist']
                    d['revocation_key'] = json_body['revocation_key']
                    d['tpm_version'] = 0
                    d['accept_tpm_hash_algs'] = json_body['accept_tpm_hash_algs']
                    d['accept_tpm_encryption_algs'] = json_body['accept_tpm_encryption_algs']
                    d['accept_tpm_signing_algs'] = json_body['accept_tpm_signing_algs']
                    d['hash_alg'] = ""
                    d['enc_alg'] = ""
                    d['sign_alg'] = ""

                    new_agent = self.db.add_agent(agent_id,d)

                    # don't allow overwriting
                    if new_agent is None:
                        common.echo_json_response(self, 409, "Agent of uuid %s already exists"%(agent_id))
                        logger.warning("Agent of uuid %s already exists"%(agent_id))
                    else:
                        self.process_agent(new_agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE)
                        common.echo_json_response(self, 200, "Success")
                        logger.info('POST returning 200 response for adding agent id: ' + agent_id)
            else:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
        except Exception as e:
            common.echo_json_response(self, 400, "Exception error: %s"%e)
            logger.warning("POST returning 400 response. Exception error: %s"%e)
            logger.exception(e)

        self.finish()

    # @tornado.web.asynchronous
    def put(self):
        """This method handles the PUT requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's will return errors.
        agents requests require a json block sent in the body
        """
        try:
            rest_params = common.get_restful_params(self.request.uri)
            if rest_params is None:
                common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
                return

            if "agents" not in rest_params:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning('PUT returning 400 response. uri not supported: ' + self.request.path)
                return

            agent_id = rest_params["agents"]
            if agent_id is None:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")

            agent = self.db.get_agent(agent_id)

            if agent is not None:
                common.echo_json_response(self, 404, "agent id not found")
                logger.info('PUT returning 404 response. agent id: ' + agent_id + ' not found.')

            if "reactivate" in rest_params:
                agent['operational_state']=cloud_verifier_common.CloudAgent_Operational_State.START
                self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE)
                common.echo_json_response(self, 200, "Success")
                logger.info('PUT returning 200 response for agent id: ' + agent_id)
            elif "stop" in rest_params:
                # do stuff for terminate
                logger.debug("Stopping polling on %s"%agent_id)
                self.db.update_agent(agent_id,'operational_state',cloud_verifier_common.CloudAgent_Operational_State.TENANT_FAILED)

                common.echo_json_response(self, 200, "Success")
                logger.info('PUT returning 200 response for agent id: ' + agent_id)
            else:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")

        except Exception as e:
            common.echo_json_response(self, 400, "Exception error: %s"%e)
            logger.warning("PUT returning 400 response. Exception error: %s"%e)
            logger.exception(e)


        self.finish()


    def invoke_get_quote(self, agent, need_pubkey):
        params = cloud_verifier_common.prepare_get_quote(agent)
        agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE
        client = tornado.httpclient.AsyncHTTPClient()

        partial_req = "1"
        if need_pubkey:
            partial_req = "0"

        url = "http://%s:%d/quotes/integrity?nonce=%s&mask=%s&vmask=%s&partial=%s"%(agent['ip'],agent['port'],params["nonce"],params["mask"],params['vmask'],partial_req)
        # the following line adds the agent and params arguments to the callback as a convenience
        cb = functools.partial(self.on_get_quote_response, agent, url)
        client.fetch(url, callback=cb)

    def on_get_quote_response(self, agent, url, response):
        if agent is None:
            raise Exception("agent deleted while being processed")
        if response.error:
            # this is a connection error, retry get quote
            if isinstance(response.error, IOError) or (isinstance(response.error, tornado.web.HTTPError) and response.error.code == 599):
                self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE_RETRY)
            else:
                #catastrophic error, do not continue
                error = "Unexpected Get Quote response error for cloud agent " + agent['agent_id']  + ", Error: " + str(response.error)
                logger.critical(error)
                self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
        else:
            try:
                json_response = json.loads(response.body)

                # validate the cloud agent response
                if cloud_verifier_common.process_quote_response(agent, json_response['results']):
                    if agent['provide_V']:
                        self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V)
                    else:
                        self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE)
                else:
                    self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.INVALID_QUOTE)
                    cloud_verifier_common.notifyError(agent)

#                 if self.get_q_log_file_base_name is not None and writeTime:
#                     self.get_q_log_file.write("%s\n" % t.secs)
#                     self.get_q_log_file.flush()

            except Exception as e:
                logger.exception(e)



    def invoke_provide_v(self, agent):
        if agent['pending_event'] is not None:
            agent['pending_event'] = None
        v_json_message = cloud_verifier_common.prepare_v(agent)
        agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V
        client = tornado.httpclient.AsyncHTTPClient()
        url = "http://%s:%d/keys/vkey"%(agent['ip'],agent['port'])
        cb = functools.partial(self.on_provide_v_response, agent, url)
        client.fetch(url, method="POST", callback=cb, headers=None, body=v_json_message)

    def on_provide_v_response(self, agent, url_with_params, response):
        if agent is None:
            raise Exception("Agent deleted while being processed")
        if response.error:
            if isinstance(response.error, IOError) or (isinstance(response.error, tornado.web.HTTPError) and response.error.code == 599):
                self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V_RETRY)
            else:
                #catastrophic error, do not continue
                error = "Unexpected Provide V response error for cloud agent " + agent['agent_id']  + ", Error: " + str(response.error)
                logger.critical(error)
                self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
        else:
            self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE)

    def process_agent(self, agent, new_operational_state):
        try:
            main_agent_operational_state = agent['operational_state']
            stored_agent = self.db.get_agent(agent['agent_id'])

            # if the user did terminated this agent
            if stored_agent['operational_state'] == cloud_verifier_common.CloudAgent_Operational_State.TERMINATED:
                logger.warning("agent %s terminated by user."%agent['agent_id'])
                if agent['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(agent['pending_event'])
                self.db.remove_agent(agent['agent_id'])
                return

            # if the user tells us to stop polling because the tenant quote check failed
            if stored_agent['operational_state']==cloud_verifier_common.CloudAgent_Operational_State.TENANT_FAILED:
                logger.warning("agent %s has failed tenant quote.  stopping polling"%agent['agent_id'])
                if agent['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(agent['pending_event'])
                return

            # If failed during processing, log regardless and drop it on the floor
            # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).
            if new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.FAILED or \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.INVALID_QUOTE:
                agent['operational_state'] = new_operational_state
                if agent['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(agent['pending_event'])
                self.db.overwrite_agent(agent['agent_id'], agent)
                logger.warning("agent %s failed, stopping polling"%agent['agent_id'])
                return

            # propagate all state
            self.db.overwrite_agent(agent['agent_id'], agent)

            # if new, get a quote
            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.START and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE:
                agent['num_retries']=0
                self.invoke_get_quote(agent, True)
                return

            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE and \
                (new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V):
                agent['num_retries']=0
                self.invoke_provide_v(agent)
                return

            if (main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V or
               main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE) and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE:
                agent['num_retries']=0
                interval = config.getfloat('cloud_verifier','quote_interval')

                if interval==0:
                    self.invoke_get_quote(agent, False)
                else:
                    #logger.debug("Setting up callback to check again in %f seconds"%interval)
                    # set up a call back to check again
                    cb = functools.partial(self.invoke_get_quote, agent, False)
                    pending = tornado.ioloop.IOLoop.current().call_later(interval,cb)
                    agent['pending_event'] = pending
                return

            maxr = config.getint('cloud_verifier','max_retries')
            retry = config.getfloat('cloud_verifier','retry_interval')
            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE_RETRY:
                if agent['num_retries']>=maxr:
                    logger.warning("agent %s was not reachable for quote in %d tries, setting state to FAILED"%(agent['agent_id'],maxr))
                    if agent['first_verified']: # only notify on previously good agents
                        cloud_verifier_common.notifyError(agent,'comm_error')
                    else:
                        logger.debug("Communication error for new agent.  no notification will be sent")
                    self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
                else:
                    cb = functools.partial(self.invoke_get_quote, agent, True)
                    agent['num_retries']+=1
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(agent['ip'],agent['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return

            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V_RETRY:
                if agent['num_retries']>=maxr:
                    logger.warning("agent %s was not reachable to provide v in %d tries, setting state to FAILED"%(agent['agent_id'],maxr))
                    cloud_verifier_common.notifyError(agent,'comm_error')
                    self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
                else:
                    cb = functools.partial(self.invoke_provide_v, agent)
                    agent['num_retries']+=1
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(agent['ip'],agent['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return
            raise Exception("nothing should ever fall out of this!")

        except Exception as e:
            logger.error("Polling thread error: %s"%e)
            logger.exception(e)

def start_tornado(tornado_server, port):
    tornado_server.listen(port)
    print("Starting Torando on port " + str(port))
    tornado.ioloop.IOLoop.instance().start()
    print("Tornado finished")


def main(argv=sys.argv):
    """Main method of the Cloud Verifier Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    config = configparser.ConfigParser()
    config.read(common.CONFIG_FILE) # CONFIG_FILE="../keylime.conf"
    # print('file name comes here')

    cloudverifier_port = config.get('general', 'cloudverifier_port') 
    # general is all? cloudcerifier_port = 8881

    db_filename = "%s/%s"%(common.WORK_DIR,config.get('cloud_verifier','db_filename'))
    '''
    common.WORK_DIR
    WORK_DIR=os.path.abspath(".") or os.getenv('KEYLIME_DIR','/var/lib/keylime')
    Return a normalized absolutized version of the pathname path.

    cloud_verifier: a bunch of setting I couldn't understand ~_~
    db_filename: db_filename = cv_data.sqlite   What's this???!!!
    '''
    db = cloud_verifier_common.init_db(db_filename) # init a light weighted db, db is an object
    db.update_all_agents('operational_state', cloud_verifier_common.CloudAgent_Operational_State.SAVED)
    '''
    key: 'operational_state'
    value: cloud_verifier_common.CloudAgent_Operational_State.SAVED: just a state code
    update status? SET <key, value> operation
    '''

    num = db.count_agents() # count the number of agents: return len(self.get_agent_ids())
    if num>0:
        agent_ids = db.get_agent_ids() # get a list of agent ids
        logger.info("agent ids in db loaded from file: %s"%agent_ids)
    else: # this log is added by me for testing 
        logger.info("no agent now(testing)") 

    logger.info('Starting Cloud Verifier (tornado) on port ' + cloudverifier_port + ', use <Ctrl-C> to stop')
    '''
    this is what shows on screen
    logger = keylime_logging.init_logging('cloudverifier') logger is a logging
    ''' 
    # =============== adding handler ====================
    VerifierHandler = VerifierHandler_provider if identity=="provider" else VerifierHandler_tenant
    # ================================================
    app = tornado.web.Application([
        (r"/(?:v[0-9]/)?agents/.*", AgentsHandler,{'db':db}), # r"/ main page handler
        (r"/verifier/(.*)", VerifierHandler),
        (r".*", MainHandler),
        ])
    '''
    Apache framework
    The Tornado web server and tools.
    https://www.tornadoweb.org/en/stable/web.html#application-configuration
    ([...])each request handler is a tuple
    r"/" root location, according handler
    need to create a handler, class
    regular expression

    what are these handlers do? how do they react with each others
    '''
    context = cloud_verifier_common.init_mtls()
    '''
    init_mtls(section='cloud_verifier',generatedir='cv_ca'):

    '''
    
    #after TLS is up, start revocation notifier
    if config.getboolean('cloud_verifier', 'revocation_notifier'):  # [cloud_verifier] revocation_notifier = True
        logger.info("Starting service for revocation notifications on port %s"%config.getint('general','revocation_notifier_port'))
        revocation_notifier.start_broker()

    sockets = tornado.netutil.bind_sockets(int(cloudverifier_port), address='0.0.0.0')  
    # 0.0.0.0 all ip addr on local machine
    # Creates listening sockets bound to the given port and address.
    # [<socket.socket fd=5, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=6, laddr=('0.0.0.0', 8881)>]
    tornado.process.fork_processes(config.getint('cloud_verifier','multiprocessing_pool_num_workers'))
    ''' 
        Starts multiple worker processes.
        multiprocessing_pool_num_workers = 0
        If num_processes is None or <= 0, we detect the number of cores available 
        on this machine and fork that number of child processes.
        Since we use processes and not threads, there is no shared memory between any server code.
    '''
    asyncio.set_event_loop(asyncio.new_event_loop())
    '''
        Asynchronous I/O
        asyncio is a library to write concurrent code using the async/await syntax.
        The event loop is the core of every asyncio application. Event loops run asynchronous tasks and callbacks, 
        perform network IO operations, and run subprocesses.
        low level code
        Note that the behaviour of get_event_loop(), set_event_loop(), and new_event_loop() functions 
        can be altered by setting a custom event loop policy.
    '''
    server = tornado.httpserver.HTTPServer(app,ssl_options=context)
    '''
        A non-blocking, single-threaded HTTP server.
        Typical applications have little direct interaction with the HTTPServer class 
        except to start a server at the beginning of the process 
        (and even that is often done indirectly via tornado.web.Application.listen).

    '''
    server.add_sockets(sockets)

    '''
    similar to example
    sockets = tornado.netutil.bind_sockets(8888)
    tornado.process.fork_processes(0)
    server = HTTPServer(app)
    server.add_sockets(sockets)
    IOLoop.current().start()
    '''

    try:
        if identity=="tenant":
            requests.get(url=provider_ip+"/verifier/I_need_quote")
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.instance().stop()
        if config.getboolean('cloud_verifier', 'revocation_notifier'):
            revocation_notifier.stop_broker()


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)

'''
    key things are to figure out those handler 
    1. try to communicate using handler
    2. directly communicate with socket
'''
