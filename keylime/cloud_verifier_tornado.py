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

import asyncio
import configparser
import traceback
import sys
import functools
import time
import tornado.ioloop
import tornado.web
from tornado import httpserver
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import url_concat
import keylime.tornado_requests as tornado_requests

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

class MainHandler(tornado.web.RequestHandler):
    def head(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")
    def get(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")
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

    async def get(self):
        """This method handles the GET requests to retrieve status on agents from the Cloud Verifier.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. Agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.  If the agent_id
        was not found, it either completed successfully, or failed.  If found, the agent_id is still polling
        to contact the Cloud Agent.
        """
        rest_params = common.get_restful_params(self.request.uri)
        # DEBUG
        print("get a request with", rest_params)

        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" in rest_params:
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
        elif "verifier" in rest_params:
            # develope verifier api endpoint
            # DEBUG
            print("entering the verifier with: ", rest_params)
            partial_req = "1"  # don't need a pub key
            # TODO
            # assign the only agent we have as the provider 
            # actually should figure out which agent the corresponding provider to the tenant who send the request
            agent = self.db.get_agent_ids()
            new_agent = self.db.get_agent(agent[0])
            # DEBUG ensure we have correct ip and port
            # print(new_agent['ip'],new_agent['port'], new_agent['need_provider_quote']) 
            url = "http://%s:%d/quotes/integrity?nonce=%s&mask=%s&vmask=%s&partial=%s"%(new_agent['ip'],new_agent['port'],rest_params["nonce"],rest_params["mask"],rest_params['vmask'],partial_req)
            # DEBUG check url
            print(url)
            # Launch GET request
            await res = tornado_requests.request("GET", url, context=None)
            print(res)
            print("successful for now , without response back to tenant")
            print(res)
            
            response = await res 
            json_response = json.loads(response.body)
            common.echo_json_response(self, 200, "Success", json_response)
        else:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('GET returning 400 response. uri not supported: ' + self.request.path)
            # return  # not sure is necessary


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
                    # TODO: global setting in keylime.conf to assign these parameters
                    # currently hardcoding here
                    # ================
                    # d['provider_ip'] = ""
                    # d['provider_verifier_port'] = ""
                    d['need_provider_quote'] = True
                    # ================
                    

                    new_agent = self.db.add_agent(agent_id,d)

                    # don't allow overwriting
                    if new_agent is None:
                        common.echo_json_response(self, 409, "Agent of uuid %s already exists"%(agent_id))
                        logger.warning("Agent of uuid %s already exists"%(agent_id))
                    else:
                        asyncio.ensure_future(self.process_agent(new_agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE))
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
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE))
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


    async def invoke_get_quote(self, agent, need_pubkey):
        if agent is None:
            raise Exception("agent deleted while being processed")
        params = cloud_verifier_common.prepare_get_quote(agent)
        # why this line is missing is file
        agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE

        partial_req = "1"
        if need_pubkey:
            partial_req = "0"

        res = tornado_requests.request("GET",
                                    "http://%s:%d/quotes/integrity?nonce=%s&mask=%s&vmask=%s&partial=%s"%(agent['ip'],agent['port'],params["nonce"],params["mask"],params['vmask'],partial_req), context=None)
        response = await res

        if response.status_code !=200:
            # this is a connection error, retry get quote
            if response.status_code == 599:
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE_RETRY))
            else:
                #catastrophic error, do not continue
                error = "Unexpected Get Quote response error for cloud agent " + agent['agent_id']  + ", Error: " + str(response.status_code)
                logger.critical(error)
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED))
        else:
            try:
                    json_response = json.loads(response.body)

                    # validate the cloud agent response
                    if cloud_verifier_common.process_quote_response(agent, json_response['results']):
                        
                        # TODO: need a policy to determine when do we need and disable provider's quote
                        # Current approach: provider_quote only run once when bootstrapping
                        if agent['provide_V'] == False:
                            agent['need_provider_quote'] = False

                        if agent['need_provider_quote']:
                            asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE)  )
                        if agent['provide_V']:
                            asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V))
                        else:
                            asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE))
                    else:
                        asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.INVALID_QUOTE))

            except Exception as e:
                logger.exception(e)

    async def invoke_get_prov_quote(self, agent, need_pubkey):
        # obviously not need pubkey, delete latter
        params = cloud_verifier_common.prepare_get_quote(agent)
        agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE
        # DEBUG
        print("invoke_get_prov_quote")
        # TODO: hardcoding provider ip addr, need to read this info somewhere
        url = "http://%s:%d/verifier?nonce=%s&mask=%s&vmask=%s"%("10.0.2.4",8881,params["nonce"],params["mask"],params['vmask'])
        print("requesting from tenant")
        res = tornado_requests.request("GET", url, context=None)
        response = await res
        print("waiting")
        print(response.body)
        print(response.status_code)
        # process response:
        if response.status_code !=200:
            if response.status_code == 599:
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE_RETRY))
            else:
                error = "Unexpected Get Quote response error for provider: " + "10.0.2.4:8881 " + ", Error: " + str(response.status_code)
                logger.critical(error)
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED))
        else:
            try:
                json_response = json.loads(response.body)
                print(json_response) # so far doing now
                # common.echo_json_response(self, 200, json_response)
                # TODO develop a mechanism to validate provider quote
                # # validate the provider response
    #             if cloud_verifier_common.process_quote_response(agent, json_response['results']):
    #                 if agent['provide_V']: 
    #                     asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V))
    #                 else:  # theoretically won't get here
    #                     asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE))
    #             else:
    #                 asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.INVALID_QUOTE))

            except Exception as e:
                logger.exception(e)

        pass


    async def invoke_provide_v(self, agent):
        if agent is None:
            raise Exception("Agent deleted while being processed")
        if agent['pending_event'] is not None:
            agent['pending_event'] = None
        v_json_message = cloud_verifier_common.prepare_v(agent)
        res = tornado_requests.request("POST", "http://%s:%d//keys/vkey"%(agent['ip'],agent['port']), data=v_json_message)
        response = await res

        if response.status_code !=200:
            if isinstance(response.error, IOError) or (isinstance(response.error, tornado.web.HTTPError) and response.error.code == 599):
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V_RETRY))
            else:
                #catastrophic error, do not continue
                error = "Unexpected Provide V response error for cloud agent " + agent['agent_id']  + ", Error: " + str(response.error)
                logger.critical(error)
                asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED))
        else:
            asyncio.ensure_future(self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE))


    async def process_agent(self, agent, new_operational_state):
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

                # issue notification for invalid quotes
                if new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.INVALID_QUOTE:
                    cloud_verifier_common.notifyError(agent)

                if agent['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(agent['pending_event'])
                self.db.overwrite_agent(agent['agent_id'], agent)
                logger.warning("agent %s failed, stopping polling"%agent['agent_id'])
                return

            # propagate all state
            self.db.overwrite_agent(agent['agent_id'], agent)
            print("main_agent_operational_state: ", main_agent_operational_state, " & new_operational_state: ", new_operational_state)
            # if new, get a quote
            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.START and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE:
                agent['num_retries']=0
                agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE
                await self.invoke_get_quote(agent, True)
                return


            # if need provider quote
            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE:
                agent['num_retries'] = 0
                agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE
                await self.invoke_get_prov_quote(agent, True)
                return


            if (main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE or \
                main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE) and \
                (new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V):
                agent['num_retries']=0
                agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V
                await self.invoke_provide_v(agent)
                return

            if (main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V or
               main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE or 
               main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE) and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE:
                agent['num_retries']=0
                interval = config.getfloat('cloud_verifier','quote_interval')
                agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE
                if interval==0:
                    await self.invoke_get_quote(agent, False)
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
                    await self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
                else:
                    agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.GET_QUOTE
                    cb = functools.partial(self.invoke_get_quote, agent, True)
                    agent['num_retries']+=1
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(agent['ip'],agent['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return


            # provider quote retry
            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.GET_PROVIDER_QUOTE_RETRY:
                if agent['num_retries'] >= maxr:
                    logger.warning("provider %s was not reachable for quote in %d tries, setting state to FAILED"%(agent['agent_id'],maxr))
                    # TODO this logic may need to be split between agent and verifier
                    if agent['first_verified']: # only notify on previously good agents
                        cloud_verifier_common.notifyError(agent,'comm_error')
                    else:
                        logger.debug("Communication error for new agent.  no notification will be sent")
                    await self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
                else:
                    cb = functools.partial(self.invoke_get_prov_quote, agent, True)
                    agent['num_retries']+=1
                    # TODO agent ip/port needs to be changed to provider
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(agent['ip'],agent['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return

            if main_agent_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V and \
                new_operational_state == cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V_RETRY:
                if agent['num_retries']>=maxr:
                    logger.warning("agent %s was not reachable to provide v in %d tries, setting state to FAILED"%(agent['agent_id'],maxr))
                    cloud_verifier_common.notifyError(agent,'comm_error')
                    await self.process_agent(agent, cloud_verifier_common.CloudAgent_Operational_State.FAILED)
                else:
                    agent['operational_state'] = cloud_verifier_common.CloudAgent_Operational_State.PROVIDE_V
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
    config.read(common.CONFIG_FILE)

    cloudverifier_port = config.get('general', 'cloudverifier_port')

    db_filename = "%s/%s"%(common.WORK_DIR,config.get('cloud_verifier','db_filename'))
    db = cloud_verifier_common.init_db(db_filename)
    db.update_all_agents('operational_state', cloud_verifier_common.CloudAgent_Operational_State.SAVED)

    num = db.count_agents()
    if num>0:
        agent_ids = db.get_agent_ids()
        logger.info("agent ids in db loaded from file: %s"%agent_ids)

    logger.info('Starting Cloud Verifier (tornado) on port ' + cloudverifier_port + ', use <Ctrl-C> to stop')

    app = tornado.web.Application([
        (r"/(?:v[0-9]/)?agents/.*", AgentsHandler,{'db':db}),
        (r"/verifier.*", AgentsHandler,{'db':db}),
        (r".*", MainHandler),
        ])

    context = cloud_verifier_common.init_mtls()

    #after TLS is up, start revocation notifier
    if config.getboolean('cloud_verifier', 'revocation_notifier'):
        logger.info("Starting service for revocation notifications on port %s"%config.getint('general','revocation_notifier_port'))
        revocation_notifier.start_broker()  # need to pass in the rev_port?

    sockets = tornado.netutil.bind_sockets(int(cloudverifier_port), address='0.0.0.0')
    tornado.process.fork_processes(config.getint('cloud_verifier','multiprocessing_pool_num_workers'))
    asyncio.set_event_loop(asyncio.new_event_loop())
    server = tornado.httpserver.HTTPServer(app,ssl_options=context)
    server.add_sockets(sockets)

    try:
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
