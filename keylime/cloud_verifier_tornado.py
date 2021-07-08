#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import traceback
import sys
import functools
import asyncio

import simplejson as json
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound
import tornado.ioloop
import tornado.web

from keylime import config
from keylime.common import states
from keylime.db.verifier_db import VerfierMain
from keylime.db.verifier_db import VerifierAllowlist
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime import keylime_logging
from keylime import cloud_verifier_common
from keylime import revocation_notifier
from keylime import tornado_requests

logger = keylime_logging.init_logging('cloudverifier')


try:
    engine = DBEngineManager().make_engine('cloud_verifier')
except SQLAlchemyError as err:
    logger.error('Error creating SQL engine or session: %s', err)
    sys.exit(1)


def get_session():
    return SessionManager().make_session(engine)


# The "exclude_db" dict values are removed from the response before adding the dict to the DB
# This is because we want these values to remain ephemeral and not stored in the database.
exclude_db = {
    'registrar_data': '',
    'nonce': '',
    'b64_encrypted_V': '',
    'provide_V': True,
    'num_retries': 0,
    'pending_event': None,
    'first_verified': False,
}


def _from_db_obj(agent_db_obj):
    fields = [ 'agent_id', \
                'v', \
                'ip', \
                'port', \
                'operational_state', \
                'public_key', \
                'tpm_policy', \
                'vtpm_policy', \
                'meta_data', \
                'mb_refstate', \
                'allowlist', \
                'ima_sign_verification_keys', \
                'revocation_key', \
                'accept_tpm_hash_algs', \
                'accept_tpm_encryption_algs', \
                'accept_tpm_signing_algs', \
                'hash_alg', \
                'enc_alg', \
                'sign_alg']
    agent_dict = {}
    for field in fields:
        agent_dict[field] = getattr(agent_db_obj, field, None)
    return agent_dict


class BaseHandler(tornado.web.RequestHandler):
    def prepare(self):  # pylint: disable=W0235
        super().prepare()

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

    def data_received(self, chunk):
        raise NotImplementedError()


class MainHandler(tornado.web.RequestHandler):

    def head(self):
        config.echo_json_response(
            self, 405, "Not Implemented: Use /agents/ interface instead")

    def get(self):
        config.echo_json_response(
            self, 405, "Not Implemented: Use /agents/ interface instead")

    def delete(self):
        config.echo_json_response(
            self, 405, "Not Implemented: Use /agents/ interface instead")

    def post(self):
        config.echo_json_response(
            self, 405, "Not Implemented: Use /agents/ interface instead")

    def put(self):
        config.echo_json_response(
            self, 405, "Not Implemented: Use /agents/ interface instead")

    def data_received(self, chunk):
        raise NotImplementedError()


class AgentsHandler(BaseHandler):
    def head(self):
        """HEAD not supported"""
        config.echo_json_response(self, 405, "HEAD not supported")

    def get(self):
        """This method handles the GET requests to retrieve status on agents from the Cloud Verifier.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. Agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.  If the agent_id
        was not found, it either completed successfully, or failed.  If found, the agent_id is still polling
        to contact the Cloud Agent.
        """
        session = get_session()
        rest_params = config.get_restful_params(self.request.uri)
        if rest_params is None:
            config.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            config.echo_json_response(self, 400, "uri not supported")
            logger.warning('GET returning 400 response. uri not supported: %s', self.request.path)
            return

        agent_id = rest_params["agents"]

        if (agent_id is not None) and (agent_id != ''):
            try:
                agent = session.query(VerfierMain).filter_by(
                    agent_id=agent_id).one_or_none()
            except SQLAlchemyError as e:
                logger.error('SQLAlchemy Error: %s', e)

            if agent is not None:
                response = cloud_verifier_common.process_get_status(agent)
                config.echo_json_response(self, 200, "Success", response)
            else:
                config.echo_json_response(self, 404, "agent id not found")
        else:
            json_response = None
            if "bulk" in rest_params.keys():
                agent_list = None

                if ("verifier" in rest_params.keys()) and (rest_params["verifier"] != ''):
                    agent_list = session.query(VerfierMain).filter_by(verifier_id=rest_params["verifier"]).all()
                else:
                    agent_list = session.query(VerfierMain).all()

                json_response = {}
                for agent in agent_list:
                    json_response[agent.agent_id] = cloud_verifier_common.process_get_status(agent)

                config.echo_json_response(self, 200, "Success", json_response)
            else:
                if ("verifier" in rest_params.keys()) and (rest_params["verifier"] != ''):
                    json_response = session.query(VerfierMain.agent_id).filter_by(
                        verifier_id=rest_params["verifier"]).all()
                else:
                    json_response = session.query(VerfierMain.agent_id).all()

                config.echo_json_response(self, 200, "Success", {
                    'uuids': json_response})

            logger.info('GET returning 200 response for agent_id list')

    def delete(self):
        """This method handles the DELETE requests to remove agents from the Cloud Verifier.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        session = get_session()
        rest_params = config.get_restful_params(self.request.uri)
        if rest_params is None:
            config.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            config.echo_json_response(self, 400, "uri not supported")
            return

        agent_id = rest_params["agents"]

        if agent_id is None:
            config.echo_json_response(self, 400, "uri not supported")
            logger.warning('DELETE returning 400 response. uri not supported: %s', self.request.path)
            return

        try:
            agent = session.query(VerfierMain).filter_by(
                agent_id=agent_id).first()
        except SQLAlchemyError as e:
            logger.error('SQLAlchemy Error: %s', e)

        if agent is None:
            config.echo_json_response(self, 404, "agent id not found")
            logger.info('DELETE returning 404 response. agent id: %s not found.', agent_id)
            return

        verifier_id = config.get('cloud_verifier', 'cloudverifier_id', cloud_verifier_common.DEFAULT_VERIFIER_ID)
        if verifier_id != agent.verifier_id:
            config.echo_json_response(self, 404, "agent id associated to this verifier")
            logger.info('DELETE returning 404 response. agent id: %s not associated to this verifer.', agent_id)
            return

        op_state = agent.operational_state
        if op_state in (states.SAVED, states.FAILED, states.TERMINATED,
                        states.TENANT_FAILED, states.INVALID_QUOTE):
            try:
                session.query(VerfierMain).filter_by(
                    agent_id=agent_id).delete()
                session.commit()
            except SQLAlchemyError as e:
                logger.error('SQLAlchemy Error: %s', e)
            config.echo_json_response(self, 200, "Success")
            logger.info('DELETE returning 200 response for agent id: %s', agent_id)
        else:
            try:
                update_agent = session.query(VerfierMain).get(agent_id)
                update_agent.operational_state = states.TERMINATED
                try:
                    session.add(update_agent)
                except SQLAlchemyError as e:
                    logger.error('SQLAlchemy Error: %s', e)
                session.commit()
                config.echo_json_response(self, 202, "Accepted")
                logger.info('DELETE returning 202 response for agent id: %s', agent_id)
            except SQLAlchemyError as e:
                logger.error('SQLAlchemy Error: %s', e)

    def post(self):
        """This method handles the POST requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's will return errors.
        agents requests require a json block sent in the body
        """
        session = get_session()
        try:
            rest_params = config.get_restful_params(self.request.uri)
            if rest_params is None:
                config.echo_json_response(
                    self, 405, "Not Implemented: Use /agents/ interface")
                return

            if "agents" not in rest_params:
                config.echo_json_response(self, 400, "uri not supported")
                logger.warning('POST returning 400 response. uri not supported: %s', self.request.path)
                return

            agent_id = rest_params["agents"]

            if agent_id is not None:
                content_length = len(self.request.body)
                if content_length == 0:
                    config.echo_json_response(
                        self, 400, "Expected non zero content length")
                    logger.warning('POST returning 400 response. Expected non zero content length.')
                else:
                    json_body = json.loads(self.request.body)
                    agent_data = {}
                    agent_data['v'] = json_body['v']
                    agent_data['ip'] = json_body['cloudagent_ip']
                    agent_data['port'] = int(json_body['cloudagent_port'])
                    agent_data['operational_state'] = states.START
                    agent_data['public_key'] = ""
                    agent_data['tpm_policy'] = json_body['tpm_policy']
                    agent_data['vtpm_policy'] = json_body['vtpm_policy']
                    agent_data['meta_data'] = json_body['metadata']
                    agent_data['allowlist'] = json_body['allowlist']
                    agent_data['mb_refstate'] = json_body['mb_refstate']
                    agent_data['ima_sign_verification_keys'] = json_body['ima_sign_verification_keys']
                    agent_data['revocation_key'] = json_body['revocation_key']
                    agent_data['accept_tpm_hash_algs'] = json_body['accept_tpm_hash_algs']
                    agent_data['accept_tpm_encryption_algs'] = json_body['accept_tpm_encryption_algs']
                    agent_data['accept_tpm_signing_algs'] = json_body['accept_tpm_signing_algs']
                    agent_data['hash_alg'] = ""
                    agent_data['enc_alg'] = ""
                    agent_data['sign_alg'] = ""
                    agent_data['agent_id'] = agent_id
                    agent_data['verifier_id'] = config.get('cloud_verifier', 'cloudverifier_id', cloud_verifier_common.DEFAULT_VERIFIER_ID)
                    agent_data['verifier_ip'] = config.get('cloud_verifier', 'cloudverifier_ip')
                    agent_data['verifier_port'] = config.get('cloud_verifier', 'cloudverifier_port')

                    is_valid, err_msg = cloud_verifier_common.validate_agent_data(agent_data)
                    if not is_valid:
                        config.echo_json_response(self, 400, err_msg)
                        logger.warning(err_msg)
                        return

                    try:
                        new_agent_count = session.query(
                            VerfierMain).filter_by(agent_id=agent_id).count()
                    except SQLAlchemyError as e:
                        logger.error('SQLAlchemy Error: %s', e)

                    # don't allow overwriting

                    if new_agent_count > 0:
                        config.echo_json_response(
                            self, 409, "Agent of uuid %s already exists" % (agent_id))
                        logger.warning("Agent of uuid %s already exists", agent_id)
                    else:
                        try:
                            # Add the agent and data
                            session.add(VerfierMain(**agent_data))
                            session.commit()
                        except SQLAlchemyError as e:
                            logger.error('SQLAlchemy Error: %s', e)

                        for key in list(exclude_db.keys()):
                            agent_data[key] = exclude_db[key]
                        asyncio.ensure_future(
                            process_agent(agent_data, states.GET_QUOTE))
                        config.echo_json_response(self, 200, "Success")
                        logger.info('POST returning 200 response for adding agent id: %s', agent_id)
            else:
                config.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
        except Exception as e:
            config.echo_json_response(self, 400, "Exception error: %s" % e)
            logger.warning("POST returning 400 response. Exception error: %s", e)
            logger.exception(e)

        self.finish()

    def put(self):
        """This method handles the PUT requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's will return errors.
        agents requests require a json block sent in the body
        """
        session = get_session()
        try:
            rest_params = config.get_restful_params(self.request.uri)
            if rest_params is None:
                config.echo_json_response(
                    self, 405, "Not Implemented: Use /agents/ interface")
                return

            if "agents" not in rest_params:
                config.echo_json_response(self, 400, "uri not supported")
                logger.warning('PUT returning 400 response. uri not supported: %s', self.request.path)
                return

            agent_id = rest_params["agents"]

            if agent_id is None:
                config.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")
            try:
                verifier_id = config.get('cloud_verifier', 'cloudverifier_id', cloud_verifier_common.DEFAULT_VERIFIER_ID)
                agent = session.query(VerfierMain).filter_by(
                    agent_id=agent_id, verifier_id=verifier_id).one()
            except SQLAlchemyError as e:
                logger.error('SQLAlchemy Error: %s', e)

            if agent is None:
                config.echo_json_response(self, 404, "agent id not found")
                logger.info('PUT returning 404 response. agent id: %s not found.', agent_id)
                return

            if "reactivate" in rest_params:
                agent.operational_state = states.START
                asyncio.ensure_future(
                    process_agent(agent, states.GET_QUOTE))
                config.echo_json_response(self, 200, "Success")
                logger.info('PUT returning 200 response for agent id: %s', agent_id)
            elif "stop" in rest_params:
                # do stuff for terminate
                logger.debug("Stopping polling on %s", agent_id)
                try:
                    session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update(
                        {'operational_state': states.TENANT_FAILED})
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error('SQLAlchemy Error: %s', e)

                config.echo_json_response(self, 200, "Success")
                logger.info('PUT returning 200 response for agent id: %s', agent_id)
            else:
                config.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")

        except Exception as e:
            config.echo_json_response(self, 400, "Exception error: %s" % e)
            logger.warning("PUT returning 400 response. Exception error: %s", e)
            logger.exception(e)
        self.finish()

    def data_received(self, chunk):
        raise NotImplementedError()


class AllowlistHandler(BaseHandler):
    def head(self):
        config.echo_json_response(
            self, 400, "Allowlist handler: HEAD Not Implemented")

    def get(self):
        """Get an allowlist

        GET /(?:v[0-9]/)?allowlists/{name}
        """

        rest_params = config.get_restful_params(self.request.uri)
        if rest_params is None or 'allowlists' not in rest_params:
            config.echo_json_response(self, 400, "Invalid URL")
            return

        allowlist_name = rest_params['allowlists']
        if allowlist_name is None:
            config.echo_json_response(self, 400, "Invalid URL")
            logger.warning(
                'GET returning 400 response: ' + self.request.path)
            return

        session = get_session()
        try:
            allowlist = session.query(VerifierAllowlist).filter_by(
                name=allowlist_name).one()
        except NoResultFound:
            config.echo_json_response(self, 404, "Allowlist %s not found" % allowlist_name)
            return
        except SQLAlchemyError as e:
            logger.error(f'SQLAlchemy Error: {e}')
            config.echo_json_response(self, 500, "Failed to get allowlist")
            raise

        response = {}
        for field in ('name', 'tpm_policy', 'vtpm_policy', 'ima_policy'):
            response[field] = getattr(allowlist, field, None)
        config.echo_json_response(self, 200, 'Success', response)

    def delete(self):
        """Delete an allowlist

        DELETE /(?:v[0-9]/)?allowlists/{name}
        """

        rest_params = config.get_restful_params(self.request.uri)
        if rest_params is None or 'allowlists' not in rest_params:
            config.echo_json_response(self, 400, "Invalid URL")
            return

        allowlist_name = rest_params['allowlists']
        if allowlist_name is None:
            config.echo_json_response(self, 400, "Invalid URL")
            logger.warning(
                'DELETE returning 400 response: ' + self.request.path)
            return

        session = get_session()
        try:
            session.query(VerifierAllowlist).filter_by(
                name=allowlist_name).one()
        except NoResultFound:
            config.echo_json_response(self, 404, "Allowlist %s not found" % allowlist_name)
            return
        except SQLAlchemyError as e:
            logger.error(f'SQLAlchemy Error: {e}')
            config.echo_json_response(self, 500, "Failed to get allowlist")
            raise

        try:
            session.query(VerifierAllowlist).filter_by(
                name=allowlist_name).delete()
            session.commit()
        except SQLAlchemyError as e:
            logger.error(f'SQLAlchemy Error: {e}')
            config.echo_json_response(self, 500, "Failed to get allowlist")
            raise

        # NOTE(kaifeng) 204 Can not have response body, but current helper
        # doesn't support this case.
        self.set_status(204)
        self.set_header('Content-Type', 'application/json')
        self.finish()
        logger.info(
            'DELETE returning 204 response for allowlist: ' + allowlist_name)

    def post(self):
        """Create an allowlist

        POST /(?:v[0-9]/)?allowlists/{name}
        body: {"tpm_policy": {..}, "vtpm_policy": {..}
        """

        rest_params = config.get_restful_params(self.request.uri)
        if rest_params is None or 'allowlists' not in rest_params:
            config.echo_json_response(self, 400, "Invalid URL")
            return

        allowlist_name = rest_params['allowlists']
        if allowlist_name is None:
            config.echo_json_response(self, 400, "Invalid URL")
            return

        content_length = len(self.request.body)
        if content_length == 0:
            config.echo_json_response(
                self, 400, "Expected non zero content length")
            logger.warning(
                'POST returning 400 response. Expected non zero content length.')
            return

        allowlist = {}
        json_body = json.loads(self.request.body)
        allowlist['name'] = allowlist_name
        tpm_policy = json_body.get('tpm_policy')
        if tpm_policy:
            allowlist['tpm_policy'] = tpm_policy
        vtpm_policy = json_body.get('vtpm_policy')
        if vtpm_policy:
            allowlist['vtpm_policy'] = vtpm_policy
        ima_policy = json_body.get('ima_policy')
        if ima_policy:
            allowlist['ima_policy'] = ima_policy

        session = get_session()
        # don't allow overwritting
        try:
            al_count = session.query(
                VerifierAllowlist).filter_by(name=allowlist_name).count()
            if al_count > 0:
                config.echo_json_response(
                    self, 409, "Allowlist with name %s already exists" % allowlist_name)
                logger.warning(
                    "Allowlist with name %s already exists" % allowlist_name)
                return
        except SQLAlchemyError as e:
            logger.error(f'SQLAlchemy Error: {e}')
            raise

        try:
            # Add the agent and data
            session.add(VerifierAllowlist(**allowlist))
            session.commit()
        except SQLAlchemyError as e:
            logger.error(f'SQLAlchemy Error: {e}')
            raise

        config.echo_json_response(self, 201)
        logger.info('POST returning 201')

    def put(self):
        config.echo_json_response(
            self, 400, "Allowlist handler: PUT Not Implemented")

    def data_received(self, chunk):
        raise NotImplementedError()


async def invoke_get_quote(agent, need_pubkey):
    if agent is None:
        raise Exception("agent deleted while being processed")
    params = cloud_verifier_common.prepare_get_quote(agent)

    partial_req = "1"
    if need_pubkey:
        partial_req = "0"

    res = tornado_requests.request("GET",
                                   "http://%s:%d/quotes/integrity?nonce=%s&mask=%s&vmask=%s&partial=%s" %
                                   (agent['ip'], agent['port'], params["nonce"], params["mask"], params['vmask'], partial_req), context=None)
    response = await res

    if response.status_code != 200:
        # this is a connection error, retry get quote
        if response.status_code == 599:
            asyncio.ensure_future(process_agent(
                agent, states.GET_QUOTE_RETRY))
        else:
            # catastrophic error, do not continue
            logger.critical("Unexpected Get Quote response error for cloud agent %s, Error: %s", agent['agent_id'], response.status_code)
            asyncio.ensure_future(process_agent(agent, states.FAILED))
    else:
        try:
            json_response = json.loads(response.body)

            # validate the cloud agent response
            if 'provide_V' not in agent :
                agent['provide_V'] = True
            if cloud_verifier_common.process_quote_response(agent, json_response['results']):
                if agent['provide_V']:
                    asyncio.ensure_future(process_agent(agent, states.PROVIDE_V))
                else:
                    asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
            else:
                asyncio.ensure_future(process_agent(agent, states.INVALID_QUOTE))

        except Exception as e:
            logger.exception(e)


async def invoke_provide_v(agent):
    if agent is None:
        raise Exception("Agent deleted while being processed")
    try:
        if agent['pending_event'] is not None:
            agent['pending_event'] = None
    except KeyError:
        pass
    v_json_message = cloud_verifier_common.prepare_v(agent)
    res = tornado_requests.request(
        "POST", "http://%s:%d//keys/vkey" % (agent['ip'], agent['port']), data=v_json_message)
    response = await res

    if response.status_code != 200:
        if response.status_code == 599:
            asyncio.ensure_future(
                process_agent(agent, states.PROVIDE_V_RETRY))
        else:
            # catastrophic error, do not continue
            logger.critical("Unexpected Provide V response error for cloud agent %s, Error: %s", agent['agent_id'], response.error)
            asyncio.ensure_future(process_agent(agent, states.FAILED))
    else:
        asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))


async def process_agent(agent, new_operational_state):
    # Convert to dict if the agent arg is a db object
    if not isinstance(agent, dict):
        agent = _from_db_obj(agent)

    session = get_session()
    try:
        main_agent_operational_state = agent['operational_state']
        try:
            stored_agent = session.query(VerfierMain).filter_by(
                agent_id=str(agent['agent_id'])).first()
        except SQLAlchemyError as e:
            logger.error('SQLAlchemy Error: %s', e)

        # if the user did terminated this agent
        if stored_agent.operational_state == states.TERMINATED:
            logger.warning("Agent %s terminated by user.", agent['agent_id'])
            if agent['pending_event'] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(
                    agent['pending_event'])
            session.query(VerfierMain).filter_by(
                agent_id=agent['agent_id']).delete()
            session.commit()
            return

        # if the user tells us to stop polling because the tenant quote check failed
        if stored_agent.operational_state == states.TENANT_FAILED:
            logger.warning("Agent %s has failed tenant quote. Stopping polling",  agent['agent_id'])
            if agent['pending_event'] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(
                    agent['pending_event'])
            return

        # If failed during processing, log regardless and drop it on the floor
        # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).
        if new_operational_state in (states.FAILED, states.INVALID_QUOTE):
            agent['operational_state'] = new_operational_state

            # issue notification for invalid quotes
            if new_operational_state == states.INVALID_QUOTE:
                cloud_verifier_common.notify_error(agent)

            if agent['pending_event'] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(
                    agent['pending_event'])
            for key in exclude_db:
                if key in agent:
                    del agent[key]
            session.query(VerfierMain).filter_by(
                agent_id=agent['agent_id']).update(agent)
            session.commit()

            logger.warning("Agent %s failed, stopping polling", agent['agent_id'])
            return

        # propagate all state, but remove none DB keys first (using exclude_db)
        try:
            agent_db = dict(agent)
            for key in exclude_db:
                if key in agent_db:
                    del agent_db[key]

            session.query(VerfierMain).filter_by(
                agent_id=agent_db['agent_id']).update(agent_db)
            session.commit()
        except SQLAlchemyError as e:
            logger.error('SQLAlchemy Error: %s', e)

        # if new, get a quote
        if (main_agent_operational_state == states.START and
                new_operational_state == states.GET_QUOTE):
            agent['num_retries'] = 0
            agent['operational_state'] = states.GET_QUOTE
            await invoke_get_quote(agent, True)
            return

        if (main_agent_operational_state == states.GET_QUOTE and
                new_operational_state == states.PROVIDE_V):
            agent['num_retries'] = 0
            agent['operational_state'] = states.PROVIDE_V
            await invoke_provide_v(agent)
            return

        if (main_agent_operational_state in (states.PROVIDE_V, states.GET_QUOTE) and
                new_operational_state == states.GET_QUOTE):
            agent['num_retries'] = 0
            interval = config.getfloat('cloud_verifier', 'quote_interval')
            agent['operational_state'] = states.GET_QUOTE
            if interval == 0:
                await invoke_get_quote(agent, False)
            else:
                logger.debug("Setting up callback to check again in %f seconds", interval)
                # set up a call back to check again
                cb = functools.partial(invoke_get_quote, agent, False)
                pending = tornado.ioloop.IOLoop.current().call_later(interval, cb)
                agent['pending_event'] = pending
            return

        maxr = config.getint('cloud_verifier', 'max_retries')
        retry = config.getfloat('cloud_verifier', 'retry_interval')
        if (main_agent_operational_state == states.GET_QUOTE and
                new_operational_state == states.GET_QUOTE_RETRY):
            if agent['num_retries'] >= maxr:
                logger.warning("Agent %s was not reachable for quote in %d tries, setting state to FAILED", agent['agent_id'], maxr)
                if agent['first_verified']:  # only notify on previously good agents
                    cloud_verifier_common.notify_error(
                        agent, msgtype='comm_error')
                else:
                    logger.debug("Communication error for new agent. No notification will be sent")
                await process_agent(agent, states.FAILED)
            else:
                agent['operational_state'] = states.GET_QUOTE
                cb = functools.partial(invoke_get_quote, agent, True)
                agent['num_retries'] += 1
                logger.info("Connection to %s refused after %d/%d tries, trying again in %f seconds", agent['ip'], agent['num_retries'], maxr, retry)
                tornado.ioloop.IOLoop.current().call_later(retry, cb)
            return

        if (main_agent_operational_state == states.PROVIDE_V and
                new_operational_state == states.PROVIDE_V_RETRY):
            if agent['num_retries'] >= maxr:
                logger.warning("Agent %s was not reachable to provide v in %d tries, setting state to FAILED", agent['agent_id'], maxr)
                cloud_verifier_common.notify_error(
                    agent, msgtype='comm_error')
                await process_agent(agent, states.FAILED)
            else:
                agent['operational_state'] = states.PROVIDE_V
                cb = functools.partial(invoke_provide_v, agent)
                agent['num_retries'] += 1
                logger.info("Connection to %s refused after %d/%d tries, trying again in %f seconds", agent['ip'], agent['num_retries'], maxr, retry)
                tornado.ioloop.IOLoop.current().call_later(retry, cb)
            return
        raise Exception("nothing should ever fall out of this!")

    except Exception as e:
        logger.error("Polling thread error: %s", e)
        logger.exception(e)


async def activate_agents(verifier_id, verifier_ip, verifier_port):
    session = get_session()
    try:
        agents = session.query(VerfierMain).filter_by(
            verifier_id=verifier_id).all()
        for agent in agents:
            agent.verifier_ip = verifier_ip
            agent.verifier_host = verifier_port
            if agent.operational_state == states.START:
                asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
        session.commit()
    except SQLAlchemyError as e:
        logger.error('SQLAlchemy Error: %s', e)


def start_tornado(tornado_server, port):
    tornado_server.listen(port)
    print("Starting Torando on port " + str(port))
    tornado.ioloop.IOLoop.instance().start()
    print("Tornado finished")


def main():
    """Main method of the Cloud Verifier Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    cloudverifier_port = config.get('cloud_verifier', 'cloudverifier_port')
    cloudverifier_host = config.get('cloud_verifier', 'cloudverifier_ip')
    cloudverifier_id = config.get('cloud_verifier', 'cloudverifier_id', cloud_verifier_common.DEFAULT_VERIFIER_ID)

    # allow tornado's max upload size to be configurable
    max_upload_size = None
    if config.has_option('cloud_verifier', 'max_upload_size'):
        max_upload_size = int(config.get('cloud_verifier', 'max_upload_size'))

    VerfierMain.metadata.create_all(engine, checkfirst=True)
    session = get_session()
    try:
        query_all = session.query(VerfierMain).all()
        for row in query_all:
            if row.operational_state in states.APPROVED_REACTIVATE_STATES:
                row.operational_state = states.START
        session.commit()
    except SQLAlchemyError as e:
        logger.error('SQLAlchemy Error: %s', e)

    num = session.query(VerfierMain.agent_id).count()
    if num > 0:
        agent_ids = session.query(VerfierMain.agent_id).all()
        logger.info("Agent ids in db loaded from file: %s", agent_ids)

    logger.info('Starting Cloud Verifier (tornado) on port %s, use <Ctrl-C> to stop', cloudverifier_port)

    app = tornado.web.Application([
        (r"/(?:v[0-9]/)?agents/.*", AgentsHandler),
        (r"/(?:v[0-9]/)?allowlists/.*", AllowlistHandler),
        (r".*", MainHandler),
    ])

    context = cloud_verifier_common.init_mtls()

    # after TLS is up, start revocation notifier
    if config.getboolean('cloud_verifier', 'revocation_notifier'):
        logger.info("Starting service for revocation notifications on port %s", config.getint('cloud_verifier', 'revocation_notifier_port'))
        revocation_notifier.start_broker()

    sockets = tornado.netutil.bind_sockets(
        int(cloudverifier_port), address=cloudverifier_host)
    task_id = tornado.process.fork_processes(config.getint(
        'cloud_verifier', 'multiprocessing_pool_num_workers'))
    asyncio.set_event_loop(asyncio.new_event_loop())
    # Auto reactivate agent
    if task_id == 0:
        asyncio.ensure_future(activate_agents(cloudverifier_id, cloudverifier_host, cloudverifier_port))

    server = tornado.httpserver.HTTPServer(app, ssl_options=context, max_buffer_size=max_upload_size)
    server.add_sockets(sockets)

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.instance().stop()
        if config.getboolean('cloud_verifier', 'revocation_notifier'):
            revocation_notifier.stop_broker()
