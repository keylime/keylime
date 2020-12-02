#!/usr/bin/python3

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import base64
import logging
import os
import ssl
import traceback
import sys

import simplejson as json
import tornado.ioloop
import tornado.web

from keylime.requests_client import RequestsClient
from keylime import cloud_verifier_common
from keylime import tenant
from keylime import common
from keylime import keylime_logging

logger = keylime_logging.init_logging('tenant_webapp')
config = common.get_config()

tenant_templ = tenant.Tenant()
my_cert, my_priv_key = tenant_templ.get_tls_context()
cert = (my_cert, my_priv_key)
if config.getboolean('general', "enable_tls"):
    tls_enabled = True
else:
    tls_enabled = False
    cert = ""
    logger.warning(
        "TLS is currently disabled, keys will be sent in the clear! Should only be used for testing")

verifier_ip = config.get('cloud_verifier', 'cloudverifier_ip')
verifier_port = config.get('cloud_verifier', 'cloudverifier_port')
verifier_base_url = f'{verifier_ip}:{verifier_port}'

registrar_ip = config.get('registrar', 'registrar_ip')
registrar_tls_port = config.get('registrar', 'registrar_tls_port')
registrar_base_tls_url = f'{registrar_ip}:{registrar_tls_port}'


class Agent_Init_Types:
    FILE = '0'
    KEYFILE = '1'
    CA_DIR = '2'


class BaseHandler(tornado.web.RequestHandler):

    def write_error(self, status_code, **kwargs):

        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            common.echo_json_response(self, status_code, self._reason, lines)
        else:
            common.echo_json_response(self, status_code, self._reason)


class MainHandler(tornado.web.RequestHandler):
    def head(self):
        common.echo_json_response(
            self, 405, "Not Implemented: Use /webapp/, /agents/ or /logs/ interface instead")

    def get(self):
        common.echo_json_response(
            self, 405, "Not Implemented: Use /webapp/, /agents/ or /logs/  interface instead")

    def put(self):
        common.echo_json_response(
            self, 405, "Not Implemented: Use /webapp/, /agents/ or /logs/  interface instead")

    def post(self):
        common.echo_json_response(
            self, 405, "Not Implemented: Use /webapp/, /agents/ or /logs/  interface instead")

    def delete(self):
        common.echo_json_response(
            self, 405, "Not Implemented: Use /webapp/, /agents/ or /logs/  interface instead")


class WebAppHandler(BaseHandler):
    def head(self):
        """HEAD not supported"""
        common.echo_json_response(self, 405, "HEAD not supported")

    def get(self):
        """This method handles the GET requests to retrieve status on agents for all agents in a Web-based GUI.

        Currently, only the web app is available for GETing, i.e. /webapp. All other GET uri's
        will return errors.
        """

        # Get default policies for TPM/vTPM from config as suggestions to user
        tpm_policy = json.dumps(json.loads(
            config.get('tenant', 'tpm_policy')), indent=2)
        vtpm_policy = json.dumps(json.loads(
            config.get('tenant', 'vtpm_policy')), indent=2)

        self.set_status(200)
        self.set_header('Content-Type', 'text/html')
        self.write(
            """
            <!DOCTYPE html>
            <html>
                <head>
                    <meta charset='UTF-8'>
                    <title>Advanced Tenant Management System</title>
                    <script type='text/javascript' src='/static/js/webapp.js'></script>
                    <link href='/static/css/webapp.css' rel='stylesheet' type='text/css'/>
                </head>
                <body>
                    <div id='modal_box' onclick="if (event.target == this) {toggleVisibility(this.id);resetAddAgentForm();return false;}">

            """
        )

        self.write(
            """
                        <div id='modal_body'>
                            <center>
                                <h3>Add Agent</h3>
                                <h4 id='uuid_str'></h4>
                            </center>
                            <form id='add_agent' name='add_agent' onsubmit='submitAddAgentForm(this); return false;'>
                                <div class="form_block">
                                    <label for='agent_ip'>Agent IP: </label>
                                    <input type='text' id='agent_ip' name='agent_ip' value='127.0.0.1' required onfocus='this.select()'>
                                    <br>
                                </div>

                                <div id='imalist_toggle' onclick="toggleVisibility('imalist_block');" title='IMA Configuration'>
                                    IMA Configuration
                                </div>
                                <div id="imalist_block">
                                    <div class="form_block">
                                        <label for='a_list'>Allow-List: </label>
                                        <div id='a_list' name='a_list' class='file_drop'>
                                            <i>Drag payload here &hellip;</i>
                                        </div>
                                        <input type='hidden' name='a_list_data' id='a_list_data' value=''>
                                        <input type='hidden' name='a_list_name' id='a_list_name' value=''>
                                        <br>
                                    </div>

                                    <div class="form_block">
                                        <label for='e_list'>Exclude: </label>
                                        <div id='e_list' name='e_list' class='file_drop'>
                                            <i>Drag payload here &hellip;</i>
                                        </div>
                                        <input type='hidden' name='e_list_data' id='e_list_data' value=''>
                                        <input type='hidden' name='e_list_name' id='e_list_name' value=''>
                                        <br>
                                    </div>
                                </div>
                                <br>

                                <div id='policy_toggle' onclick="toggleVisibility('policy_block');" title='TPM &amp; vTPM Policy Configuration'>
                                    TPM &amp; vTPM Policy Configuration
                                </div>
                                <div id="policy_block">
                                    <div class="form_block">
                                        <label for='tpm_policy'>TPM Policy: </label><br>
                                        <textarea class='json_input' id='tpm_policy' name='tpm_policy'>{0}</textarea>
                                        <br>
                                    </div>

                                    <div class="form_block">
                                        <label for='vtpm_policy'>vTPM Policy: </label><br>
                                        <textarea class='json_input' id='vtpm_policy' name='vtpm_policy'>{1}</textarea>
                                        <br>
                                    </div>
                                </div>
                                <br>
            """.format(tpm_policy, vtpm_policy)
        )

        self.write(
            """
                                <div id="payload_block">
                                    <div class="form_block">
                                        <label for='ptype'>Payload type: </label>
                                        <label><input type='radio' name='ptype' value='{0}' checked="checked" onclick='toggleTabs(this.value)'> File </label>&nbsp;
                                        <label><input type='radio' name='ptype' value='{1}' onclick='toggleTabs(this.value)'> Keyfile </label>&nbsp;
                                        <label><input type='radio' name='ptype' value='{2}' onclick='toggleTabs(this.value)'> CA Dir </label>&nbsp;
                                        <br>
                                    </div>
            """.format(Agent_Init_Types.FILE, Agent_Init_Types.KEYFILE, Agent_Init_Types.CA_DIR)
        )

        self.write(
            """
                                    <div id='keyfile_container' class="form_block" style="display:none;">
                                        <label for='file'>Keyfile: </label>
                                        <div id='keyfile' name='keyfile' class='file_drop'>
                                            <i>Drag key file here &hellip;</i>
                                        </div>
                                        <input type='hidden' name='keyfile_data' id='keyfile_data' value=''>
                                        <input type='hidden' name='keyfile_name' id='keyfile_name' value=''>
                                        <br>
                                    </div>

                                    <div id='file_container' class="form_block">
                                        <label for='file'>Payload: </label>
                                        <div id='file' name='file' class='file_drop'>
                                            <i>Drag payload here &hellip;</i>
                                        </div>
                                        <input type='hidden' name='file_data' id='file_data' value=''>
                                        <input type='hidden' name='file_name' id='file_name' value=''>
                                        <br>
                                    </div>

                                    <div id='ca_dir_container' style="display:none;">
                                        <div class="form_block">
                                            <label for='ca_dir'>CA Dir: </label>
                                            <input type='text' id='ca_dir' name='ca_dir' placeholder='e.g., default'>
                                            <br>
                                        </div>

                                        <div class="form_block">
                                            <label for='ca_dir_pw'>CA Password: </label>
                                            <input type='password' id='ca_dir_pw' name='ca_dir_pw' placeholder='e.g., default'>
                                            <br>
                                        </div>

                                        <div class="form_block">
                                            <label for='include_dir'>Include dir: </label>
                                            <div id='include_dir' name='include_dir' class='file_drop multi_file'>
                                                <i>Drag files here &hellip;</i>
                                            </div>
                                            <input type='hidden' name='include_dir_data' id='include_dir_data' value=''>
                                            <input type='hidden' name='include_dir_name' id='include_dir_name' value=''>
                                            <br>
                                        </div>
                                    </div>
                                </div>
                                <br>

                                <input type='hidden' name='uuid' id='uuid' value=''>
                                <center><button type="submit" value="Add Agent">Add Agent</button></center>
                                <br>
                            </form>
                        </div>
                    </div>

                    <div id="header">
                        <div class="logo" title="Keylime">&nbsp;</div>
                        <div id="header_banner">
                            <h1>Keylime Advanced Tenant Management System</h1>
                        </div>
                        <div class="logo" style="float:right;" title="Keylime">&nbsp;</div>
                       <br style="clear:both;">
                    </div>

                    <div id="agent_body">
                        <h2>Agents</h2>
                        <div class='table_header'>
                            <div class='table_control'>&nbsp;</div>
                            <div class='table_col'>UUID</div>
                            <div class='table_col'>address</div>
                            <div class='table_col'>status</div>
                            <br style='clear:both;' />
                        </div>
                        <div id='agent_template' style='display:none;'>
                            <li class='agent'>
                                <div style='display:block;cursor:help;width:800px;'></div>
                                <div style='display:none;'></div>
                            </li>
                        </div>
                        <ol id='agent_container'></ol>
                        <div style="color:#888;margin-left:15px;padding:10px;">
                            <i>End of results</i>
                        </div>
                        <div id="terminal-frame">
                            <div id="terminal-header" onmousedown="toggleVisibility('terminal')">Tenant Logs</div>
                            <div id="terminal"></div>
                        </div>
                    </div>
                </body>
            </html>
            """
        )


class AgentsHandler(BaseHandler):
    def head(self):
        """HEAD not supported"""
        common.echo_json_response(self, 405, "HEAD not supported")

    async def get_agent_state(self, agent_id):
        try:
            get_agent_state = RequestsClient(verifier_base_url, tls_enabled)
            response = get_agent_state.get(
                (f'/agents/{agent_id}'),
                cert=cert,
                verify=False
            )

        except Exception as e:
            logger.error("Status command response: %s:%s Unexpected response from Cloud Verifier." % (
                tenant_templ.cloudverifier_ip, tenant_templ.cloudverifier_port))
            logger.exception(e)
            common.echo_json_response(
                self, 500, "Unexpected response from Cloud Verifier", str(e))
            logger.error("Unexpected response from Cloud Verifier: %s" % str(e))
            return

        inst_response_body = response.json()

        if response.status_code != 200 and response.status_code != 404:
            logger.error(
                "Status command response: %d Unexpected response from Cloud Verifier." % response.status_code)
            keylime_logging.log_http_response(
                logger, logging.ERROR, inst_response_body)
            return None

        if "results" not in inst_response_body:
            logger.critical("Error: unexpected http response body from Cloud Verifier: %s" % str(
                response.status_code))
            return None

        # Agent not added to CV (but still registered)
        if response.status_code == 404:
            return {"operational_state": cloud_verifier_common.CloudAgent_Operational_State.REGISTERED}
        else:
            return inst_response_body["results"]

        return None

    async def get(self):
        """This method handles the GET requests to retrieve status on agents from the WebApp.

        Currently, only the web app is available for GETing, i.e. /agents. All other GET uri's
        will return errors.
        """

        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ or /logs/ interface")
            return

        if "logs" in rest_params and rest_params["logs"] == "tenant":
            offset = 0
            if "pos" in rest_params and rest_params["pos"] is not None and rest_params["pos"].isdigit():
                offset = int(rest_params["pos"])
            # intercept requests for logs
            with open(keylime_logging.LOGSTREAM, 'r') as f:
                logValue = f.readlines()
                common.echo_json_response(self, 200, "Success", {
                                          'log': logValue[offset:]})
            return
        elif "agents" not in rest_params:
            # otherwise they must be looking for agent info
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'GET returning 400 response. uri not supported: ' + self.request.path)
            return

        agent_id = rest_params["agents"]
        if agent_id is not None:
            # Handle request for specific agent data separately
            agents = await self.get_agent_state(agent_id)
            agents["id"] = agent_id

            common.echo_json_response(self, 200, "Success", agents)
            return

        # If no agent ID, get list of all agents from Registrar
        try:
            get_agents = RequestsClient(registrar_base_tls_url, tls_enabled)
            response = get_agents.get(
                (f'/agents/'),
                cert=cert,
                verify=False
            )

        except Exception as e:
            logger.error("Status command response: %s:%s Unexpected response from Registrar." % (
                tenant_templ.registrar_ip, tenant_templ.registrar_port))
            logger.exception(e)
            common.echo_json_response(
                self, 500, "Unexpected response from Registrar", str(e))
            return

        response_body = response.json()

        if response.status_code != 200:
            logger.error(
                "Status command response: %d Unexpected response from Registrar." % response.status_code)
            keylime_logging.log_http_response(
                logger, logging.ERROR, response_body)
            return None

        if ("results" not in response_body) or ("uuids" not in response_body["results"]):
            logger.critical("Error: unexpected http response body from Registrar: %s" % str(
                response.status_code))
            return None

        agent_list = response_body["results"]["uuids"]

        # Loop through each agent and ask for status
        agents = {}
        for agent in agent_list:
            agents[agent] = await self.get_agent_state(agent_id)

        # Pre-create sorted agents list
        sorted_by_state = {}
        states = cloud_verifier_common.CloudAgent_Operational_State.STR_MAPPINGS
        for state in states:
            sorted_by_state[state] = {}

        # Build sorted agents list
        for agent_id in agents:
            state = agents[agent_id]["operational_state"]
            sorted_by_state[state][agent_id] = agents[agent_id]

        print_order = [10, 9, 7, 3, 4, 5, 6, 2, 1, 8, 0]
        sorted_agents = []
        for state in print_order:
            for agent_id in sorted_by_state[state]:
                sorted_agents.append(agent_id)

        common.echo_json_response(self, 200, "Success", {
                                  'uuids': sorted_agents})

    def delete(self):
        """This method handles the DELETE requests to remove agents from the Cloud Verifier.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """

        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'DELETE returning 400 response. uri not supported: ' + self.request.path)
            return

        agent_id = rest_params["agents"]

        # let Tenant do dirty work of deleting agent
        mytenant = tenant.Tenant()
        mytenant.agent_uuid = agent_id
        mytenant.do_cvdelete()

        common.echo_json_response(self, 200, "Success")

    def post(self):
        """This method handles the POST requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's will return errors.
        agents requests require a yaml block sent in the body
        """

        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'POST returning 400 response. uri not supported: ' + self.request.path)
            return

        agent_id = rest_params["agents"]

        # Parse payload files (base64 data-uri)
        if self.get_argument("ptype", Agent_Init_Types.FILE, True) == Agent_Init_Types.FILE:
            keyfile = None
            payload = None
            data = {'data': parse_data_uri(
                self.get_argument("file_data", None, True))}
            ca_dir = None
            incl_dir = None
            ca_dir_pw = None
        elif self.get_argument("ptype", Agent_Init_Types.FILE, True) == Agent_Init_Types.KEYFILE:
            keyfile = {'data': parse_data_uri(
                self.get_argument("keyfile_data", None, True)), }
            payload = {'data': parse_data_uri(
                self.get_argument("file_data", None, True))}
            data = None
            ca_dir = None
            incl_dir = None
            ca_dir_pw = None
        elif self.get_argument("ptype", Agent_Init_Types.FILE, True) == Agent_Init_Types.CA_DIR:
            keyfile = None
            payload = None
            data = None
            incl_dir = {
                'data': parse_data_uri(self.get_argument("include_dir_data", None, True)),
                'name': self.get_argument("include_dir_name", "", True).splitlines()
            }
            ca_dir = self.get_argument("ca_dir", 'default', True)
            if ca_dir == "":
                ca_dir = 'default'
            ca_dir_pw = self.get_argument("ca_dir_pw", 'default', True)
            if ca_dir_pw == "":
                ca_dir_pw = 'default'
        else:
            common.echo_json_response(self, 400, "invalid payload type chosen")
            logger.warning('POST returning 400 response. malformed query')
            return

        # Pull in user-defined v/TPM policies
        tpm_policy = self.get_argument("tpm_policy", "", True)
        if tpm_policy == "":
            tpm_policy = None
        vtpm_policy = self.get_argument("vtpm_policy", "", True)
        if vtpm_policy == "":
            vtpm_policy = None

        # Pull in allowlist
        allowlist = None
        a_list_data = self.get_argument("a_list_data", None, True)
        if a_list_data != "":
            allowlist_str = parse_data_uri(a_list_data)
            if allowlist_str is not None:
                allowlist = allowlist_str[0].splitlines()

        # Pull in IMA exclude list
        ima_exclude = None
        e_list_data = self.get_argument("e_list_data", None, True)
        if e_list_data != "":
            ima_exclude_str = parse_data_uri(e_list_data)
            if ima_exclude_str is not None:
                ima_exclude = ima_exclude_str[0].splitlines()

        # Build args to give to Tenant's init_add method
        args = {
            'agent_ip': self.get_argument("agent_ip", None, True),
            'file': data,
            'keyfile': keyfile,
            'payload': payload,
            'ca_dir': ca_dir,
            'incl_dir': incl_dir,
            'ca_dir_pw': ca_dir_pw,
            'tpm_policy': tpm_policy,
            'vtpm_policy': vtpm_policy,
            'allowlist': allowlist,
            'ima_exclude': ima_exclude,
        }

        # let Tenant do dirty work of adding agent
        try:
            mytenant = tenant.Tenant()
            mytenant.agent_uuid = agent_id
            mytenant.init_add(args)
            mytenant.preloop()
            mytenant.do_cv()
            mytenant.do_quote()
        except Exception as e:
            logger.exception(e)
            logger.warning(
                'POST returning 500 response. Tenant error: %s' % str(e))
            common.echo_json_response(self, 500, "Request failure", str(e))
            return

        common.echo_json_response(self, 200, "Success")

    def put(self):
        """This method handles the PUT requests to add agents to the Cloud Verifier.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's will return errors.
        """

        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(
                self, 405, "Not Implemented: Use /agents/ interface")
            return

        if "agents" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning(
                'PUT returning 400 response. uri not supported: ' + self.request.path)
            return

        agent_id = rest_params["agents"]

        # let Tenant do dirty work of reactivating agent
        mytenant = tenant.Tenant()
        mytenant.agent_uuid = agent_id
        mytenant.do_cvreactivate()

        common.echo_json_response(self, 200, "Success")


def parse_data_uri(data_uri):
    if data_uri is None:
        return None

    data = []

    dataset_uris = data_uri.split("\n")
    for uri in dataset_uris:
        fpos = uri.find(",")
        if fpos == -1:
            return None

        try:
            data.append(base64.b64decode(uri[fpos:]).decode('utf-8'))
        except Exception as e:
            # skip bad data
            continue

    return data


def start_tornado(tornado_server, port):
    tornado_server.listen(port)
    logger.info("Starting Torando on port " + str(port))
    tornado.ioloop.IOLoop.instance().start()
    logger.info("Tornado finished")


def get_tls_context():
    ca_cert = config.get('tenant', 'ca_cert')
    my_cert = config.get('tenant', 'my_cert')
    my_priv_key = config.get('tenant', 'private_key')

    tls_dir = config.get('tenant', 'tls_dir')

    if tls_dir == 'default':
        ca_cert = 'cacert.crt'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'
        tls_dir = 'cv_ca'

    # this is relative path, convert to absolute in WORK_DIR
    if tls_dir[0] != '/':
        tls_dir = os.path.abspath('%s/%s' % (common.WORK_DIR, tls_dir))

    logger.info(f"Setting up client TLS in {tls_dir}")

    ca_path = "%s/%s" % (tls_dir, ca_cert)
    my_cert = "%s/%s" % (tls_dir, my_cert)
    my_priv_key = "%s/%s" % (tls_dir, my_priv_key)

    context = ssl.create_default_context()
    context.load_verify_locations(cafile=ca_path)
    context.load_cert_chain(
        certfile=my_cert, keyfile=my_priv_key)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = config.getboolean(
        'general', 'tls_check_hostnames')
    return context


def main(argv=sys.argv):
    """Main method of the Tenant Webapp Server.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""

    config = common.get_config()

    webapp_port = config.getint('webapp', 'webapp_port')

    if not common.REQUIRE_ROOT and webapp_port < 1024:
        webapp_port += 2000
        logger.warn("Running without root, changing port to %d" % webapp_port)

    logger.info(
        'Starting Tenant WebApp (tornado) on port %d use <Ctrl-C> to stop' % webapp_port)

    # Figure out where our static files are located
    if getattr(sys, 'frozen', False):
        # static directory must be bundled with the script
        root_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        # instead try to locate static directory relative to script
        root_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.exists(root_dir + "/static/"):
        raise Exception(
            'Static resource directory could not be found in %s!' % (root_dir))

    app = tornado.web.Application([
        (r"/webapp/.*", WebAppHandler),
        (r"/(?:v[0-9]/)?agents/.*", AgentsHandler),
        (r"/(?:v[0-9]/)?logs/.*", AgentsHandler),
        (r'/static/(.*)', tornado.web.StaticFileHandler,
         {'path': root_dir + "/static/"}),
        (r".*", MainHandler),
    ])

    # WebApp Server TLS
    server_context = get_tls_context()
    server_context.check_hostname = False  # config.getboolean('general', 'tls_check_hostnames')
    server_context.verify_mode = ssl.CERT_NONE  # ssl.CERT_REQUIRED

    # Set up server
    server = tornado.httpserver.HTTPServer(app, ssl_options=server_context)
    server.bind(webapp_port, address='0.0.0.0')
    server.start(config.getint('cloud_verifier',
                               'multiprocessing_pool_num_workers'))

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.instance().stop()
