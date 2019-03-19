#!/usr/bin/python

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
import common
logger = common.init_logging('cloudverifier')

import json
import ConfigParser
import traceback
import sys
import tornado.ioloop
import tornado.web
import functools
from tornado import httpserver
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import url_concat
import cloud_verifier_common
import revocation_notifier

config = ConfigParser.SafeConfigParser()
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
        common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface instead")
    def get(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface instead")
    def delete(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface instead")
    def post(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface instead")
    def put(self):
        common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface instead")

class InstancesHandler(BaseHandler):
    db = None
    def initialize(self, db):
        self.db = db
       
    def head(self):
        """HEAD not supported"""
        common.echo_json_response(self, 405, "HEAD not supported")
  
    def get(self):
        """This method handles the GET requests to retrieve status on instances from the Cloud Verifier. 
        
        Currently, only instances resources are available for GETing, i.e. /instances. All other GET uri's 
        will return errors. instances requests require a single instance_id parameter which identifies the 
        instance to be returned. If the instance_id is not found, a 404 response is returned.  If the instance_id
        was not found, it either completed successfully, or failed.  If found, the instance_id is still polling 
        to contact the Cloud Node. 
        """
        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface")
            return
        
        if "instances" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('GET returning 400 response. uri not supported: ' + self.request.path)
            return
        
        instance_id = rest_params["instances"]
        
        if instance_id is not None:
            instance = self.db.get_instance(instance_id)
            if instance != None:
                response = cloud_verifier_common.process_get_status(instance)
                common.echo_json_response(self, 200, "Success", response)
                #logger.info('GET returning 200 response for instance_id: ' + instance_id)
                
            else:
                #logger.info('GET returning 404 response. instance id: ' + instance_id + ' not found.')
                common.echo_json_response(self, 404, "instance id not found")
        else:
            # return the available keys in the DB
            json_response = self.db.get_instance_ids()
            common.echo_json_response(self, 200, "Success", {'uuids':json_response})
            logger.info('GET returning 200 response for instance_id list')
            
    def delete(self):
        """This method handles the DELETE requests to remove instances from the Cloud Verifier. 
         
        Currently, only instances resources are available for DELETEing, i.e. /instances. All other DELETE uri's will return errors.
        instances requests require a single instance_id parameter which identifies the instance to be deleted.    
        """
        rest_params = common.get_restful_params(self.request.uri)
        if rest_params is None:
            common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface")
            return
        
        if "instances" not in rest_params:
            common.echo_json_response(self, 400, "uri not supported")
            return
        
        instance_id = rest_params["instances"]
        
        if instance_id is None:
            common.echo_json_response(self, 400, "uri not supported")
            logger.warning('DELETE returning 400 response. uri not supported: ' + self.request.path)
                        
        instance = self.db.get_instance(instance_id)
        
        if instance is None:
            common.echo_json_response(self, 404, "instance id not found")
            logger.info('DELETE returning 404 response. instance id: ' + instance_id + ' not found.')
            return
                
        op_state =  instance['operational_state']
        if op_state == cloud_verifier_common.CloudInstance_Operational_State.SAVED or \
        op_state == cloud_verifier_common.CloudInstance_Operational_State.FAILED or \
        op_state == cloud_verifier_common.CloudInstance_Operational_State.INVALID_QUOTE:
            self.db.remove_instance(instance_id)
            common.echo_json_response(self, 200, "Success")
            logger.info('DELETE returning 200 response for instance id: ' + instance_id)
        else:            
            self.db.update_instance(instance_id, 'operational_state',cloud_verifier_common.CloudInstance_Operational_State.TERMINATED)
            common.echo_json_response(self, 202, "Accepted")
            logger.info('DELETE returning 202 response for instance id: ' + instance_id)

    @tornado.web.asynchronous                   
    def post(self):
        """This method handles the POST requests to add instances to the Cloud Verifier. 
         
        Currently, only instances resources are available for POSTing, i.e. /instances. All other POST uri's will return errors.
        instances requests require a json block sent in the body
        """
        try:
            rest_params = common.get_restful_params(self.request.uri)
            if rest_params is None:
                common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface")
                return
            
            if "instances" not in rest_params:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning('POST returning 400 response. uri not supported: ' + self.request.path)
                return
            
            instance_id = rest_params["instances"]
            
            if instance_id is not None: # this is for new items
                content_length = len(self.request.body)
                if content_length==0:
                    common.echo_json_response(self, 400, "Expected non zero content length")
                    logger.warning('POST returning 400 response. Expected non zero content length.')
                else:
                    json_body = json.loads(self.request.body)
                    d = {}
                    d['v'] = json_body['v']
                    d['ip'] = json_body['cloudnode_ip']
                    d['port'] = int(json_body['cloudnode_port'])
                    d['operational_state'] = cloud_verifier_common.CloudInstance_Operational_State.START
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
                    
                    new_instance = self.db.add_instance(instance_id,d)
                    
                    # don't allow overwriting
                    if new_instance is None:
                        common.echo_json_response(self, 409, "Node of uuid %s already exists"%(instance_id))
                        logger.warning("Node of uuid %s already exists"%(instance_id))
                    else:    
                        self.process_instance(new_instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE)
                        common.echo_json_response(self, 200, "Success")
                        logger.info('POST returning 200 response for adding instance id: ' + instance_id)
            else:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
        except Exception as e:
            common.echo_json_response(self, 400, "Exception error: %s"%e)
            logger.warning("POST returning 400 response. Exception error: %s"%e)
            logger.warning(traceback.format_exc())
        
        self.finish()
        

    @tornado.web.asynchronous                   
    def put(self):
        """This method handles the PUT requests to add instances to the Cloud Verifier. 
         
        Currently, only instances resources are available for PUTing, i.e. /instances. All other PUT uri's will return errors.
        instances requests require a json block sent in the body
        """
        try:
            rest_params = common.get_restful_params(self.request.uri)
            if rest_params is None:
                common.echo_json_response(self, 405, "Not Implemented: Use /instances/ interface")
                return
            
            if "instances" not in rest_params:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning('PUT returning 400 response. uri not supported: ' + self.request.path)
                return
            
            instance_id = rest_params["instances"]
            if instance_id is None:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")
            
            instance = self.db.get_instance(instance_id)
            if instance is not None:
                common.echo_json_response(self, 404, "instance id not found")
                logger.info('PUT returning 404 response. instance id: ' + instance_id + ' not found.')
                
            if "reactivate" in rest_params:
                instance['operational_state']=cloud_verifier_common.CloudInstance_Operational_State.START
                self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE)
                common.echo_json_response(self, 200, "Success")
                logger.info('PUT returning 200 response for instance id: ' + instance_id)
            elif "stop" in rest_params:
                # do stuff for terminate
                logger.debug("Stopping polling on %s"%instance_id)
                self.db.update_instance(instance_id,'operational_state',cloud_verifier_common.CloudInstance_Operational_State.TENANT_FAILED)
                common.echo_json_response(self, 200, "Success")
                logger.info('PUT returning 200 response for instance id: ' + instance_id)
            else:
                common.echo_json_response(self, 400, "uri not supported")
                logger.warning("PUT returning 400 response. uri not supported")
                    
        except Exception as e:
            common.echo_json_response(self, 400, "Exception error: %s"%e)
            logger.warning("PUT returning 400 response. Exception error: %s"%e)
            logger.warning(traceback.format_exc())
            
        
        self.finish()


    def invoke_get_quote(self, instance, need_pubkey):
        params = cloud_verifier_common.prepare_get_quote(instance)
        instance['operational_state'] = cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE
        client = tornado.httpclient.AsyncHTTPClient()
        
        partial_req = "1"
        if need_pubkey:
            partial_req = "0"
        
        url = "http://%s:%d/quotes/integrity?nonce=%s&mask=%s&vmask=%s&partial=%s"%(instance['ip'],instance['port'],params["nonce"],params["mask"],params['vmask'],partial_req) 
        # the following line adds the instance and params arguments to the callback as a convenience
        cb = functools.partial(self.on_get_quote_response, instance, url)
        client.fetch(url, callback=cb)
    
    def on_get_quote_response(self, instance, url, response):
        if instance is None:
            raise Exception("instance deleted while being processed")
        if response.error: 
            # this is a connection error, retry get quote
            if isinstance(response.error, IOError) or (isinstance(response.error, tornado.web.HTTPError) and response.error.code == 599):
                self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE_RETRY)
            else:
                #catastrophic error, do not continue
                error = "Unexpected Get Quote response error for cloud instance " + instance['instance_id']  + ", Error: " + str(response.error)
                logger.critical(error)
                self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.FAILED)
        else:
            try:
 
#                writeTime=False
#                with cloud_verifier_common.Timer() as t:
                    json_response = json.loads(response.body)

                    # validate the cloud node response
                    if cloud_verifier_common.process_quote_response(instance, json_response['results']):
                        #only write timing if the quote was successful
#                         if self.time_series_log_file_base_name is not None:
#                             self.time_series_log_file.write("%s\n" % time.time())
#                             self.time_series_log_file.flush()
#                         writeTime=True
                         
                        if instance['provide_V']:
                            self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V)
                        else:
                            self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE)
                    else:
                        self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.INVALID_QUOTE)
                        cloud_verifier_common.notifyError(instance)
 
#                 if self.get_q_log_file_base_name is not None and writeTime:
#                     self.get_q_log_file.write("%s\n" % t.secs)
#                     self.get_q_log_file.flush()  
                 
            except Exception as e:
                logger.debug(traceback.print_exc())
                logger.critical("Unexpected exception occurred in worker_get_quote.  Error: %s"%e )            



    def invoke_provide_v(self, instance):
        if instance['pending_event'] is not None:
            instance['pending_event'] = None
        v_json_message = cloud_verifier_common.prepare_v(instance)
        instance['operational_state'] = cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V
        client = tornado.httpclient.AsyncHTTPClient()
        url = "http://%s:%d/keys/vkey"%(instance['ip'],instance['port'])
        cb = functools.partial(self.on_provide_v_response, instance, url)
        client.fetch(url, method="POST", callback=cb, headers=None, body=v_json_message)
    
    def on_provide_v_response(self, instance, url_with_params, response):
        if instance is None:
            raise Exception("instance deleted while being processed")
        if response.error: 
            if isinstance(response.error, IOError) or (isinstance(response.error, tornado.web.HTTPError) and response.error.code == 599):
                self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V_RETRY)
            else:
                #catastrophic error, do not continue
                error = "Unexpected Provide V response error for cloud instance " + instance['instance_id']  + ", Error: " + str(response.error)
                logger.critical(error)
                self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.FAILED)
        else:
            self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE)
 
    def process_instance(self, instance, new_operational_state):
        try:
            if instance is None:
                #import traceback
                traceback.print_stack()
            main_instance_operational_state = instance['operational_state']
            stored_instance = self.db.get_instance(instance['instance_id'])
            
            # if the user did terminated this instance
            if stored_instance['operational_state'] == cloud_verifier_common.CloudInstance_Operational_State.TERMINATED:
                logger.warning("Instance %s terminated by user."%instance['instance_id'])
                if instance['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(instance['pending_event'])
                self.db.remove_instance(instance['instance_id'])
                return
            
            # if the user tells us to stop polling because the tenant quote check failed
            if stored_instance['operational_state']==cloud_verifier_common.CloudInstance_Operational_State.TENANT_FAILED:
                logger.warning("Instance %s has failed tenant quote.  stopping polling"%instance['instance_id'])
                if instance['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(instance['pending_event'])
                return
            
            # If failed during processing, log regardless and drop it on the floor
            # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).  
            if new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.FAILED or \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.INVALID_QUOTE:
                instance['operational_state'] = new_operational_state
                if instance['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(instance['pending_event'])
                self.db.overwrite_instance(instance['instance_id'], instance)
                logger.warning("Instance %s failed, stopping polling"%instance['instance_id'])
                return
            
            # propagate all state 
            self.db.overwrite_instance(instance['instance_id'], instance)
            
            # if new, get a quote
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.START and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE:
                instance['num_retries']=0
                self.invoke_get_quote(instance, True)
                return
            
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE and \
                (new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V): 
                instance['num_retries']=0
                self.invoke_provide_v(instance)
                return
            
            if (main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V or
               main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE) and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE: 
                instance['num_retries']=0
                interval = config.getfloat('cloud_verifier','quote_interval')
                
                if interval==0:
                    self.invoke_get_quote(instance, False)
                else:
                    #logger.debug("Setting up callback to check again in %f seconds"%interval)
                    # set up a call back to check again
                    cb = functools.partial(self.invoke_get_quote, instance, False)
                    pending = tornado.ioloop.IOLoop.current().call_later(interval,cb)
                    instance['pending_event'] = pending
                return
            
            maxr = config.getint('cloud_verifier','max_retries')
            retry = config.getfloat('cloud_verifier','retry_interval')
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE_RETRY:
                if instance['num_retries']>=maxr:
                    logger.warning("Instance %s was not reachable for quote in %d tries, setting state to FAILED"%(instance['instance_id'],maxr))
                    if instance['first_verified']: # only notify on previously good instances
                        cloud_verifier_common.notifyError(instance,'comm_error')
                    else:
                        logger.debug("Communication error for new node.  no notification will be sent")
                    self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.FAILED)
                else:
                    cb = functools.partial(self.invoke_get_quote, instance, True)
                    instance['num_retries']+=1
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(instance['ip'],instance['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return   
            
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V_RETRY:
                if instance['num_retries']>=maxr:
                    logger.warning("Instance %s was not reachable to provide v in %d tries, setting state to FAILED"%(instance['instance_id'],maxr))
                    cloud_verifier_common.notifyError(instance,'comm_error')
                    self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.FAILED)
                else:
                    cb = functools.partial(self.invoke_provide_v, instance)
                    instance['num_retries']+=1
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(instance['ip'],instance['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return
            
            print instance
            raise Exception("nothing should ever fall out of this!")
   
        except Exception as e:
            logger.warning("Polling thread Exception error: %s"%e)
            logger.warning("Polling thread trace: " + traceback.format_exc())        

def start_tornado(tornado_server, port):
    tornado_server.listen(port)
    print "Starting Torando on port " + str(port)
    tornado.ioloop.IOLoop.instance().start()
    print "Tornado finished"
     
def main(argv=sys.argv):
    """Main method of the Cloud Verifier Server.  This method is encapsulated in a function for packaging to allow it to be 
    called as a function by an external program."""

    config = ConfigParser.SafeConfigParser()
    config.read(common.CONFIG_FILE)
     
    cloudverifier_port = config.get('general', 'cloudverifier_port')
    
    db_filename = "%s/%s"%(common.WORK_DIR,config.get('cloud_verifier','db_filename'))
    db = cloud_verifier_common.init_db(db_filename)
    db.update_all_instances('operational_state', cloud_verifier_common.CloudInstance_Operational_State.SAVED)
    
    num = db.count_instances()
    if num>0:
        logger.info("Instance ids in db loaded from file: %s"%db.get_instance_ids())

    
    logger.info('Starting Cloud Verifier (tornado) on port ' + cloudverifier_port + ', use <Ctrl-C> to stop')

    app = tornado.web.Application([
        (r"/(?:v[0-9]/)?instances/.*", InstancesHandler,{'db':db}),
        (r".*", MainHandler),
        ])
    
    context = cloud_verifier_common.init_mtls()
    server = tornado.httpserver.HTTPServer(app,ssl_options=context)
    server.bind(int(cloudverifier_port), address='0.0.0.0')
    
    #after TLS is up, start revocation notifier
    if config.getboolean('cloud_verifier', 'revocation_notifier'):
        logger.info("Starting service for revocation notifications on port %s"%config.getint('general','revocation_notifier_port'))
        revocation_notifier.start_broker()
        
    server.start(config.getint('cloud_verifier','multiprocessing_pool_num_workers')) 
        
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
