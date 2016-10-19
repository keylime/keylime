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

is_closing = False

config = ConfigParser.SafeConfigParser()
config.read(common.CONFIG_FILE)

def try_exit(): 
    global is_closing
    if is_closing:
        # clean up here
        tornado.ioloop.IOLoop.instance().stop()
        logger.info('exit success')

def do_shutdown(servers,result_queue_thread):
        result_queue_thread.stop()
        for server in servers:
            server.shutdown()

class BaseHandler(tornado.web.RequestHandler):

    def write_error(self, status_code, **kwargs):

        self.set_header('Content-Type', 'text/json')
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            self.finish(json.dumps({
                'error': {
                    'code': status_code,
                    'message': self._reason,
                    'traceback': lines,
                }
            }))
        else:
            self.finish(json.dumps({
                'error': {
                    'code': status_code,
                    'message': self._reason,
                }
            }))

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_status(501,"Not Implemented")
        self.write("Use /v1/instances/ interface instead\n")
            
class InstancesHandler(BaseHandler):       
    def head(self):
        """HEAD not supported"""                  
        self.set_status(501, "Not Implemented")
        self.write("Head not available")
  
    def get(self):
        """This method handles the GET requests to retrieve status on instances from the Cloud Verifier. 
        
        Currently, only instances resources are available for GETing, i.e. /v1/instances. All other GET uri's 
        will return errors. instances requests require a single instance_id parameter which identifies the 
        instance to be returned. If the instance_id is not found, a 404 response is returned.  If the instance_id
        was not found, it either completed successfully, or failed.  If found, the instance_id is still polling 
        to contact the Cloud Node. 
        """
        instance_id = self.get_argument("instance_id", default=None, strip=True)
        if instance_id is not None:
            instance = cloud_verifier_common.get_instance(instance_id)
            if instance != None:
                response = cloud_verifier_common.process_get_status(instance)
                self.set_status(200)
                self.write(response)
                logger.info('GET returning 200 response for instance_id: ' + instance_id)
                 
            else:
                logger.info('GET returning 404 response. instance_id: ' + instance_id + ' not found.')
                self.set_status(404)                       
        else:
            # return the available keys in the DB
            json_response = cloud_verifier_common.get_instance_ids()
            self.set_status(200)
            #Since the data is essentially a string, set the content type explicitly 
            self.set_header('Content-Type', 'application/json')
            print json_response
            self.write(json_response)
            logger.info('GET returning 200 response for instance_id list')
            
    def delete(self):
        """This method handles the DELETE requests to remove instances from the Cloud Verifier. 
         
        Currently, only instances resources are available for DELETEing, i.e. /v1/instances. All other DELETE uri's will return errors.
        instances requests require a single instance_id parameter which identifies the instance to be deleted.    
        """
        instance_id = self.get_argument("instance_id", default=None, strip=True)
        if instance_id is not None:
            if cloud_verifier_common.terminate_instance(instance_id):
                self.set_status(200)
                logger.info('DELETE returning 200 response for instance_id: ' + instance_id)
            else:
                self.set_status(404)
                logger.info('DELETE returning 404 response. instance_id: ' + instance_id + ' not found.')
                 
        else:
            self.set_status(400)
            logger.warning('DELETE returning 400 response. uri not supported: ' + self.path)
            
    @tornado.web.asynchronous                   
    def post(self):
        """This method handles the POST requests to add instances to the Cloud Verifier. 
         
        Currently, only instances resources are available for POSTing, i.e. /v1/instances. All other POST uri's will return errors.
        instances requests require a json block sent in the body
        """
        try:
            instance_id = self.get_argument("instance_id", default=None, strip=True)
            
            if instance_id is not None: # this is for reactivating 
                new_instance = cloud_verifier_common.get_instance(instance_id)
                if new_instance is not None:
                    new_instance['operational_state']=cloud_verifier_common.CloudInstance_Operational_State.START
                    self.process_instance(new_instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE)
                    self.set_status(200)
                    logger.info('DELETE returning 200 response for instance_id: ' + instance_id)
                else:
                    self.set_status(404)
                    logger.info('DELETE returning 404 response. instance_id: ' + instance_id + ' not found.')
            else: # this is for new items
                content_length = len(self.request.body)
                if content_length==0:
                    self.set_status(400)
                    logger.warning('POST returning 400 response. Expected non zero content length.')
                else:
                    json_body = json.loads(self.request.body)
                    new_instance = cloud_verifier_common.add_instance(json_body)
                    
                    # don't allow overwriting
                    if new_instance is None:
                        raise Exception("Node of uuid %s already exists"%(json_body.get('instance_id','unknown')))
                        
                    self.process_instance(new_instance, cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE)
                     
                    self.set_status(200)
                    logger.info('POST returning 200 response for adding instance_id: ' + json_body['instance_id'])                                  
        except Exception as e:
            self.set_status(400)
            logger.warning("POST returning 400 response. Exception error: %s"%e)
            logger.warning(traceback.format_exc())
        
        self.finish()

    def invoke_get_quote(self, instance):        
        params = cloud_verifier_common.prepare_get_quote(instance)
        instance['operational_state'] = cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE
        client = tornado.httpclient.AsyncHTTPClient()
        url = "http://%s:%d/v1/quotes/cloudverifier"%(instance['ip'],instance['port']) 
        url_with_params = url_concat(url, params)
        # the following line adds the instance and params arguments to the callback as a convenience
        cb = functools.partial(self.on_get_quote_response, instance, url_with_params)
        client.fetch(url_with_params, callback=cb)
    
    def on_get_quote_response(self, instance, url_with_params, response):
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
                    if cloud_verifier_common.process_quote_response(instance, json_response, config):
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
                        cloud_verifier_common.handleVerificationError(instance)
 
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
        url = "http://%s:%d/v1/quotes/cloudverifier"%(instance['ip'],instance['port'])
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
            stored_instance = cloud_verifier_common.get_instance(instance['instance_id'])
            
            # if the user did terminated this instance
            if stored_instance['operational_state'] == cloud_verifier_common.CloudInstance_Operational_State.TERMINATED:
                logger.warning("Instance %s terminated by user."%instance['instance_id'])
                if instance['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(instance['pending_event'])
                cloud_verifier_common.remove_instance(instance['instance_id'])
                return
            
            # If failed during processing, log regardless and drop it on the floor
            # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).  
            if new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.FAILED or \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.INVALID_QUOTE:
                instance['operational_state'] = new_operational_state
                if instance['pending_event'] is not None:
                    tornado.ioloop.IOLoop.current().remove_timeout(instance['pending_event'])
                cloud_verifier_common.overwrite_instance(instance['instance_id'], instance)
                logger.warning("Instance %s failed, stopping polling"%instance['instance_id'])
                return
            
            # propagate all state 
            cloud_verifier_common.overwrite_instance(instance['instance_id'], instance)
            
            # if new, get a quote
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.START and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE:
                instance['num_retries']=0
                self.invoke_get_quote(instance)
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
                    self.invoke_get_quote(instance)
                else:
                    #logger.debug("Setting up callback to check again in %f seconds"%interval)
                    # set up a call back to check again
                    cb = functools.partial(self.invoke_get_quote, instance)
                    pending = tornado.ioloop.IOLoop.current().call_later(interval,cb)
                    instance['pending_event'] = pending
                return
            
            maxr = config.getint('cloud_verifier','max_retries')
            retry = config.getfloat('cloud_verifier','retry_interval')
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.GET_QUOTE_RETRY:
                if instance['num_retries']>=maxr:
                    logger.warning("Instance %s was not reachable in %d tries, setting state to FAILED"%(instance['instance_id'],maxr))
                    self.process_instance(instance, cloud_verifier_common.CloudInstance_Operational_State.FAILED)
                else:
                    cb = functools.partial(self.invoke_get_quote, instance)
                    instance['num_retries']+=1
                    logger.info("connection to %s refused after %d/%d tries, trying again in %f seconds"%(instance['ip'],instance['num_retries'],maxr,retry))
                    tornado.ioloop.IOLoop.current().call_later(retry,cb)
                return   
            
            if main_instance_operational_state == cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V and \
                new_operational_state == cloud_verifier_common.CloudInstance_Operational_State.PROVIDE_V_RETRY:
                if instance['num_retries']>=maxr:
                    logger.warning("Instance %s was not reachable in %d tries, setting state to FAILED"%(instance['instance_id'],maxr))
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
    cloud_verifier_common.init_db(db_filename)
    
    cloud_verifier_common.set_saved()
    num = cloud_verifier_common.count_instances()
    if num>0:
        logger.info("Instance ids in db loaded from file: %s"%cloud_verifier_common.get_instance_ids())
    
    logger.info('Starting Cloud Verifier (tornado) on port ' + cloudverifier_port + ', use <Ctrl-C> to stop')

    app = tornado.web.Application([
        (r"/", MainHandler),                      
        (r"/v1/instances", InstancesHandler),
        ])
    
    context = cloud_verifier_common.init_tls(config)
    server = tornado.httpserver.HTTPServer(app,ssl_options=context)
    server.bind(int(cloudverifier_port), address='0.0.0.0')
    server.start(config.getint('cloud_verifier','multiprocessing_pool_num_workers')) 
    tornado.ioloop.IOLoop.current().start()

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
