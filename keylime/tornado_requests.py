'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2016 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''
from tornado import httpclient
import json

def request(method,url,params=None,data=None,context=None):
    http_client = httpclient.HTTPClient()        
    if params is not None and len(list(params.keys()))>0:
        url+='?'
        for key in list(params.keys()):
            url+="%s=%s&"%(key,params[key])
        url=url[:-1]
    
    if context is not None:
        url = url.replace('http://','https://',1)
    try:
        request = httpclient.HTTPRequest(url=url,
                                         method =method,
                                         ssl_options=context,
                                         body=data)
        response = http_client.fetch(request)
        http_client.close()
    except httpclient.HTTPError as e:
        if e.response is None:
            return tornado_response(500,str(e))
        
        return tornado_response(e.response.code,e.response.body)
    if response is None:
        return None
    return tornado_response(response.code,response.body)

def is_refused(e):
    if hasattr(e,'strerror'):
        return "Connection refused" in e.strerror
    else:
        return False

class tornado_response():
    
    def __init__(self,code,body):
        self.status_code = code
        self.body = body
        
    def json(self):
        try:
            retval =  json.loads(self.body)
        except Exception as e:
            retval = [self.body,str(e)]
        return retval