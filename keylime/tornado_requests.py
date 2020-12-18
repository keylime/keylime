#!/usr/bin/env python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import json
import yaml
try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

from tornado import httpclient


async def request(method, url, params=None, data=None, context=None, headers=None):

    http_client = httpclient.AsyncHTTPClient()
    if params is not None and len(list(params.keys())) > 0:
        url += '?'
        for key in list(params.keys()):
            url += "%s=%s&" % (key, params[key])
        url = url[:-1]

    if context is not None:
        url = url.replace('http://', 'https://', 1)

    try:
        req = httpclient.HTTPRequest(url=url,
                                     method=method,
                                     ssl_options=context,
                                     body=data,
                                     headers=headers)
        response = await http_client.fetch(req)

    except httpclient.HTTPError as e:
        if e.response is None:
            return tornado_response(500, str(e))

        return tornado_response(e.response.code, e.response.body)
    except ConnectionError as e:
        return tornado_response(599, "Connection error: %s" % e)
    if response is None:
        return None
    return tornado_response(response.code, response.body)


def is_refused(e):
    if hasattr(e, 'strerror'):
        return "Connection refused" in e.strerror

    return False


class tornado_response():

    def __init__(self, code, body):
        self.status_code = code
        self.body = body

    def json(self):
        try:
            retval = json.loads(self.body)

        except Exception as e:
            retval = [self.body, str(e)]
        return retval

    def yaml(self):
        try:
            retval = yaml.load(self.body, Loader=SafeLoader)
        except Exception as e:
            retval = [self.body, str(e)]
        return retval
