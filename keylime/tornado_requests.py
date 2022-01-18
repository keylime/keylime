#!/usr/bin/env python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from tornado import httpclient


async def request(method, url, params=None, data=None, context=None, headers=None):

    http_client = httpclient.AsyncHTTPClient()
    if params is not None and len(list(params.keys())) > 0:
        url += '?'
        for key in list(params.keys()):
            url += f"{key}={params[key]}&"
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
            return TornadoResponse(500, str(e))

        return TornadoResponse(e.response.code, e.response.body)
    except ConnectionError as e:
        return TornadoResponse(599, "Connection error: %s" % e)
    if response is None:
        return None
    return TornadoResponse(response.code, response.body)


class TornadoResponse:

    def __init__(self, code, body):
        self.status_code = code
        self.body = body
