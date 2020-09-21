'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Luke Hinds (lhinds@redhat.com), Red Hat, Inc.
'''

import http.client

from keylime import keylime_logging

# setup logging
logger = keylime_logging.init_logging('httpclient_requests')


def request(method, host, port, params=None, data=None, context=None,
            timeout=5):
    """http client connection handler

    :param method: Contains the method type (e.g. GET, POST)
    :param host: The host will be connected to
    :param port: The connection port
    :param params: The URL path (e.g /v1/agent/)
    :param data: The data to provide
    :param context: The SSL context
    :param timeout: Timeout for the http connection, in seconds.
    :returns: The http response or exception
    :note: to add more failure types, refer to https://docs.python.org/3/library/exceptions.html
    """
    if context is not None:
        conn = http.client.HTTPSConnection(
            host,
            port,
            context=context,
            timeout=timeout)
    else:
        conn = http.client.HTTPConnection(
            host,
            port,
            timeout=timeout)

    try:
        logger.debug(f"Making HTTP {method} request to {host}:{port}{params}")
        conn.request(method, params, body=data)
    except http.client.HTTPException as e:
        logger.error(f"HTTPException: {e}")
        return 500, str(e)
    except ConnectionError as e:
        logger.error(f"ConnectionError: {e}")
        return 503
    except TimeoutError as e:
        logger.error(f"TimeoutError: {e}")
        return 504
    response = conn.getresponse()
    return response
