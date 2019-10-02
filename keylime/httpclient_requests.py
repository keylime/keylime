import http.client

def request(method, url, port, params=None, data=None,context=None):
    """
    http client connection handler

    :param method: Contains the method type (e.g. GET, POST)
    :param url: Is the connection IP (could use a rename to `ip`)
    :param port: The connection port
    :param params: Is the url specifics (e.g /v1/agent/)
    :param data: The data to provide
    :param context: The SSL context
    :returns: The http response or exception
    :note: to add more failure types, refer to https://docs.python.org/3/library/exceptions.html
    """
    flag = False
    counter = 0
    if context is not None:
        conn =  http.client.HTTPSConnection(
            url,
            port,
            context=context,
            timeout=5)
    else:
        conn =  http.client.HTTPConnection(
            url,
            port,
            timeout=5)

    while True:
        counter += 1
        if data is not None:
            try:
                conn.request(method, params, data)
            except http.client.HTTPException as e:
                return(500, str(e))
            except ConnectionError:
                return(503)
            except TimeoutError:
                return(504)
        else:
            try:
                conn.request(method, params)
            except http.client.HTTPException as e:
                return(500, str(e))
            except ConnectionError:
                return(503)
            except TimeoutError:
                return(504)
        if counter>9:
           break
        response = conn.getresponse()
        return response
