import ssl
from typing import Any, Dict, Optional, Union

from tornado import httpclient
from tornado.httputil import HTTPHeaders

from keylime import json


class TornadoResponse:
    def __init__(self, code: int, body: Union[str, bytes]):
        self.status_code = code
        self.body = body


async def request(
    method: str,
    url: str,
    params: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    context: Optional[ssl.SSLContext] = None,
    headers: Optional[Union[Dict[str, str], HTTPHeaders]] = None,
    timeout: float = 60.0,
) -> TornadoResponse:

    http_client = httpclient.AsyncHTTPClient()
    if params is not None and len(list(params.keys())) > 0:
        url += "?"
        for key in list(params.keys()):
            url += f"{key}={params[key]}&"
        url = url[:-1]

    if context is not None:
        url = url.replace("http://", "https://", 1)

    # Convert dict to JSON before sending
    body: Optional[str]
    if isinstance(data, dict):
        body = json.dumps(data)
        if headers is None:
            headers = {}
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
    else:
        body = data

    try:
        req = httpclient.HTTPRequest(
            url=url,
            method=method,
            ssl_options=context,
            body=body,
            headers=headers,
            request_timeout=timeout,
        )
        response = await http_client.fetch(req)

    except httpclient.HTTPError as e:
        if e.response is None:
            return TornadoResponse(500, str(e))
        return TornadoResponse(e.response.code, e.response.body)
    except ConnectionError as e:
        return TornadoResponse(599, f"Connection error: {str(e)}")
    except ssl.SSLError as e:
        return TornadoResponse(599, f"SSL connection error: {str(e)}")
    except OSError as e:
        return TornadoResponse(599, f"TCP/IP Connection error: {str(e)}")
    except Exception as e:
        return TornadoResponse(599, f"General communication failure: {str(e)}")
    if response is None:
        return TornadoResponse(599, "Unspecified failure in tornado (empty http response)")
    return TornadoResponse(response.code, response.body)
