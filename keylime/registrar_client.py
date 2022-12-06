import logging
import ssl
import sys
from typing import Any, Dict, Optional, Union

from keylime import api_version as keylime_api_version
from keylime import crypto, json, keylime_logging
from keylime.requests_client import RequestsClient

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

if sys.version_info >= (3, 11):
    from typing import NotRequired
else:
    from typing_extensions import NotRequired


class RegistrarData(TypedDict):
    ip: Optional[str]
    port: Optional[str]
    regcount: int
    mtls_cert: Optional[str]
    aik_tpm: str
    ek_tpm: str
    ekcert: Optional[str]
    provider_keys: NotRequired[Dict[str, str]]


logger = keylime_logging.init_logging("registrar_client")
api_version = keylime_api_version.current_version()


def getData(
    registrar_ip: str, registrar_port: str, agent_id: str, tls_context: Optional[ssl.SSLContext]
) -> Optional[RegistrarData]:
    """
    Get the agent data from the registrar.

    This is called by the tenant code

    :returns: JSON structure containing the agent data
    """
    # make absolutely sure you don't ask for data that contains AIK keys unauthenticated
    if not tls_context:
        raise Exception("It is unsafe to use this interface to query AIKs without server-authenticated TLS.")

    response = None
    try:
        client = RequestsClient(f"{registrar_ip}:{registrar_port}", True, tls_context=tls_context)
        response = client.get(f"/v{api_version}/agents/{agent_id}")
        response_body = response.json()

        if response.status_code == 404:
            logger.critical(
                "Error: could not get agent %s data from Registrar Server: %s", agent_id, response.status_code
            )
            keylime_logging.log_http_response(logger, logging.CRITICAL, response_body)
            return None

        if response.status_code != 200:
            logger.critical("Error: unexpected http response code from Registrar Server: %s", response.status_code)
            keylime_logging.log_http_response(logger, logging.CRITICAL, response_body)
            return None

        # Check for all values that are consumed by other parts of Keylime
        if "results" not in response_body:
            logger.critical("Error: unexpected http response body from Registrar Server: %s", response.status_code)
            return None

        if "aik_tpm" not in response_body["results"]:
            logger.critical("Error: did not receive AIK from Registrar Server.")
            return None

        if "regcount" not in response_body["results"]:
            logger.critical("Error: did not receive regcount from Registrar Server.")
            return None

        if "ek_tpm" not in response_body["results"]:
            logger.critical("Error: did not receive EK from Registrar Server.")
            return None

        if "ip" not in response_body["results"]:
            logger.critical("Error: did not receive IP from Registrar Server.")
            return None

        if "port" not in response_body["results"]:
            logger.critical("Error: did not receive port from Registrar Server.")
            return None

        r = response_body["results"]
        res: RegistrarData = {
            "aik_tpm": r["aik_tpm"],
            "regcount": r["regcount"],
            "ek_tpm": r["ek_tpm"],
            "ip": r["ip"],
            "port": r["port"],
            "mtls_cert": r.get("mtls_cert"),
            "ekcert": r.get("ekcert"),
        }
        if "provider_keys" in r:
            res["provider_keys"] = r["provider_keys"]

        return res

    except AttributeError as e:
        if response and response.status_code == 503:
            logger.critical("Error: the registrar is not available at %s:%s", registrar_ip, registrar_port)
        else:
            logger.exception(e)

    except Exception as e:
        logger.exception(e)

    return None


def doRegisterAgent(
    registrar_ip: str,
    registrar_port: str,
    agent_id: str,
    ek_tpm: bytes,
    ekcert: Optional[Union[bytes, str]],
    aik_tpm: bytes,
    mtls_cert: Optional[bytes] = None,
    contact_ip: Optional[str] = None,
    contact_port: Optional[str] = None,
) -> Optional[str]:
    """
    Register the agent with the registrar

    This is called by the agent code

    :returns: base64 encoded blob containing the aik_tpm name and a challenge. Is encrypted with ek_tpm.
    """

    data: Dict[str, Any] = {
        "ekcert": ekcert,
        "aik_tpm": aik_tpm,
    }
    if ekcert is None or ekcert == "emulator":
        data["ek_tpm"] = ek_tpm

    if mtls_cert is not None:
        data["mtls_cert"] = mtls_cert
    else:
        data["mtls_cert"] = "disabled"
        logger.error("Most actions require the agent to have mTLS enabled, but no cert was provided!")
    if contact_ip is not None:
        data["ip"] = contact_ip
    if contact_port is not None:
        data["port"] = contact_port

    response = None
    try:
        # The agent accesses the registrar without mTLS, meaning without client
        # certificate
        # TODO the registrar could be accessed using TLS, but without client
        # certificate verification. Currently it is accessed without TLS at all
        client = RequestsClient(f"{registrar_ip}:{registrar_port}", False)
        response = client.post(f"/v{api_version}/agents/{agent_id}", data=json.dumps(data))
        response_body = response.json()

        if response.status_code != 200:
            logger.error("Error: unexpected http response code from Registrar Server: %s", response.status_code)
            keylime_logging.log_http_response(logger, logging.ERROR, response_body)
            return None

        logger.info("Agent registration requested for %s", agent_id)

        if "results" not in response_body:
            logger.critical("Error: unexpected http response body from Registrar Server: %s", response.status_code)
            return None

        if "blob" not in response_body["results"]:
            logger.critical("Error: did not receive blob from Registrar Server: %s", response.status_code)
            return None

        return str(response_body["results"]["blob"])
    except Exception as e:
        if response and response.status_code == 503:
            logger.error("Agent cannot establish connection to registrar at %s:%s", registrar_ip, registrar_port)
            sys.exit()
        else:
            logger.exception(e)

    return None


def doActivateAgent(registrar_ip: str, registrar_port: str, agent_id: str, key: bytes) -> bool:
    """
    Activate the agent with the registrar

    Contact the registrar to inform the agent has the derived key

    This is called by the agent code

    :returns:
    """
    data = {
        "auth_tag": crypto.do_hmac(key, agent_id),
    }

    # The agent accesses the registrar without mTLS, meaning without client
    # certificate
    # TODO the registrar could be accessed using TLS, but without client
    # certificate verification. Currently it is accessed without TLS at all
    client = RequestsClient(f"{registrar_ip}:{registrar_port}", False)
    response = client.put(
        f"/v{api_version}/agents/{agent_id}/activate",
        data=json.dumps(data),
    )
    response_body = response.json()

    if response.status_code == 200:
        logger.info("Registration activated for agent %s.", agent_id)
        return True

    logger.error("Error: unexpected http response code from Registrar Server: %s", str(response.status_code))
    keylime_logging.log_http_response(logger, logging.ERROR, response_body)
    return False


def doRegistrarDelete(
    registrar_ip: str, registrar_port: str, agent_id: str, tls_context: Optional[ssl.SSLContext]
) -> Dict[str, Any]:
    """
    Delete the given agent from the registrar.

    This is called by the tenant code

    :returns: The request response body
    """

    client = RequestsClient(f"{registrar_ip}:{registrar_port}", True, tls_context=tls_context)
    response = client.delete(f"/v{api_version}/agents/{agent_id}")
    response_body: Dict[str, Any] = response.json()

    if response.status_code == 200:
        logger.debug("Registrar deleted.")
    else:
        logger.warning("Status command response: %s Unexpected response from registrar.", response.status_code)
        keylime_logging.log_http_response(logger, logging.WARNING, response_body)

    return response_body


def doRegistrarList(
    registrar_ip: str, registrar_port: str, tls_context: Optional[ssl.SSLContext]
) -> Optional[Dict[str, Any]]:
    """
    Get the list of registered agents from the registrar.

    This is called by the tenant code

    :returns: The request response body
    """
    client = RequestsClient(f"{registrar_ip}:{registrar_port}", True, tls_context=tls_context)
    response = client.get(f"/v{api_version}/agents/")
    response_body: Dict[str, Any] = response.json()

    if response.status_code != 200:
        logger.warning("Registrar returned: %s Unexpected response from registrar.", response.status_code)
        keylime_logging.log_http_response(logger, logging.WARNING, response_body)
        return None

    return response_body
