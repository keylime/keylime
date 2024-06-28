import functools
import os
import signal
import sys
import threading
import time
from multiprocessing import Process
from typing import Any, Callable, Dict, Optional, Set

import requests

from keylime import config, crypto, json, keylime_logging, web_util
from keylime.common import retry
from keylime.requests_client import RequestsClient

logger = keylime_logging.init_logging("revocation_notifier")
broker_proc: Optional[Process] = None

_SOCKET_PATH = "/var/run/keylime/keylime.verifier.ipc"


# return the revocation notification methods for cloud verifier
def get_notifiers() -> Set[str]:
    notifiers = set(config.getlist("verifier", "enabled_revocation_notifications", section="revocations"))
    return notifiers.intersection({"zeromq", "webhook", "agent"})


def start_broker() -> None:
    assert "zeromq" in get_notifiers()
    try:
        import zmq  # pylint: disable=import-outside-toplevel
    except ImportError as error:
        raise Exception("install PyZMQ for 'zeromq' in 'enabled_revocation_notifications' option") from error

    def worker() -> None:
        def sig_handler(*_: Any) -> None:
            sys.exit(0)

        # do not receive signals form the parent process
        os.setpgrp()
        signal.signal(signal.SIGTERM, sig_handler)
        dir_name = os.path.dirname(_SOCKET_PATH)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name, 0o700)
        else:
            if os.stat(dir_name).st_mode & 0o777 != 0o700:
                msg = f"{dir_name} present with wrong permissions"
                logger.error(msg)
                raise Exception(msg)

        context = zmq.Context(1)  # pylint: disable=abstract-class-instantiated
        frontend = context.socket(zmq.SUB)
        frontend.bind(f"ipc://{_SOCKET_PATH}")

        frontend.setsockopt(zmq.SUBSCRIBE, b"")

        # Socket facing services
        backend = context.socket(zmq.PUB)
        backend.bind(
            f"tcp://{config.get('verifier', 'zmq_ip', section='revocations')}:"
            f"{config.getint('verifier', 'zmq_port', section='revocations')}"
        )
        try:
            zmq.device(zmq.FORWARDER, frontend, backend)
        except (KeyboardInterrupt, SystemExit):
            context.destroy()

    global broker_proc
    broker_proc = Process(target=worker, name="zeroMQ")
    broker_proc.start()


def stop_broker() -> None:
    if broker_proc is not None:
        # Remove the socket file before  we kill the process
        if os.path.exists(f"ipc://{_SOCKET_PATH}"):
            os.remove(f"ipc://{_SOCKET_PATH}")
        logger.info("Stopping revocation notifier...")
        broker_proc.terminate()
        broker_proc.join(5)
        if broker_proc.is_alive() and sys.version_info >= (3, 7):
            logger.debug("Killing revocation notifier because it did not terminate after 5 seconds...")
            broker_proc.kill()  # pylint: disable=E1101


def notify(tosend: Dict[str, Any]) -> None:
    assert "zeromq" in get_notifiers()
    try:
        import zmq  # pylint: disable=import-outside-toplevel
    except ImportError as error:
        raise Exception("install PyZMQ for 'zeromq' in 'revocation_notifier' option") from error

    # python-requests internally uses either simplejson (preferred) or
    # the built-in json module, and when it is using the built-in one,
    # it may encounter difficulties handling bytes instead of strings.
    # To avoid such issues, let's convert `tosend' to str beforehand.
    tosend = json.bytes_to_str(tosend)

    def worker(tosend: Dict[str, Any]) -> None:
        context = zmq.Context()  # pylint: disable=abstract-class-instantiated
        mysock = context.socket(zmq.PUB)
        mysock.connect(f"ipc://{_SOCKET_PATH}")
        # wait 100ms for connect to happen
        time.sleep(0.2)
        # now send it out via 0mq
        logger.info("Sending revocation event to listening nodes...")
        for i in range(config.getint("verifier", "max_retries")):
            try:
                mysock.send_string(json.dumps(tosend))
                break
            except Exception as e:
                interval = config.getfloat("verifier", "retry_interval")
                exponential_backoff = config.getboolean("verifier", "exponential_backoff")
                next_retry = retry.retry_time(exponential_backoff, interval, i, logger)
                logger.debug(
                    "Unable to publish revocation message %d times, trying again in %f seconds: %s",
                    i,
                    next_retry,
                    e,
                )
                time.sleep(next_retry)
        mysock.close()

    cb = functools.partial(worker, tosend)
    t = threading.Thread(target=cb)
    t.start()


def notify_webhook(tosend: Dict[str, Any]) -> None:
    url = config.get("verifier", "webhook_url", section="revocations", fallback="")
    # Check if a url was specified
    if url == "":
        return

    # Similarly to notify(), let's convert `tosend' to str to prevent
    # possible issues with json handling by python-requests.
    tosend = json.bytes_to_str(tosend)

    def worker_webhook(tosend: Dict[str, Any], url: str) -> None:
        interval = config.getfloat("verifier", "retry_interval")
        exponential_backoff = config.getboolean("verifier", "exponential_backoff")

        max_retries = config.getint("verifier", "max_retries")
        if max_retries <= 0:
            logger.info("Invalid value found in 'max_retries' option for verifier, using default value")
            max_retries = 5

        # Get TLS options from the configuration
        (cert, key, trusted_ca, key_password), verify_server_cert = web_util.get_tls_options(
            "verifier", is_client=True, logger=logger
        )

        # Generate the TLS context using the obtained options
        tls_context = web_util.generate_tls_context(cert, key, trusted_ca, key_password, is_client=True, logger=logger)

        logger.info("Sending revocation event via webhook to %s ...", url)
        for i in range(max_retries):
            next_retry = retry.retry_time(exponential_backoff, interval, i, logger)

            with RequestsClient(
                url,
                verify_server_cert,
                tls_context,
            ) as client:
                try:
                    res = client.post("", json=tosend, timeout=5)
                except requests.exceptions.SSLError as ssl_error:
                    if "TLSV1_ALERT_UNKNOWN_CA" in str(ssl_error):
                        logger.warning(
                            "Keylime does not recognize certificate from peer. Check if verifier 'trusted_server_ca' is configured correctly"
                        )

                    raise ssl_error from ssl_error

                if res and res.status_code in [200, 202]:
                    break

                logger.debug(
                    "Unable to publish revocation message %d times via webhook, "
                    "trying again in %d seconds. "
                    "Server returned status code: %s",
                    i + 1,
                    next_retry,
                    res.status_code,
                )

                time.sleep(next_retry)

    w = functools.partial(worker_webhook, tosend, url)
    t = threading.Thread(target=w, daemon=True)
    t.start()


cert_key = None


def process_revocation(
    revocation: Dict[str, Any],
    callback: Callable[[Dict[str, Any]], None],
    cert_path: str,
) -> None:
    global cert_key

    if cert_key is None:
        # load up the CV signing public key
        if cert_path is not None and os.path.exists(cert_path):
            logger.info("Lazy loading the revocation certificate from %s", cert_path)
            with open(cert_path, "rb") as f:
                certpem = f.read()
            cert_key = crypto.x509_import_pubkey(certpem)

    if cert_key is None:
        logger.warning(
            "Unable to check signature of revocation message: %s not available",
            cert_path,
        )
    elif "signature" not in revocation or revocation["signature"] == "none":
        logger.warning("No signature on revocation message from server")
    elif not crypto.rsa_verify(
        cert_key,
        revocation["msg"].encode("utf-8"),
        revocation["signature"].encode("utf-8"),
    ):
        logger.error("Invalid revocation message siganture %s", revocation)
    else:
        message = json.loads(revocation["msg"])
        logger.debug("Revocation signature validated for revocation: %s", message)
        callback(message)
