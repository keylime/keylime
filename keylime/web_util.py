import http.client
import os
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler

import tornado.web

from keylime import config, ca_util, json


def init_mtls(section='cloud_verifier', generatedir='cv_ca', logger=None):
    """
    Generates mTLS SSLContext for either the cloud verifier or the registrar.
    """

    if not config.getboolean('general', "enable_tls"):
        logger.warning(
            "Warning: TLS is currently disabled, keys will be sent in the clear! This should only be used for testing.")
        return None

    if logger:
        logger.info("Setting up TLS...")
    my_cert = config.get(section, 'my_cert')
    ca_cert = config.get(section, 'ca_cert')
    my_priv_key = config.get(section, 'private_key')
    my_key_pw = config.get(section, 'private_key_pw')
    tls_dir = config.get(section, 'tls_dir')

    if tls_dir == 'generate':
        if my_cert != 'default' or my_priv_key != 'default' or ca_cert != 'default':
            raise Exception(
                "To use tls_dir=generate, options ca_cert, my_cert, and private_key must all be set to 'default'")

        if generatedir[0] != '/':
            generatedir = os.path.abspath(os.path.join(config.WORK_DIR,
                                                       generatedir))
        tls_dir = generatedir
        ca_path = "%s/cacert.crt" % (tls_dir)
        if os.path.exists(ca_path):
            if logger:
                logger.info("Existing CA certificate found in %s, not generating a new one", tls_dir)
        else:
            if logger:
                logger.info("Generating a new CA in %s and a client certificate for connecting", tls_dir)
                logger.info("use keylime_ca -d %s to manage this CA", tls_dir)
            if not os.path.exists(tls_dir):
                os.makedirs(tls_dir, 0o700)
            if my_key_pw == 'default':
                if logger:
                    logger.warning("CAUTION: using default password for CA, please set private_key_pw to a strong password")
            ca_util.setpassword(my_key_pw)
            ca_util.cmd_init(tls_dir)
            ca_util.cmd_mkcert(tls_dir, socket.gethostname())
            ca_util.cmd_mkcert(tls_dir, 'client')

    if tls_dir == 'CV':
        if section != 'registrar':
            raise Exception(
                "You only use the CV option to tls_dir for the registrar not %s" % section)
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, 'cv_ca'))
        if not os.path.exists("%s/cacert.crt" % (tls_dir)):
            raise Exception(
                "It appears that the verifier has not yet created a CA and certificates, please run the verifier first")

    # if it is relative path, convert to absolute in WORK_DIR
    if tls_dir[0] != '/':
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    if ca_cert == 'default':
        ca_path = os.path.join(tls_dir, "cacert.crt")
    elif not os.path.isabs(ca_cert):
        ca_path = os.path.join(tls_dir, ca_cert)
    else:
        ca_path = ca_cert

    if my_cert == 'default':
        my_cert = os.path.join(tls_dir, f"{socket.gethostname()}-cert.crt")
    elif not os.path.isabs(my_cert):
        my_cert = os.path.join(tls_dir, my_cert)
    else:
        pass

    if my_priv_key == 'default':
        my_priv_key = os.path.join(tls_dir,
                                   f"{socket.gethostname()}-private.pem")
    elif not os.path.isabs(my_priv_key):
        my_priv_key = os.path.join(tls_dir, my_priv_key)

    check_client_cert = (config.has_option(section, 'check_client_cert')
                         and config.getboolean(section, 'check_client_cert'))
    context = generate_mtls_context(my_cert, my_priv_key, ca_path, check_client_cert, my_key_pw, logger)

    return context


def generate_mtls_context(cert_path, private_key_path, ca_path, verify_client_cert=True,
                          private_key_password=None, logger=None):
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if sys.version_info >= (3, 7):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.options &= ~ssl.OP_NO_TLSv1_2
        context.load_verify_locations(cafile=ca_path)
        context.load_cert_chain(
            certfile=cert_path, keyfile=private_key_path, password=private_key_password)
        if verify_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
    except ssl.SSLError as exc:
        if exc.reason == 'EE_KEY_TOO_SMALL' and logger:
            logger.error('Higher key strength is required for keylime '
                         'running on this system. If keylime is responsible '
                         'to generate the certificate, please raise the value '
                         'of configuration option [ca]cert_bits, remove '
                         'generated certificate and re-run keylime service')
        raise exc

    return context


def echo_json_response(handler, code, status=None, results=None):
    """Takes a json package and returns it to the user w/ full HTTP headers"""
    if handler is None or code is None:
        return False
    if status is None:
        status = http.client.responses[code]
    if results is None:
        results = {}

    json_res = {'code': code, 'status': status, 'results': results}
    json_response = json.dumps(json_res)
    json_response = json_response.encode('utf-8')

    if isinstance(handler, BaseHTTPRequestHandler):
        handler.send_response(code)
        handler.send_header('Content-Type', 'application/json')
        handler.end_headers()
        handler.wfile.write(json_response)
        return True
    if isinstance(handler, tornado.web.RequestHandler):
        handler.set_status(code)
        handler.set_header('Content-Type', 'application/json')
        handler.write(json_response)
        handler.finish()
        return True

    return False
