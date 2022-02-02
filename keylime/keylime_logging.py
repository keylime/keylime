"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
"""

import os

import logging.config

from keylime import config


LOG_TO_FILE = ['registrar', 'provider_registrar', 'cloudverifier']
LOG_TO_STREAM = ['tenant_webapp']
LOGDIR = os.getenv('KEYLIME_LOGDIR', '/var/log/keylime')
# not clear that this works right.  console logging may not work
if not config.REQUIRE_ROOT:
    LOGSTREAM = './keylime-stream.log'
else:
    LOGSTREAM = LOGDIR + '/keylime-stream.log'

logging.config.fileConfig(config.get_config())


def set_log_func(loglevel, logger):
    log_func = logger.info

    if loglevel == logging.CRITICAL:
        log_func = logger.critical
    elif loglevel == logging.ERROR:
        log_func = logger.error
    elif loglevel == logging.WARNING:
        log_func = logger.warning
    elif loglevel == logging.INFO:
        log_func = logger.info
    elif loglevel == logging.DEBUG:
        log_func = logger.debug

    return log_func


def log_http_response(logger, loglevel, response_body):
    """Takes JSON response payload and logs error info"""
    if None in [response_body, logger]:
        return False

    log_func = set_log_func(loglevel, logger)

    matches = ["results", "code", "status"]
    if all(x in response_body for x in matches):
        log_func("Response code %s: %s" %
                 (response_body["code"], response_body["status"]))
    else:
        logger.error("Error: unexpected or malformed http response payload")
        return False

    return True


def init_logging(loggername):
    logger = logging.getLogger("keylime.%s" % loggername)
    logging.getLogger("requests").setLevel(logging.WARNING)
    mainlogger = logging.getLogger("keylime")
    basic_formatter = logging.Formatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s')
    if loggername in LOG_TO_FILE:
        logfilename = os.path.join(LOGDIR, f"{loggername}.log")
        if not os.path.exists(LOGDIR):
            os.makedirs(LOGDIR, 0o750)
        fh = logging.FileHandler(logfilename)
        fh.setLevel(logger.getEffectiveLevel())
        fh.setFormatter(basic_formatter)
        mainlogger.addHandler(fh)

    if loggername in LOG_TO_STREAM:
        fh = logging.FileHandler(filename=LOGSTREAM, mode='w')
        fh.setLevel(logger.getEffectiveLevel())
        fh.setFormatter(basic_formatter)
        mainlogger.addHandler(fh)

    return logger
