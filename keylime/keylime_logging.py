import os.path
from keylime import common
import sys
import logging.config

def log_http_response(logger, loglevel, response_body):
    """Takes JSON response payload and logs error info"""
    if response_body is None:
        return False
    if logger is None:
        return False

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

    if "results" in response_body and "code" in response_body and "status" in response_body:
        log_func("Response code %s: %s"%(response_body["code"], response_body["status"]))
    else:
        logger.error("Error: unexpected or malformed http response payload")
        return False

    return True

LOG_TO_FILE=['registrar','provider_registrar','cloudverifier']
# not clear that this works right.  console logging may not work
LOG_TO_STREAM=['tenant_webapp']
LOGDIR='/var/log/keylime'
if not common.REQUIRE_ROOT:
    LOGSTREAM = './keylime-stream.log'
else:
    LOGSTREAM=LOGDIR+'/keylime-stream.log'

logging.config.fileConfig(common.CONFIG_FILE)
def init_logging(loggername):
    logger = logging.getLogger("keylime.%s"%(loggername))
    logging.getLogger("requests").setLevel(logging.WARNING)
    mainlogger = logging.getLogger("keylime")

    if loggername in LOG_TO_FILE:
        if not common.REQUIRE_ROOT:
            logfilename = "./keylime-all.log"
        else:
            logfilename = "%s/%s.log"%(LOGDIR,loggername)
            if os.getuid()!=0:
                logger.warning("Unable to log to %s. please run as root"%logfilename)
                return logger
            else:
                if not os.path.exists(LOGDIR):
                    os.makedirs(LOGDIR, 0o750)
                common.chownroot(LOGDIR,logger)
                os.chmod(LOGDIR,0o750)

        fh = logging.FileHandler(logfilename)
        fh.setLevel(logger.getEffectiveLevel())
        basic_formatter = logging.Formatter('%(created)s  %(name)s  %(levelname)s  %(message)s')
        fh.setFormatter(basic_formatter)
        mainlogger.addHandler(fh)

    if loggername in LOG_TO_STREAM:
        fh = logging.FileHandler(filename=LOGSTREAM,mode='w')
        fh.setLevel(logger.getEffectiveLevel())
        basic_formatter = logging.Formatter('%(created)s  %(name)s  %(levelname)s  %(message)s')
        fh.setFormatter(basic_formatter)
        mainlogger.addHandler(fh)

    return logger
