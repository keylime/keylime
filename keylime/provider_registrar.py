#!/usr/bin/python3

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

from keylime import common
from keylime import keylime_logging
logger = keylime_logging.init_logging('provider-registrar')

from keylime import registrar_common
import configparser
import sys

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

def main(argv=sys.argv):
    registrar_common.start(config.getint('general', 'provider_registrar_tls_port'),config.getint('general', 'provider_registrar_port'),config.get('registrar','prov_db_filename'))

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
