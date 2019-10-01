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

import sys
import configparser
import base64
import yaml
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader as SafeLoader, SafeDumper as SafeDumper

from keylime import common
from keylime import keylime_logging
from keylime import registrar_client
from keylime import vtpm_manager

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

logger = keylime_logging.init_logging('platform-init')

def add_vtpm(inputfile):
    # read in the file
    with open(inputfile,'r') as f:
        group = yaml.load(f, Loader=SafeLoader)

    # fetch configuration parameters
    provider_reg_port = config.get('general', 'provider_registrar_port')
    provider_reg_ip = config.get('general', 'provider_registrar_ip')

    # request a vtpm uuid from the manager
    vtpm_uuid = vtpm_manager.add_vtpm_to_group(group['uuid'])

    # registrar it and get back a blob
    keyblob = registrar_client.doRegisterAgent(provider_reg_ip,provider_reg_port,vtpm_uuid,group['pubekpem'],group['ekcert'],group['aikpem'])

    # get the ephemeral registrar key by activating in the hardware tpm
    key = base64.b64encode(vtpm_manager.activate_group(group['uuid'], keyblob))

    # tell the registrar server we know the key
    registrar_client.doActivateAgent(provider_reg_ip,provider_reg_port,vtpm_uuid,key)

    logger.info("Registered new vTPM with UUID: %s"%(vtpm_uuid))

    return vtpm_uuid

def main(argv=sys.argv):
    if common.DEVELOP_IN_ECLIPSE and not common.STUB_TPM:
        raise Exception("Can't use Xen features in Eclipse without STUB_TPM")

    if common.DEVELOP_IN_ECLIPSE:
        argv = ['provider_platform_register.py','current_group.tpm']

    if len(argv)<2:
        print("usage: provider_vtpm_add.py [uuid].tpm")
        print("\tassociates creates a vtpm and adds it to the specified group \n\tusing YAML data in the .tpm file for aik, uuid, and activation key")
        sys.exit(-1)

    add_vtpm(argv[1])

    sys.exit(0)

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
