#!/usr/bin/python3

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys
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
config = common.get_config()

logger = keylime_logging.init_logging('platform-init')


def add_vtpm(inputfile):
    # read in the file
    with open(inputfile,'r') as f:
        group = yaml.load(f, Loader=SafeLoader)

    # fetch configuration parameters
    provider_reg_port = config.get('registrar', 'provider_registrar_port')
    provider_reg_ip = config.get('registrar', 'provider_registrar_ip')

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
