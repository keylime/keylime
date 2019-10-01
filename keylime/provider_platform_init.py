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
import os
import errno
import yaml
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader as SafeLoader, SafeDumper as SafeDumper

from keylime import common
from keylime import keylime_logging
from keylime import registrar_client
from keylime.keylime_sqlite import vtpm_manager

logger = keylime_logging.init_logging('provider_platform_init')

config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

def symlink_force(target, link_name):
    try:
        os.symlink(target, link_name)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(link_name)
            os.symlink(target, link_name)
        else:
            raise e

def main(argv=sys.argv):
    if common.DEVELOP_IN_ECLIPSE:
        argv = ['provider_platform_init.py','1','2']

    if len(argv)<3:
        print("usage: provider_platform_init.py pubek.pem tpm_ekcert.der")
        print("\tassociates a hypervisor host to its TPM and registers it")
        print()
        print("\tYou must obtain the public EK and the EK certificate from outside of Xen")
        print("\ttake ownership first, then obtain pubek, and ekcert as follows")
        print("\t takeown -pwdo <owner_password>")
        print("\t getpubek -pwdo <owner-password>")
        print("\t nv_readvalue -pwdo <owner-password> -in 1000f000 -cert -of tpm_ekcert.der")
        sys.exit(-1)

    if common.DEVELOP_IN_ECLIPSE and not common.STUB_TPM:
        raise Exception("Can't use Xen features in Eclipse without STUB_TPM")

    # read in the pubek
    if common.DEVELOP_IN_ECLIPSE:
        ek = common.TEST_PUB_EK
        ekcert = common.TEST_EK_CERT
    else:
        f = open(argv[1],'r')
        ek = f.read()
        f.close()
        f = open(argv[2],'r')
        ekcert = base64.b64encode(f.read())
        f.close()

    # fetch configuration parameters
    provider_reg_port = config.get('general', 'provider_registrar_port')
    provider_reg_ip = config.get('general', 'provider_registrar_ip')

    # create a new group
    (group_uuid,group_aik,group_num,_) = vtpm_manager.add_vtpm_group()

    # registrar it and get back a blob
    keyblob = registrar_client.doRegisterAgent(provider_reg_ip,provider_reg_port,group_uuid,ek,ekcert,group_aik)

    # get the ephemeral registrar key by activating in the hardware tpm
    key = base64.b64encode(vtpm_manager.activate_group(group_uuid, keyblob))

    # tell the registrar server we know the key
    registrar_client.doActivateAgent(provider_reg_ip,provider_reg_port,group_uuid,key)

    output= {
             'uuid': group_uuid,
             'aikpem': group_aik,
             'pubekpem': ek,
             'ekcert': ekcert,
             }

    # store the key and the group UUID in a file to add to vtpms later
    with open("group-%d-%s.tpm"%(group_num,group_uuid),'w') as f:
        yaml.dump(output,f, Dumper=SafeDumper)

    logger.info("Activated VTPM group %d, UUID %s"%(group_num,group_uuid))
    if group_num==0:
        logger.info("WARNING: Group 0 created, repeating activation again to create Group 1")
        main(argv)
    else:
        # create a symlink to the most recently create group
        symlink_force("group-%d-%s.tpm"%(group_num,group_uuid),"current_group.tpm")

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
