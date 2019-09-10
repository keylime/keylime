#!/usr/bin/env python

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2017 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''


import configparser
import os
from M2Crypto import X509

import keylime.secure_mount as secure_mount
import keylime.keylime_logging as keylime_logging
import keylime.common as common
import keylime.keylime_logging as keylime_logging
import keylime.cmd_exec as cmd_exec

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

logger = keylime_logging.init_logging('delete-sa')

async def execute(revocation):
    serial = revocation.get("metadata",{}).get("cert_serial",None)
    if revocation.get('type',None) != 'revocation' or serial is None:
        logger.error("Unsupported revocation message: %s"%revocation)

    # load up the ca cert
    secdir = secure_mount.mount()
    ca = X509.load_cert('%s/unzipped/cacert.crt'%secdir)

    # need to find any sa's that were established with that cert serial
    output = cmd_exec.run("racoonctl show-sa ipsec",lock=False,raiseOnError=True)['retout']
    deletelist=set()
    for line in output:
        if not line.startswith(b"\t"):
            certder = cmd_exec.run("racoonctl get-cert inet %s"%line.strip(),raiseOnError=False,lock=False)['retout']
            if len(certder)==0:
                continue;
            certobj = X509.load_cert_der_string(b''.join(certder))

            # check that CA is the same.  the strip indexing bit is to remove the stuff around it 'keyid:THEACTUALKEYID\n'
            if ca.get_ext('subjectKeyIdentifier').get_value() != certobj.get_ext('authorityKeyIdentifier').get_value().strip()[6:]:
                continue

            if certobj.get_serial_number() == serial:
                deletelist.add(line.strip())

    for todelete in deletelist:
        logger.info("deleting IPsec sa between %s"%todelete)
        cmd_exec.run("racoonctl delete-sa isakmp inet %s"%todelete,lock=False)
        tokens = todelete.split()
        cmd_exec.run("racoonctl delete-sa isakmp inet %s %s"%(tokens[1],tokens[0]),lock=False)

    # for each pair returned that doens't start with whitespace
    #racoonctl get-cert inet 192.168.240.128 192.168.240.254 (the pair from before)
    # if a der comes out
    #
    # if certobj.get_serial_number() = serial:
    # kill that one and it's reverse with
    #os.system("racoonctl delete-sa isakmp inet 192.168.240.129 192.168.240.128")
    # and
    # os.system("racoonctl delete-sa isakmp inet 192.168.240.128 192.168.240.129")




