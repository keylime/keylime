#!/usr/bin/env python

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''


import os
from M2Crypto import X509

import keylime.secure_mount as secure_mount
import keylime.keylime_logging as keylime_logging
import keylime.common as common
import keylime.keylime_logging as keylime_logging
import keylime.cmd_exec as cmd_exec

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

# read the config file
config = common.get_config()

logger = keylime_logging.init_logging('delete-sa')

async def execute(revocation):
    json_meta = json.loads(revocation['meta_data'])
    serial = json_meta['cert_serial']
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
