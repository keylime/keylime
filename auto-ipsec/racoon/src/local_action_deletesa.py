#!/usr/bin/env python

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''


import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import keylime.secure_mount as secure_mount
import keylime.keylime_logging as keylime_logging
import keylime.config as common
import keylime.keylime_logging as keylime_logging
import keylime.cmd_exec as cmd_exec
import keylime.ca_util as ca_util
from keylime import json

# read the config file
config = common.get_config()

logger = keylime_logging.init_logging('delete-sa')


async def execute(revocation):
    json_meta = json.loads(revocation['meta_data'])
    serial = json_meta['cert_serial']
    if revocation.get('type', None) != 'revocation' or serial is None:
        logger.error("Unsupported revocation message: %s" % revocation)

    # load up the ca cert
    secdir = secure_mount.mount()
    ca = ca_util.load_cert_by_path(f'{secdir}/unzipped/cacert.crt')

    # need to find any sa's that were established with that cert serial
    cmd = ('racoonctl', 'show-sa', 'ipsec')
    output = cmd_exec.run(cmd, raiseOnError=True)['retout']
    deletelist = set()
    for line in output:
        if not line.startswith(b"\t"):
            cmd = ('racoonctl', 'get-cert', 'inet', line.strip())
            certder = cmd_exec.run(cmd, raiseOnError=False)['retout']
            if len(certder) == 0:
                continue

            try:
                certobj = x509.load_der_x509_certificate(
                    data=b''.join(certder),
                    backend=default_backend(),
                )

                # check that CA is the same.
                ca_keyid = ca.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
                cert_authkeyid = certobj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
            except (ValueError, x509.extensions.ExtensionNotFound):
                continue

            if ca_keyid != cert_authkeyid:
                continue

            if certobj.serial_number == serial:
                deletelist.add(line.strip())

    for todelete in deletelist:
        logger.info("deleting IPsec sa between %s" % todelete)
        cmd = ('racoonctl', 'delete-sa', 'isakmp', 'inet', todelete)
        cmd_exec.run(cmd)
        tokens = todelete.split()
        cmd = ('racoonctl', 'delete-sa', 'isakmp', 'inet', tokens[1],
               tokens[0])
        cmd_exec.run(cmd)

    # for each pair returned that doens't start with whitespace
    # racoonctl get-cert inet 192.168.240.128 192.168.240.254 (the pair from before)
    # if a der comes out
    #
    # if certobj.get_serial_number() = serial:
    # kill that one and it's reverse with
    #os.system("racoonctl delete-sa isakmp inet 192.168.240.129 192.168.240.128")
    # and
    # os.system("racoonctl delete-sa isakmp inet 192.168.240.128 192.168.240.129")
