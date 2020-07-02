#!/usr/bin/env python

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import os
from M2Crypto import X509

import keylime.secure_mount as secure_mount
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
    subject = json_meta['subject']
    if revocation.get('type',None) != 'revocation' or serial is None or subject is None:
        logger.error("Unsupported revocation message: %s"%revocation)

    # import the crl into NSS
    secdir = secure_mount.mount()
    logger.info("loading updated CRL from %s/unzipped/cacrl.der into NSS"%secdir)
    cmd_exec.run("crlutil -I -i %s/unzipped/cacrl.der -d sql:/etc/ipsec.d"%secdir,lock=False)

    # need to find any sa's that were established with that cert subject name
    output = cmd_exec.run("ipsec whack --trafficstatus",lock=False,raiseOnError=True)['retout']
    deletelist=set()
    id = ""
    for line in output:
        line = line.strip()
        try:
            idstart = line.index("id='")+4
            idend = line[idstart:].index('\'')

            id = line[idstart:idstart+idend]

            privatestart = line.index("private#")+8
            privateend = line[privatestart:].index("/")

            ip = line[privatestart:privatestart+privateend]
        except ValueError:
            # weirdly formatted line
            continue

    # kill all the commas
    id = id.replace(",","")
    cursubj={}
    for token in id.split():
        cur = token.split('=')
        cursubj[cur[0]]=cur[1]

    cert ={}
    for token in subject[1:].split("/"):
        cur = token.split('=')
        cert[cur[0]]=cur[1]

    if cert == cursubj:
        deletelist.add(ip)

    for todelete in deletelist:
        logger.info("deleting IPsec sa with %s"%todelete)
        cmd_exec.run("ipsec whack --crash %s"%todelete,raiseOnError=False,lock=False)
