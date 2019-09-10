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
import keylime.common as common
import keylime.keylime_logging as keylime_logging
import keylime.cmd_exec as cmd_exec

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

logger = keylime_logging.init_logging('delete-sa')

async def execute(revocation):
    serial = revocation.get("metadata",{}).get("cert_serial",None)
    subject = revocation.get("metadata",{}).get("subject",None)
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
