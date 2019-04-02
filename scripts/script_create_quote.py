#!/usr/bin/env python

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


import keylime.common
from keylime.tpm_quote import create_quote, create_deep_quote
import keylime.tpm_initialize
from timeit import timeit
import logging
import sys
import os

logging.basicConfig(stream=sys.stdout, level=logging.WARN,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('test_cLime')

runs = 200

nonce     = 'def06d62d443911565e2dcb380be32ed'
rsa_key   = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA020a/i2Qg925pEKLb6wjRYoRWxaIAos8Zh0Z53uhPSw96/RD\ngcvUCJ8/JDc6u7btc3Edjh3f0grQ/l6Ka/Oe0WMlfEAdU0EOeL3hndbn2mWUw/qU\npBXrk9XM0ENvXMSyM72jSSMGGKie57ZBCEVipQ6UdBm6fNuVrxbhzAMwseD7XU/n\nF9fUEhE6b5wc4ew1fzTZUqCLByZu2x4p7qBimP0OcApl146xzXNLULyNDlDFefWa\n4IUxsplvKpSYMbSCIC1VgtWCdhgowgnT4wnfk8KwaCYS7ZOPntUB6W/4BRRfd0s4\nmyrKafoXtb//H/91CxVeA++XMMuzRmKQESAOswIDAQABAoIBAQCsjIjRFIKy/Av8\nAMsnkocew7Wyb0sFOHlMpUd04jMPZ8IJhcpqbd1YRA8WEXT/qiVUZ+bFC6CVHXq/\nfozd2W+uV4pKQ1Erlxamd+FgHfoPBYRKBYG2AKXIe16yQbbrMSR2kbhnggwBp+w4\nE0gz5dzB9Io3zp+iMtuQj84r4BantAffQX3IkwVNCreyJGJNyRrz1oSLDtFG51cG\nsKqEBJjROa/BvFMvWmyMmuLPjNkBzDXfVgnig6DYTPOoIHoVdiRgsJI8Q6OCIQQ2\nz5D/vpy1HXHNQPr3lm9dKPwJHer48F4MdDb1vYhXVrCVUXQhTnIlkEDitcuSCD6x\nnibNGvLxAoGBAOP4NZ/b10IzcxN7QSv+3JgRtvGpqRVOVAShH2oVIM1nh5BhY9XI\ngt15SF7pW11sL603+axcikEpVdm/eFDTaqubFHSKCDHXsYP9BLZ9hmKAhyhbObsI\nPLXdTSnhKaLIPWnfI3HDZcvpqWrbjqPaGgc8t/AbZhbciNfmukp6F2j9AoGBAO1s\nKSO4QC4pPuRG+dgOCQQR9g7wPNmakc9QI1SCP5YB+fjz+K6ATS6X7NuGdqec+TAs\nGgDCHkjhzUuW4DDJbvYWG6GbWttAD3vFYA4wYMQ/qvYwgDXQj1zYVylXa9QSCzOt\npQSRMq004Mz1ciCbx1+jfMSS9G94/fqGB6HObn1vAoGAGuDV+b4i2CRWyhI7MeO/\nwJI+HqohTGjK0SzqFkjdcDpnqmdBLSCSBWjaVo5u/knWKTczUdYrWtlzzNOdbPIw\nXoFPXRo1MyM6Q9SeLKIKKSz8Qo7W9K1Y8xxfj7ODhDTVwNjVRgGCzBMFrZqra7g4\nX2gSS9X/KGziGYqTplpUzkUCgYBIlM9C1znvorZSTQxmK2xALUl+qZzAnUtECGi0\nlhjgP/xuSg9VMW3m95T2S3YMqaVYP7M3ViCyAS2klRw2be4ZFwsdbYPqEPxqxx0l\nWU7Lz/bwykT3rqmVJaIHxmz1aQq5orUW31iRsN+kaMiaBWV+7FjhM1e8mE10f/Ln\nWVdXywKBgQCil44cUaNvC2DqSTGIq90rfHgjJSXqzRPjg823giODoSXljAMqupfz\nUWf9kXBlQu6BXjjPMEwKoHawJfBn0Jix05TrkTXZ3BBcozWk0M+uoiQU/9Tfw30u\n1X6v/AHtKyNdIuEJZPMj+cuTyZ5Xf31LTi5dW/rx+dPNJcmElbxd7w==\n-----END RSA PRIVATE KEY-----'
mask      = '0x400000'

os.chdir('../keylime')

#ensure things are initialized
keylime.tpm_initialize.main()
keylime.common.USE_CLIME=False
print('Creating quote %s times... '%(runs), end='')
setup = 'from __main__ import nonce, rsa_key, mask, create_quote'
c = timeit('create_quote(nonce, rsa_key, mask)', number=runs, setup=setup)
print('DONE')
print("create_quote: %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))

print('Creating quote %s times... '%(runs), end='')
keylime.common.USE_CLIME=True
c = timeit('create_quote(nonce, rsa_key, mask)', number=runs, setup=setup)
print('DONE')
print("create_quote (clime): %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))

print("\n================================\n\n")

keylime.common.USE_CLIME=False
print('Creating deep quote %s times... '%(runs), end='')
vpcrmask = '0x400000'
setup = 'from __main__ import nonce, rsa_key, mask, vpcrmask,create_deep_quote'
c = timeit('create_deep_quote(nonce, rsa_key, vpcrmask,mask)', number=runs, setup=setup)
print('DONE')
print("create_deep_quote: %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))
