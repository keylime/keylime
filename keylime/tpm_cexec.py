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

import common
import os
import tpm_exec

logger = common.init_logging('tpm_cexec')

os.putenv('TPM_SERVER_PORT', '9999')
os.putenv('TPM_SERVER_NAME', '9999')
os.putenv('PATH', os.getenv('PATH') + ':/usr/local/bin')
def check_quote(aikFile, quoteFile, extData):
    #print('Executing "%s"' % ("checkquote -aik %s -quote %s -nonce %s"%(aikFile, quoteFile, extData),))
    if common.USE_CLIME:
        import _cLime
        retout = _cLime.checkquote('-aik', aikFile, '-quote', quoteFile, '-nonce', extData)
        retout = [line + '\n' for line in retout.split('\n')]
        # Try and be transparent to tpm_quote.py
        return retout
    else:
        retout = tpm_exec.run("checkquote -aik %s -quote %s -nonce %s"%(aikFile, quoteFile, extData))[0]
        return retout


def checkdeepquote(hAIK, vAIK, deepquoteFile, nonce):
    cmd = 'checkdeepquote -aik {0} -deepquote {1} -nonce {2} -vaik {3}'.format(hAIK, deepquoteFile, nonce, vAIK)
    #logger.info('Running cmd %r', cmd)
    return tpm_exec.run(cmd)[0]