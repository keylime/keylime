#!/usr/bin/python

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
import base64
import tpm_exec
import tpm_cexec
import tempfile
import hashlib
import os
import tpm_initialize
import common
import traceback
import sets
import time
import ima
import json

logger = common.init_logging('tpm_quote')

EMPTYMASK="1"
EMPTY_PCR="0000000000000000000000000000000000000000"

def check_mask(mask,pcr):
    if mask is None:
        return False
    return bool(1<<pcr & int(mask,0))

def create_deep_quote(nonce,data=None,vpcrmask=EMPTYMASK,pcrmask=EMPTYMASK):   
    quote = ""
    with tempfile.NamedTemporaryFile() as quotepath:
        # read in the vTPM key handle
        keyhandle = tpm_initialize.get_tpm_metadata('aik_handle')
        owner_pw = tpm_initialize.get_tpm_metadata('owner_pw')
        aik_pw = tpm_initialize.get_tpm_metadata('aik_pw')
        
        if pcrmask is None:
            pcrmask = EMPTYMASK
        if vpcrmask is None:
            vpcrmask = EMPTYMASK
            
        # need to hold the lock while we reset and extend the pcr and then do the quote
        with tpm_exec.tpmutilLock:
            if data is not None:
                # add PCR 16 to pcrmask
                vpcrmask = "0x%X"%(int(vpcrmask,0) + (1 << common.TPM_DATA_PCR))
                tpm_exec.run("pcrreset -ix %d"%common.TPM_DATA_PCR,lock=False)
                tpm_exec.run("extend -ix %d -ic %s"%(common.TPM_DATA_PCR,hashlib.sha1(data).hexdigest()),lock=False)
            
            command = "deepquote -vk %s -hm %s -vm %s -nonce %s -pwdo %s -pwdk %s -oq %s" % (keyhandle, pcrmask, vpcrmask, nonce, owner_pw, aik_pw, quotepath.name)
            #print("Executing %s"%(command))
            (retout,code,quoteraw) = tpm_exec.run(command,lock=False,outputpath=quotepath.name)
            quote = base64.b64encode(quoteraw.encode("zlib"))

    return 'd'+quote

def create_quote(nonce,data=None,pcrmask=EMPTYMASK):
    quote = ""
    with tempfile.NamedTemporaryFile() as quotepath:
        keyhandle = tpm_initialize.get_tpm_metadata('aik_handle')
        aik_pw = tpm_initialize.get_tpm_metadata('aik_pw')
        
        if pcrmask is None:
            pcrmask = EMPTYMASK

        with tpm_exec.tpmutilLock:
            if data is not None:
                # add PCR 16 to pcrmask
                pcrmask = "0x%X"%(int(pcrmask,0) + (1 << common.TPM_DATA_PCR))
                tpm_exec.run("pcrreset -ix %d"%common.TPM_DATA_PCR,lock=False)
                tpm_exec.run("extend -ix %d -ic %s"%(common.TPM_DATA_PCR,hashlib.sha1(data).hexdigest()),lock=False)
            
            command = "tpmquote -hk %s -pwdk %s -bm %s -nonce %s -noverify -oq %s"%(keyhandle,aik_pw,pcrmask,nonce,quotepath.name)
            (retout,code,quoteraw) = tpm_exec.run(command,lock=False,outputpath=quotepath.name)
            quote = base64.b64encode(quoteraw.encode("zlib"))

    return 'r'+quote

def is_deep_quote(quote):
    if quote[0]=='d':
        return True
    elif quote[0]=='r':
        return False
    else:
        raise Exception("Invalid quote type %s"%quote[0])

def check_deep_quote(nonce,data,quote,vAIK,hAIK,vtpm_policy={},tpm_policy={},ima_measurement_list=None,ima_whitelist={}):
    quoteFile=None
    vAIKFile=None
    hAIKFile=None
        
    if quote[0]!='d':
        raise Exception("Invalid deep quote type %s"%quote[0])
    quote = quote[1:]
    
    try:
        # write out quote
        qfd, qtemp = tempfile.mkstemp()
        quoteFile = open(qtemp,"wb")
        quoteFile.write(base64.b64decode(quote).decode("zlib"))
        quoteFile.close()
        os.close(qfd)

        afd, atemp = tempfile.mkstemp()
        vAIKFile = open(atemp,"w")
        vAIKFile.write(vAIK)
        vAIKFile.close()
        os.close(afd)
        
        afd, atemp = tempfile.mkstemp()
        hAIKFile = open(atemp,"w")
        hAIKFile.write(hAIK)
        hAIKFile.close()
        os.close(afd)

        retout = tpm_cexec.checkdeepquote(hAIKFile.name, vAIKFile.name, quoteFile.name, nonce)
    except Exception as e:
        logger.error("Error verifying quote: %s"%(e))
        logger.error(traceback.format_exc())
        return False
    finally:
        if vAIKFile is not None:
            os.remove(vAIKFile.name)
        if hAIKFile is not None:
            os.remove(hAIKFile.name)
        if quoteFile is not None:
            os.remove(quoteFile.name)
        pass
    
    if len(retout)<1:
        return False

    if retout[0]!="Verification against AIK succeeded\n":
        logger.error("Failed to validate signature, output: %s"%retout)
        return False
    
    pcrs = None
    vpcrs = None
    for line in retout:
        if line=="PCR contents from quote:\n":
            pcrs = []
            continue
        if line=="PCR contents from vTPM quote:\n":
            vpcrs = []
            continue
        if line=="\n":
            continue
        # order important here
        if vpcrs is not None:
            vpcrs.append(line)
        elif pcrs is not None:
            pcrs.append(line)
    
    # don't pass in data to check pcrs for physical quote 
    return check_pcrs(tpm_policy,pcrs,None,False,None,None) and check_pcrs(vtpm_policy, vpcrs, data, True,ima_measurement_list,ima_whitelist)

def check_quote(nonce,data,quote,aikFromRegistrar,tpm_policy={},ima_measurement_list=None,ima_whitelist={}):
    quoteFile=None
    aikFile=None

    if quote[0]!='r':
        raise Exception("Invalid quote type %s"%quote[0])
    quote = quote[1:]
    
    try:
        # write out quote
        qfd, qtemp = tempfile.mkstemp()
        quoteFile = open(qtemp,"wb")

        quoteFile.write(base64.b64decode(quote).decode("zlib"))
        quoteFile.close()
        os.close(qfd)

        afd, atemp = tempfile.mkstemp()
        aikFile = open(atemp,"w")
        aikFile.write(aikFromRegistrar)
        aikFile.close()
        os.close(afd)

        retout = tpm_cexec.check_quote(aikFile.name, quoteFile.name, nonce)
    except Exception as e:
        logger.error("Error verifying quote: "+str(e))
        logger.error(traceback.format_exc())
        return False
    finally:
        if aikFile is not None:
            os.remove(aikFile.name)
        if quoteFile is not None:
            os.remove(quoteFile.name)
        pass

    if len(retout)<1:
        return False

    if retout[0]!="Verification against AIK succeeded\n":
        logger.error("Failed to validate signature, output: %s"%retout)
        return False
    
    pcrs = None
    for line in retout[1:]:
        if line=="PCR contents from quote:\n":
            pcrs = []
            continue
        if line=="\n":
            continue
        if pcrs is not None:
            pcrs.append(line)    

    return check_pcrs(tpm_policy,pcrs,data,False,ima_measurement_list,ima_whitelist)

def check_pcrs(tpm_policy,pcrs,data,virtual,ima_measurement_list,ima_whitelist):
    pcrWhiteList = tpm_policy.copy()
    if 'mask' in pcrWhiteList: del pcrWhiteList['mask']
    # convert all pcr num keys to integers
    pcrWhiteList = {int(k):v for k,v in pcrWhiteList.items()}
    
    pcrsInQuote=sets.Set()
    for line in pcrs:
        tokens = line.split()
        if len(tokens)<3:
            logger.error("Invalid %sPCR in quote: %s"%(("","v")[virtual],pcrs))
            continue
        
        # always lower case
        pcrval = tokens[2].lower()
        # convert pcr num to number
        try:
            pcrnum = int(tokens[1])
        except Exception:
            logger.error("Invalide PCR number %s"%tokens[1])
        
        if pcrnum==common.TPM_DATA_PCR and data is not None:
            # compute expected value  H(0|H(string(H(data))))
            # confused yet?  pcrextend will hash the string of the original hash again
            expectedval = hashlib.sha1(EMPTY_PCR.decode('hex')+hashlib.sha1(hashlib.sha1(data).hexdigest()).digest()).hexdigest().lower()
            if expectedval != pcrval and not common.STUB_TPM:
                logger.error("%sPCR #%s: invalid bind data %s from quote does not match expected value %s"%(("","v")[virtual],pcrnum,pcrval,expectedval))
                return False
            continue
               
        # check for ima PCR
        if pcrnum==common.IMA_PCR and not common.STUB_TPM:
            if ima_measurement_list==None:
                logger.error("IMA PCR in policy, but no measurement list provided")
                return False
            
            if check_ima(pcrval,ima_measurement_list,ima_whitelist):
                pcrsInQuote.add(pcrnum)
                continue
            else:
                return False
                
        if pcrnum not in pcrWhiteList.keys():
            if not common.STUB_TPM and len(tpm_policy.keys())>0:
                logger.warn("%sPCR #%s in quote not found in %stpm_policy, skipping."%(("","v")[virtual],pcrnum),("","v")[virtual])
            continue
        elif pcrval not in pcrWhiteList[pcrnum] and not common.STUB_TPM:
            logger.error("%sPCR #%s: %s from quote does not match expected value %s"%(("","v")[virtual],pcrnum,pcrval,pcrWhiteList[pcrnum]))
            return False
        else:
            pcrsInQuote.add(pcrnum)       

    if common.STUB_TPM:
        return True

    missing = list(sets.Set(pcrWhiteList.keys()).difference(pcrsInQuote))
    if len(missing)>0:
        logger.error("%sPCRs specified in policy not in quote: %s"%(("","v")[virtual],missing))
        return False
    return True

def check_ima(pcrval,ima_measurement_list,ima_whitelist):
    logger.info("Checking IMA measurement list...")
    ex_value = ima.process_measurement_list(ima_measurement_list.split('\n'),ima_whitelist)
    if ex_value is None:
        return False
    
    if pcrval != ex_value and not common.STUB_IMA:
        logger.error("IMA measurement list expected pcr value %s does not match TPM PCR %s"%(ex_value,pcrval))
        return False
    logger.debug("IMA measurement list validated")
    return True

def readPolicy(configval):
    policy = json.loads(configval)
    
    # compute PCR mask from tpm_policy
    mask = 0
    for key in policy.keys():
        if not key.isdigit() or int(key)>24:
            raise Exception("Invalid tpm policy pcr number: %s"%(key))
        
        if int(key)==common.TPM_DATA_PCR:
            raise Exception("Invalid whitelist PCR number %s, keylime uses this PCR to bind data."%key)
        if int(key)==common.IMA_PCR:
            raise Exception("Invalid whitelist PCR number %s, this PCR is used for IMA."%key)
        
        mask = mask + (1<<int(key))
        
        # wrap it in a list if it is a singleton
        if isinstance(policy[key],basestring):
            policy[key]=[policy[key]]
         
        # convert all hash values to lowercase
        policy[key] = [x.lower() for x in policy[key]]
    
    policy['mask'] = "0x%X"%(mask)
    return policy

# this is just for testing
def main(argv=sys.argv):
    nonce = "NABIL"
    rsa_key = "somebase64data"
    
    print "creating quote..."
    quote = create_quote(nonce,rsa_key)
    print "\tDONE"

    print "checking quote..."
    if common.STUB_TPM:
        aik ='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzpAAp0TEPftgRr0z0ZYV\nBtKz3yDAYE+lH8p6gE3hRcI/Vg9ngGfQJohc9wsy4ELSSKUVMBVOkw2ITKCH3UOo\ny6J+FPApp12oYGSKxUMeHH30cVKaFSXMKSYl4J67Uufv8rhuKbcp60EJNfo8ougv\nHV1n9fwSBsmYeU8InW3cC4qcOkkQW++zeQi6HhTvrXdajTSdoH9wO8olQvx+IW4n\nmWz74vYWt5u5whyIv2wDkGlOz1x5iAAcarxS3xPuQTu/Mv9QOVNqwcvQaAolps6z\n3ckOGyRrEUS7rKkkBGX4FATUq6XhbxyJ7ZLba83jEnGS9h8EO2t9SUmp7cNxV+A7\njQIDAQAB\n-----END PUBLIC KEY-----\n'

    else:
        aik = tpm_initialize.get_tpm_metadata('aik')
        
    print "\tVerified %s"%check_quote(nonce,rsa_key,quote,aik)

    print "creating full quote..."
    # this is a quote for pcr 22,2
    quote = create_quote(nonce,rsa_key,"0x400004")
    print "\tDONE"

    print "checking full quote..."
    
    json_tpm_policy = '{"22":"ffffffffffffffffffffffffffffffffffffffff","02":"0000000000000000000000000000000000000000"}'
    
    tpm_policy = readPolicy(json_tpm_policy)
    print "\tVerified %s"%check_quote(nonce,rsa_key,quote,aik,tpm_policy)
    
    print "\n========\n\nchecking deepquote"
    TEST_DQ='deJxjYP7//z8jAwPD2YOCkba7vsoFf9ndFiVZtO7EGaG04uNiAn6W4rdCQuZO0FG4vW6vfZRZr9ln1+2s4mmTXYxPPXDW/Bjbcbo2tC+Q7W/tH4kvS3of1jq57gjQYWZ5OHXVvPN89ZeXnfPODjxz7tfZ0y9vvfOw+57Y/GmO7sMjxyQ6eabK7j6kHTCp8+bt+POPJksYeK3/NV2lcWfnxN4+XxWXr0zzc5WDf1jb7I1MtEosvcvREtn5MuuzJNPOnW62qk/DDhV+fiQmY6fh/IRJMEw5+VqpJkPlYR+u188lzvb2zra5+dRkJXvar+SZXId6V/94zrgmg/PUQhFJQeblnr+WrNG9wymsvvrsFumaA26hx62S/e+DwkDeSWO6ikneSua6jOji3aY/X+/IEmegAEgAsd+Jb/Xm6yUvHXG0ujLt9vOdiwVj8qIn716wLGW5QFCkV8HUTeyl5cyu3Kkf067PmMp7cb6p9dJXp2o3xJzS5sSmjq26/XUtL+/Ri+8PHpqX3br0sRTHwbrIrt93Xyle3HawqPJIG/e2Fu6H+tj0YhOjxH8DBf4PEMDqGAEgZgQjhq62J0933/cVvnl6JtsW/Rvu5hc+Vuyy/vdshjH72Yymf+LXn2xft93xkn3vbo6TbIrax/TmmLeuvp5TvlbofMS5qf+PH44ymy11QmRbB3tN+T5p54N2T/dMzHO6XhzdYCe52XXS9Vk2c5Sk2LZ/9XSsu/Lhsf6klZmsU3oCHBzjuJ5JRYtd/+Us3HUrYGMOg0rDAtt3pxNsnm10PsRt//ROqJlcS/p53okH2Z9MOP2wZ6k4k/sEM3H1S1mmEjGzdt2vMG7ZH6aw76F4cgNDF2fkbeG8LYoSDjMqw378yJj2ZonP4k3NFyas0PBT3Gn6ePdFmytJE07/WXvvgs1uVo7k+38Wb4v+eoHJnMWh+jwzAySQHjDCgoaViV5pYjiDgUrvxAIAoKts4Q=='
    TEST_DQ_NONCE='123456'
    TEST_HAIK='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Em0Y7CEPS1wjY4DwlbP\nnleKpKcViK54K5R2wghixKT+I17FqzCfZWR9oxgO7YrjasoNkd8q+IaPzNIwv8f0\nxBJPjJdZy+OKP2b1/Yl5vlArvhhA8v0/FJv6qBnzMsPhoIKFaVidE5Z5MHZdGBP9\nY3CeXHGxeFoulge8CQj/A2rKPzCJ78TDY8is5wkmiqbqV1nAV+oDgnzWniVP3Bg6\njaK6uGxeATWtpNPFyyxbS+F/p5vRr7fpz/6RjJrheW2xsMHo+8V8J6knNXoAUsFj\nWgNm6MWpEWtJ9kEopSAKNPr96JA50Ns3fPG2OlCPU4bG7rHB5zr8irjWwiJFtpiE\ncQIDAQAB\n-----END PUBLIC KEY-----\n'
    TEST_VAIK='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsWZQSYGM03DPfaN9FgH/\nCZ9KHDY79VeVqnhBFk3NcnWQ515ld9cCunqfKLdCow4G3dNmTmsNhp7nNIK4UtSl\nzDCaH2/v1jk5eAPTS0w0E50oYSIMAfN+7PQDCNlzM4mKSiP4sj4uNYj/WVbuZxCM\nb37Cdj8q1Wh+lONUnBfPhIwBnjQ1o9Gzbq2/18xLKHiJvIPeCsNlVabPbbWg26eA\n5sRqeTyx8gSKX0u6fmgrf8KmiHeau8aU131SIZgdvYMv74ZB2i4qgZpNAXK3XvU+\nay5lOaYNr2//MdSSV43hQZvyh9hSb2r4BtoJfJ5eyubPC4hRQSC55/hI+2j3x0+z\nmQIDAQAB\n-----END PUBLIC KEY-----\n'

    print "\tVerified %s"%check_deep_quote(common.TEST_DQ_NONCE, None, common.TEST_DQ, common.TEST_VAIK, common.TEST_HAIK, {}, {})
    
    if True:
        sys.exit(0)
        
    print "creating a bunch of quotes"
    for _ in range(1000):
        create_quote(nonce,rsa_key)
        check_quote(nonce,rsa_key,quote,aik,tpm_policy)
        pass
    print "done"


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
