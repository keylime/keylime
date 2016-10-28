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

import os.path
import ConfigParser
import logging.config
import sys
    
# SET THIS TO True TO ENABLE THIS TO RUN in ECLIPSE
DEVELOP_IN_ECLIPSE=False

# SET THIS TO True TO ALLOW ALL TPM Operations to be stubbed out
STUB_TPM=False

# set this to true to run the load testing on the CV
LOAD_TEST=False

if LOAD_TEST and DEVELOP_IN_ECLIPSE:
    raise Exception("don't specify load_test and develop_in_eclipse at the same time")

if LOAD_TEST or DEVELOP_IN_ECLIPSE:
    MOUNT_SECURE=False
else:
    MOUNT_SECURE=True
    
# if you're Robert and you really don't want to mount secure
#MOUNT_SECURE=False

# Try and import cLime, if it fails set USE_CLIME to False.
try:
    import _cLime
    USE_CLIME=True
except ImportError:
    USE_CLIME=False
    
TPM_TOOLS_PATH = '/usr/local/bin/'
if getattr(sys, 'frozen', False):
    # we are running in a pyinstaller bundle, redirect tpm tools to bundle
    TPM_TOOLS_PATH = sys._MEIPASS

if DEVELOP_IN_ECLIPSE:
    CONFIG_FILE="../keylime.conf"
elif LOAD_TEST:
    CONFIG_FILE="./keylime.conf"
else:
    CONFIG_FILE=os.getenv('KEYLIME_CONFIG', '/etc/keylime.conf')

# if CONFIG_FILE not set as environment var or in /etc/keylime.conf and bundle
# try to locate the config file next to the script
if not os.path.exists(CONFIG_FILE) and getattr(sys, 'frozen', False):
    CONFIG_FILE = os.path.dirname(os.path.abspath(sys.executable))+"/keylime.conf"

if not os.path.exists(CONFIG_FILE):
    raise Exception('"{0}" does not exist. Please set environment variable KEYLIME_CONFIG or see "{1}" for more details'.format(CONFIG_FILE, __file__))
print("Using config file %s"%(CONFIG_FILE,))

if DEVELOP_IN_ECLIPSE:
    WORK_DIR="."
else:
    WORK_DIR=os.getenv('KEYLIME_DIR','/var/lib/keylime')

CA_WORK_DIR='%s/ca/'%WORK_DIR

def ch_dir(path=WORK_DIR,root=True):    
    if not os.path.exists(path):
        os.makedirs(path,0o700)
        if not DEVELOP_IN_ECLIPSE and root:
            os.chown(path,0,0)
    os.chdir(path)

LOG_TO_FILE=['cloudnode','registrar','provider_registrar','cloudverifier']
# not clear that this works right.  console logging may not work
LOG_TO_SYSCONSOLE=['cloudnode']
LOGDIR='/var/log/keylime'

logging.config.fileConfig(CONFIG_FILE)
def init_logging(loggername):
    logger = logging.getLogger("keylime.%s"%(loggername))
    logging.getLogger("requests").setLevel(logging.WARNING)
    mainlogger = logging.getLogger("keylime")

    if loggername in LOG_TO_FILE:
        if DEVELOP_IN_ECLIPSE:
            logfilename = "./keylime-dev.log"
        else:
            logfilename = "%s/%s.log"%(LOGDIR,loggername)
            if os.getuid()!=0:
                logger.warning("Unable to log to %s. please run as root"%logfilename)
                return logger
            else:
                if not os.path.exists(LOGDIR):
                    os.makedirs(LOGDIR, 0o750)
                os.chown(LOGDIR, 0, 0)
                os.chmod(LOGDIR,0o750)
                
        fh = logging.FileHandler(logfilename)
        fh.setLevel(logger.getEffectiveLevel())
        basic_formatter = logging.Formatter('%(created)s - %(name)s - %(levelname)s - %(message)s')    
        fh.setFormatter(basic_formatter)
        mainlogger.addHandler(fh)

    if loggername in LOG_TO_SYSCONSOLE:
        if os.getuid()!=0:
            logger.warning("unable to log to /dev/console. please run as root")
        else:
            fh = logging.FileHandler("/dev/console")
            fh.setLevel(logger.getEffectiveLevel())
            fh.setFormatter(basic_formatter)
            mainlogger.addHandler(fh)
    
    return logger

TEST_CREATE_QUOTE_DELAY=0.08969
TEST_CREATE_DEEP_QUOTE_DELAY=1.5159

if LOAD_TEST:
    config = ConfigParser.RawConfigParser()
    config.read(CONFIG_FILE)
    TEST_CREATE_DEEP_QUOTE_DELAY = config.getfloat('general', 'test_deep_quote_delay')
    TEST_CREATE_QUOTE_DELAY = config.getfloat('general','test_quote_delay')

# this just needs to be a valid AES key
TEST_AES_REG_KEY='F\xdb\x8d\x9bh\xff\xbcvDK~EP\xbd\xec/\x96\x92\x04] Z1\x8f\x1a\xa4\xd2\x18\x00\nt\xfa'
# this is just a valid tpm ek.  doesn't have to be from the same TPM as the later AIK
TEST_PUB_EK='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1xWZh1aVwKIXT1B9n519\nLE6Oe3QIkeKqUUNURN8wFMd9Acs+vInh5NWgKAHtG4b5KBZqVytvIOJ4NctjinFY\nTCJKM3SJtPA2XYcXaUc6EAQda5TMgfqCeitHjivTtgb3hTMNrIgfOCV40peUU3Im\nSnd84q4Rrq9CfGIdmBCLCzAFfoble6ivMxRVzJ9Ob3xtlaS8ROXKqF+vq0dZZ41Q\nIp6IgpDlSf1TL8w+GHdMQQIUM1XEIRt9Owv8JQvnM4iX06EpnCP/BZshLUN+CivX\n4VRWxjua8NkwMv/wc3xI64E58EYFWnGca3UBi3JBD0QuuzkYM1vkfkvi2QNiWA7I\nFQIDAQAB\n-----END PUBLIC KEY-----\n'
TEST_EK_CERT='MIIDiTCCAnGgAwIBAgIFLgbvovcwDQYJKoZIhvcNAQEFBQAwUjFQMBwGA1UEAxMVTlRDIFRQTSBFSyBSb290IENBIDAyMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkGA1UEBhMCVFcwHhcNMTMxMDA2MDkxNTM4WhcNMzMxMDA2MDkxNTM4WjAAMIIBXzBKBgkqhkiG9w0BAQcwPaALMAkGBSsOAwIaBQChGDAWBgkqhkiG9w0BAQgwCQYFKw4DAhoFAKIUMBIGCSqGSIb3DQEBCQQFVENQQQADggEPADCCAQoCggEBANcVmYdWlcCiF09QfZ+dfSxOjnt0CJHiqlFDVETfMBTHfQHLPryJ4eTVoCgB7RuG+SgWalcrbyDieDXLY4pxWEwiSjN0ibTwNl2HF2lHOhAEHWuUzIH6gnorR44r07YG94UzDayIHzgleNKXlFNyJkp3fOKuEa6vQnxiHZgQiwswBX6G5XuorzMUVcyfTm98bZWkvETlyqhfr6tHWWeNUCKeiIKQ5Un9Uy/MPhh3TEECFDNVxCEbfTsL/CUL5zOIl9OhKZwj/wWbIS1Dfgor1+FUVsY7mvDZMDL/8HN8SOuBOfBGBVpxnGt1AYtyQQ9ELrs5GDNb5H5L4tkDYlgOyBUCAwEAAaN7MHkwVAYDVR0RAQH/BEowSKRGMEQxQjAUBgVngQUCARMLaWQ6NTc0NTQzMDAwGAYFZ4EFAgITD05QQ1Q0MngvTlBDVDUweDAQBgVngQUCAxMHaWQ6MDM5MTAMBgNVHRMBAf8EAjAAMBMGA1UdJQEB/wQJMAcGBWeBBQgBMA0GCSqGSIb3DQEBBQUAA4IBAQALYCcNLxnWs2rvt/gPGjCfZKuURHmgcICu97IaAM5iJPsyLR14rgOpOXpH1yUbcNvJbljOOfHsCczHOW5rvc+lIOrWHwhPKaRAAVnx7o7Zdj6ndDIqwjMi3royPvM8qad69vVRXTAx/zJkOtWO6eFX0UmPlfpRwVjLbjrbih7rJ58etNH6Umk23iCUriYTXy9HSyuhqQY3f/gxuvQB5v0DIvH6m3ne4mNcvtAv4LMIvKS6PUAjamMHRtebhY3xvGzZUlyHzXuId9Rw9bOS1fRwA6k4cC0qqWDO3d12ojN5B9Tr1IPV65weu7sCQT0PzkUKI0KeCoAGcPy0+ibk4VxL'
# use the following option to get the next three canned values from a real system
PRINT_QUOTE_INFO = False
TEST_QUOTE='eJxjEGBgYGAEIwZ9jbgCnopDz5Zc29kovtPX6ZTh9+lFy2qWbZp6ilsqu8klV3y5hfc5y9Jgz0l/rmbqSS4Q+cl+s9HAe9vT+6ZpPsknWfjEZ++39eabNX/pKh33XkcX1+2GZzRk5r05bWcSqTs18LHRP7F1MUvdq/gmTT/x/Ob+lE1ymhrti06aHZdfwnr+4nNNa89pn3adKGDfFSY+VfnUndiDOxzXLDEW1OCLMmtYqTexRmnjucqShOKLvN+NTyb9/7ly2912sfQN230n912/MFf5ecBDsVvWZSdn2ZXeb/2QsYfpZ/rtbRIc+x5GOIWk+MvIblj03vL3Tsa4N85m0sZ9//Weq33qlWUr3WUpum9C9fElvqnMwDBwrGdg0GCAgAUsBzof1TNgBf+xAABvBpOV'
TEST_NONCE='c092b9a693d632c5f93a3b2776b2317bf11d0af8'
TEST_AIK='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzpAAp0TEPftgRr0z0ZYV\nBtKz3yDAYE+lH8p6gE3hRcI/Vg9ngGfQJohc9wsy4ELSSKUVMBVOkw2ITKCH3UOo\ny6J+FPApp12oYGSKxUMeHH30cVKaFSXMKSYl4J67Uufv8rhuKbcp60EJNfo8ougv\nHV1n9fwSBsmYeU8InW3cC4qcOkkQW++zeQi6HhTvrXdajTSdoH9wO8olQvx+IW4n\nmWz74vYWt5u5whyIv2wDkGlOz1x5iAAcarxS3xPuQTu/Mv9QOVNqwcvQaAolps6z\n3ckOGyRrEUS7rKkkBGX4FATUq6XhbxyJ7ZLba83jEnGS9h8EO2t9SUmp7cNxV+A7\njQIDAQAB\n-----END PUBLIC KEY-----\n'

# use the following option to get the next three canned values from a real system
PRINT_DEEPQUOTE_INFO = False
TEST_DQ='eJxjYP7//z8jAwPD2YOCkba7vsoFf9ndFiVZtO7EGaG04uNiAn6W4rdCQuZO0FG4vW6vfZRZr9ln1+2s4mmTXYxPPXDW/Bjbcbo2tC+Q7W/tH4kvS3of1jq57gjQYWZ5OHXVvPN89ZeXnfPODjxz7tfZ0y9vvfOw+57Y/GmO7sMjxyQ6eabK7j6kHTCp8+bt+POPJksYeK3/NV2lcWfnxN4+XxWXr0zzc5WDf1jb7I1MtEosvcvREtn5MuuzJNPOnW62qk/DDhV+fiQmY6fh/IRJMEw5+VqpJkPlYR+u188lzvb2zra5+dRkJXvar+SZXId6V/94zrgmg/PUQhFJQeblnr+WrNG9wymsvvrsFumaA26hx62S/e+DwkDeSWO6ikneSua6jOji3aY/X+/IEmegAEgAsd+Jb/Xm6yUvHXG0ujLt9vOdiwVj8qIn716wLGW5QFCkV8HUTeyl5cyu3Kkf067PmMp7cb6p9dJXp2o3xJzS5sSmjq26/XUtL+/Ri+8PHpqX3br0sRTHwbrIrt93Xyle3HawqPJIG/e2Fu6H+tj0YhOjxH8DBf4PEMDqGAEgZgQjhq62J0933/cVvnl6JtsW/Rvu5hc+Vuyy/vdshjH72Yymf+LXn2xft93xkn3vbo6TbIrax/TmmLeuvp5TvlbofMS5qf+PH44ymy11QmRbB3tN+T5p54N2T/dMzHO6XhzdYCe52XXS9Vk2c5Sk2LZ/9XSsu/Lhsf6klZmsU3oCHBzjuJ5JRYtd/+Us3HUrYGMOg0rDAtt3pxNsnm10PsRt//ROqJlcS/p53okH2Z9MOP2wZ6k4k/sEM3H1S1mmEjGzdt2vMG7ZH6aw76F4cgNDF2fkbeG8LYoSDjMqw378yJj2ZonP4k3NFyas0PBT3Gn6ePdFmytJE07/WXvvgs1uVo7k+38Wb4v+eoHJnMWh+jwzAySQHjDCgoaViV5pYjiDgUrvxAIAoKts4Q=='
TEST_DQ_NONCE='123456'
TEST_HAIK='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Em0Y7CEPS1wjY4DwlbP\nnleKpKcViK54K5R2wghixKT+I17FqzCfZWR9oxgO7YrjasoNkd8q+IaPzNIwv8f0\nxBJPjJdZy+OKP2b1/Yl5vlArvhhA8v0/FJv6qBnzMsPhoIKFaVidE5Z5MHZdGBP9\nY3CeXHGxeFoulge8CQj/A2rKPzCJ78TDY8is5wkmiqbqV1nAV+oDgnzWniVP3Bg6\njaK6uGxeATWtpNPFyyxbS+F/p5vRr7fpz/6RjJrheW2xsMHo+8V8J6knNXoAUsFj\nWgNm6MWpEWtJ9kEopSAKNPr96JA50Ns3fPG2OlCPU4bG7rHB5zr8irjWwiJFtpiE\ncQIDAQAB\n-----END PUBLIC KEY-----\n'
TEST_VAIK='-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsWZQSYGM03DPfaN9FgH/\nCZ9KHDY79VeVqnhBFk3NcnWQ515ld9cCunqfKLdCow4G3dNmTmsNhp7nNIK4UtSl\nzDCaH2/v1jk5eAPTS0w0E50oYSIMAfN+7PQDCNlzM4mKSiP4sj4uNYj/WVbuZxCM\nb37Cdj8q1Wh+lONUnBfPhIwBnjQ1o9Gzbq2/18xLKHiJvIPeCsNlVabPbbWg26eA\n5sRqeTyx8gSKX0u6fmgrf8KmiHeau8aU131SIZgdvYMv74ZB2i4qgZpNAXK3XvU+\nay5lOaYNr2//MdSSV43hQZvyh9hSb2r4BtoJfJ5eyubPC4hRQSC55/hI+2j3x0+z\nmQIDAQAB\n-----END PUBLIC KEY-----\n'
TEST_GROUP_UUID='c697ce76-641c-41fb-a4a6-b816860afd11'
TEST_VTPM_UUID='C432FBB3-D2F1-4A97-9EF7-75BD81C866E9'

HEADERS = {'User-Agent': 'foo', 'Content-Type': 'text/xml'}
BS = 16

# how many quotes are we allowed to verify before asking the registrar if the key is valid
MAX_STALE_REGISTRAR_CACHE = 200

if DEVELOP_IN_ECLIPSE:
    IMA_ML = 'ascii'
else:
    IMA_ML = '/sys/kernel/security/ima/ascii_runtime_measurements'
IMA_PCR = 10

# this is where data will be bound to a quote, MUST BE RESETABLE!
TPM_DATA_PCR = 16

# the size of the bootstrap key for AES-GCM 256bit
BOOTSTRAP_KEY_SIZE=32
