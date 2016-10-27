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
import common
import hashlib
import struct
import re

logger = common.init_logging('ima')

# Paths
measure_path = '/sys/kernel/security/ima/ascii_runtime_measurements'

#         m = ima_measure_re.match(measure_line)
#         measure  = m.group('file_hash')
#         filename = m.group('file_path')

# build whitelist
# find / \( -fstype rootfs -o -type f \) -uid 0 -exec sha1sum '{}' > ~/list.txt \;

START_HASH = '0000000000000000000000000000000000000000'.decode('hex')
FF_HASH =  'ffffffffffffffffffffffffffffffffffffffff'.decode('hex')


# struct event {
#     struct {
#         u_int32_t pcr;
#         u_int8_t digest[SHA_DIGEST_LENGTH];
#         u_int32_t name_len;
#     } header;
#     char name[TCG_EVENT_NAME_LEN_MAX + 1];
#     struct ima_template_desc *template_desc; /* template descriptor */
#     u_int32_t template_data_len;
#     u_int8_t *template_data;    /* template related data */
# };


def read_unpack(fd,fmt):
    return struct.unpack(fmt,fd.read(struct.calcsize(fmt)))
    
TCG_EVENT_NAME_LEN_MAX=255
SHA_DIGEST_LEN=20

defined_templates={
                   'ima':'d|n',
                   'ima-ng':'d-ng|n-ng',
                   'ima-sig':'d-ng|n-ng|sig;',
                   }

def ima_eventname_parse():
    pass

def ima_eventdigest_ng_parse():
    pass


def ima_eventname_ng_parse():
    pass

def ima_eventsig_parse():
    pass

supported_fields ={
                   "n":ima_eventname_parse,
                   "d-ng":ima_eventdigest_ng_parse,
                   "n-ng":ima_eventname_ng_parse,
                   "sig":ima_eventsig_parse,
                   }
 
def read_measreument_list_bin(path,whitelist):
    raise Exception("not implementated fully yet")
    f = open(path, 'rb')

    while True:
        template={}
        (template['pcr'],template['digest'],template['name_len']) = read_unpack(f,"<I20sI")
        
        if template['name_len']>TCG_EVENT_NAME_LEN_MAX:
            raise Exception("Error event name too long %d",template['name_len'])
    
        name = read_unpack(f,"<%ds"%template['name_len'])[0]
        
        is_ima_template = name=='ima'
        if not is_ima_template:
            template['data_len']=read_unpack(f,"<I")[0]
            print "reading ima len %d"%template['data_len']
        else:
            template['data_len'] = SHA_DIGEST_LEN+TCG_EVENT_NAME_LEN_MAX+1
        
        template['data'] = read_unpack(f,"<%ds"%template['data_len'])[0]
        
        if is_ima_template:
            field_len = read_unpack(f,"<I")[0]
            extra_data=read_unpack(f,"<%ds"%field_len)[0]
            template['data']+= extra_data 
        
        print "record %s"%template
        
        if template['name'] not in defined_templates.keys():
            template['name']='ima'
        template['desc-fmt']=defined_templates[template['name']]
        
        #tokens = template['desc-fmt'].split('|') 
        
        import pdb; pdb.set_trace()
        
def process_measurement_list(lines,whitelist=None,m2w=None):
    errs = [0,0,0,0]
    runninghash = START_HASH
    
    for line in lines:
        line = line.strip()
        tokens = line.split()
        
        if line =='':
            continue
        if len(tokens)!=5:
            logger.error("invalid measurement list file line: -%s-"%(line))
            return None
        
        #print tokens
        #pcr = tokens[0]
        template_hash=tokens[1].decode('hex')
        mode = tokens[2]
        filedata = tokens[3]
        ftokens = filedata.split(":")
        filedata_algo = str(ftokens[0])
        filedata_hash = ftokens[1].decode('hex')
        path = str(line[line.find(filedata)+len(filedata)+1:])
        
        if mode !="ima-ng":
            raise Exception("Unsupported ima mode %s"%(mode))
        
        # this is some IMA weirdness
        if template_hash == START_HASH:
            template_hash = FF_HASH
        else:
            #verify template hash. yep this is terrible
            fmt = "<I%dsBB%dsI%dsB"%(len(filedata_algo),len(filedata_hash),len(path))
            # +2 for the : and the null terminator, and +1 on path for null terminator
            tohash=struct.pack(fmt,len(filedata_hash)+len(filedata_algo)+2,filedata_algo,ord(':'),ord('\0'),filedata_hash,len(path)+1,path,ord('\0'))
            expected_template_hash = hashlib.sha1(tohash).digest()
            
            if expected_template_hash!=template_hash:
                errs[0]+=1
                logger.warning("template hash for file %s does not match %s != %s"%(path,expected_template_hash.encode('hex'),template_hash.encode('hex')))     
                sys.exit(0)   
        
        # update hash
        runninghash = hashlib.sha1(runninghash+template_hash).digest()
        
        # write out the new hash
        if m2w is not None:
            m2w.write("%s %s\n"%(filedata_hash.encode('hex'),path))
        
        if whitelist is not None:
            accept_list = whitelist.get(path,None)
            if accept_list is None:
                logger.warning("File not found in whitelist: %s"%(path))
                errs[1]+=1
                continue
            if filedata_hash not in accept_list:
                logger.warning("Hashes for file %s don't match %s not in %s"%(path,filedata_hash.encode('hex'),[x.encode('hex') for x in accept_list]))
                errs[2]+=1
                continue
        
        errs[3]+=1
    
    print "ERRORS: template-hash %d fnf %d hash %d good %d"%tuple(errs)
    return runninghash

def read_whitelist(path):
    f = open(path, 'r')
    whitelist = {}
    for line in f:
        line = line.strip()
        spaces = re.search("(\s+)",line)
        if spaces is None:
            logger.error("invalid whitelist file line: %s"%(line))
            continue
        spaces = spaces.group(1)
        space = line.find(spaces)
        path = line[space+len(spaces):]
        if path.startswith("."):
            path = path[1:]
        if not path.startswith("/"):
            path = "/%s"%path
            
        tmp = whitelist.get(path,[])
        tmp.append(line[:space].decode('hex'))
        whitelist[path]=tmp
    f.close()
    return whitelist

def main(argv=sys.argv):
    #read_measreument_list_bin("/sys/kernel/security/ima/binary_runtime_measurements", None)
    
    print "reading white list"
    whitelist = read_whitelist('whitelist.txt')
    whitelist['boot_aggregate'] = START_HASH
    
    print "reading measurement list"
    m2w = open('measure2white.txt',"w")
    f = open(measure_path, 'r')
    lines = f.readlines()
    process_measurement_list(lines,whitelist,m2w)
    f.close()
    m2w.close()
    
    print "using m2w"
    
    wl2 = read_whitelist('measure2white.txt')
    
    process_measurement_list(lines,wl2)
    
    print "done"
        
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)