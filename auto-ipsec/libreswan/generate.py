#!/usr/bin/env python

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2018 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''

import sys
import argparse
import os
import shutil

def usage():
    print("ERROR: you must specify a configuration file with one or more subnets for ipsec")
    print("\tExample: generate.py file.txt")
    print("====file.txt format ====")
    print("# Any file starting with # will be ignored")
    print("# All Subnets after ipsec are enabled by default")
    print("ipsec")
    print("192.168.0.0/24")
    print("172.22.2.4/32")
    print("# All subnets after exclude will not use ipsec")
    print("exclude")
    print("192.168.0.1/32")
    sys.exit(1)

def main(argv=sys.argv):
    if len(argv)<2:
        usage()
    
    subnets=None
    exclude=None
    with open(argv[1],'r') as f:
        for line in f:
            line = line.strip()
            if line[0]=='#':
                continue

            if line=='ipsec':
                subnets=[]
                continue
            
            if line=='exclude':
                exclude=[]
                continue
            
            if exclude is not None:
                exclude.append(line)
                continue
            
            if subnets is not None:
                subnets.append(line)
    
    if subnets is None:
        usage()
    if exclude is None:
        exclude=[]
  
    print("Preparing extra files for ipsec config in directory: ipsec-extra")
    print("enabling ipsec for subnets:  %s"%subnets)
    print("disabling ipsec for subnets: %s"%exclude)
    
    if os.path.exists('ipsec-extra'):
        shutil.rmtree('ipsec-extra')
    os.mkdir("ipsec-extra")
    
    with open('ipsec-extra/private','w') as f:
        for subnet in subnets:
            f.write("%s\n"%(subnet))
            
    with open('ipsec-extra/clear','w') as f:
        for subnet in exclude:
            f.write("%s\n"%(subnet))
            
    with open("ipsec-extra/action_list",'w') as f:
        f.write("local_action_update_crl,local_action_crashsa\n")
    shutil.copy("src/local_action_update_crl.py","ipsec-extra")
    shutil.copy("src/local_action_crashsa.py",'ipsec-extra')

    shutil.copy("src/autorun.sh",'ipsec-extra')
    shutil.copy("src/ipsec.conf",'ipsec-extra')
    shutil.copy("src/oe-keylime.conf",'ipsec-extra')

    print("include directory ipsec-extra when using keylime in cert mode to enable ipsec")
    
    
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print(e)