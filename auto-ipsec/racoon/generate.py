#!/usr/bin/env python

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys
import argparse
import os
import shutil

IPSEC_TOOLS_CONF="flush;\n\
spdflush;\n"

IPSEC_TOOLS_SUBNET="spdadd 0.0.0.0/0 %s any -P out ipsec esp/transport//require;\n\
spdadd %s 0.0.0.0/0 any -P in ipsec esp/transport//require;\n"

IPSEC_TOOLS_EXCLUDE="spdadd 0.0.0.0/0 %s any -P out none;\n\
spdadd %s 0.0.0.0/0 any -P in none;\n"

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

    with open('ipsec-extra/ipsec-tools.conf','w') as f:
        f.write(IPSEC_TOOLS_CONF)
        for subnet in subnets:
            f.write(IPSEC_TOOLS_SUBNET%(subnet,subnet))
        for subnet in exclude:
            f.write(IPSEC_TOOLS_EXCLUDE%(subnet,subnet))

    with open("ipsec-extra/action_list",'w') as f:
        f.write("local_action_update_crl,local_action_deletesa\n")

    shutil.copy("src/local_action_update_crl.py","ipsec-extra")
    shutil.copy("src/local_action_deletesa.py",'ipsec-extra')
    shutil.copy("src/autorun.sh",'ipsec-extra')
    shutil.copy("src/racoon.conf",'ipsec-extra')

    print("include directory ipsec-extra when using keylime in cert mode to enable ipsec")


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print(e)
