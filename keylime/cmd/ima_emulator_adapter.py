#!/usr/bin/python3
'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys
import select
import time
import itertools
from keylime.tpm.tpm_abstract import *
from keylime.tpm import tpm_obj

# get the tpm object
tpm = tpm_obj.getTPM(need_hw_tpm=True)

start_hash = ('0000000000000000000000000000000000000000')
ff_hash = ('ffffffffffffffffffffffffffffffffffffffff')

def ml_extend(ml,position,searchHash=None):
    global start_hash
    f = open(ml,'r')
    lines = itertools.islice(f, position, None)

    for line in lines:
        line = line.strip()
        tokens = line.split()

        if line =='':
            continue
        if len(tokens)<5:
            print("ERROR: invalid measurement list file line: -%s-"%(line))
            return position
        position += 1

        # get the filename roughly
        path = str(line[line.rfind(tokens[3])+len(tokens[3])+1:])
        template_hash=tokens[1]

        # this is some IMA weirdness
        if template_hash == start_hash:
            template_hash = ff_hash

        if searchHash is None:
            print("extending hash %s for %s"%(template_hash,path))
            #TODO: Add support for other hash algorithms
            tpm.extendPCR(common.IMA_PCR, template_hash, Hash_Algorithms.SHA1)
        else:
            # Let's only encode if its not a byte
            try:
                runninghash = start_hash.encode('utf-8')
            except AttributeError:
                pass
            # Let's only encode if its not a byte
            try:
                template_hash = template_hash.encode('utf-8')
            except AttributeError:
                pass

            runninghash = hashlib.sha1(runninghash+template_hash).digest()

            if runninghash == searchHash:
                print("Located last IMA file updated: %s"%(path))
                return position

    if searchHash is not None:
        raise Exception("Unable to find current measurement list position, Resetting the TPM emulator may be neccesary")

    return position


def main(argv=sys.argv):
    if not tpm.is_emulator():
        raise Exception("This stub should only be used with a TPM emulator")

    # initialize position in ML
    pos=0

    # check if pcr is clean
    pcrval = tpm.readPCR(common.IMA_PCR, Hash_Algorithms.SHA1)
    if pcrval != start_hash:
        print("Warning: IMA PCR is not empty, trying to find the last updated file in the measurement list...")
        pos = ml_extend(common.IMA_ML, 0, pcrval)

    print("Monitoring %s"%(common.IMA_ML))
    poll_object = select.poll()
    fd_object = open(common.IMA_ML, "r")
    number = fd_object.fileno()
    poll_object.register(fd_object,select.POLLIN|select.POLLPRI)

    while True:
        results = poll_object.poll()
        for result in results:
            if result[0] != number:
                continue
            pos = ml_extend(common.IMA_ML,pos)
            time.sleep(0.2)
    sys.exit(1)

if __name__ == '__main__':
    main()
