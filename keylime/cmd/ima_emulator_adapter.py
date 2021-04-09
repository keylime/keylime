#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys
import select
import time
import itertools

from keylime.tpm.tpm_main import tpm
from keylime.tpm.tpm_abstract import config, hashlib
from keylime.common import algorithms

# Instaniate tpm
tpm_instance = tpm(need_hw_tpm=True)

START_HASH = '0000000000000000000000000000000000000000'
FF_HASH = 'ffffffffffffffffffffffffffffffffffffffff'


def ml_extend(ml, position, searchHash=None):
    f = open(ml, 'r')
    lines = itertools.islice(f, position, None)

    for line in lines:
        line = line.strip()
        tokens = line.split()

        if line == '':
            continue
        if len(tokens) < 5:
            print("ERROR: invalid measurement list file line: -%s-" % (line))
            return position
        position += 1

        # get the filename roughly
        path = str(line[line.rfind(tokens[3]) + len(tokens[3]) + 1:])
        template_hash = tokens[1]

        # this is some IMA weirdness
        if template_hash == START_HASH:
            template_hash = FF_HASH

        if searchHash is None:
            print("extending hash %s for %s" % (template_hash, path))
            # TODO: Add support for other hash algorithms
            tpm_instance.extendPCR(config.IMA_PCR, template_hash, algorithms.Hash.SHA1)
        else:
            # Let's only encode if its not a byte
            try:
                runninghash = START_HASH.encode('utf-8')
            except AttributeError:
                pass
            # Let's only encode if its not a byte
            try:
                template_hash = template_hash.encode('utf-8')
            except AttributeError:
                pass

            runninghash = hashlib.sha1(runninghash + template_hash).digest()

            if runninghash == searchHash:
                print("Located last IMA file updated: %s" % (path))
                return position

    if searchHash is not None:
        raise Exception(
            "Unable to find current measurement list position, Resetting the TPM emulator may be neccesary")

    return position


def main():
    if not tpm_instance.is_emulator():
        raise Exception("This stub should only be used with a TPM emulator")

    # initialize position in ML
    pos = 0

    # check if pcr is clean
    pcrval = tpm_instance.readPCR(config.IMA_PCR, algorithms.Hash.SHA1)
    if pcrval != START_HASH:
        print("Warning: IMA PCR is not empty, trying to find the last updated file in the measurement list...")
        pos = ml_extend(config.IMA_ML, 0, pcrval)

    print("Monitoring %s" % (config.IMA_ML))
    poll_object = select.poll()
    fd_object = open(config.IMA_ML, "r")
    number = fd_object.fileno()
    poll_object.register(fd_object, select.POLLIN | select.POLLPRI)

    while True:
        results = poll_object.poll()
        for result in results:
            if result[0] != number:
                continue
            pos = ml_extend(config.IMA_ML, pos)
            time.sleep(0.2)
    sys.exit(1)


if __name__ == '__main__':
    main()
