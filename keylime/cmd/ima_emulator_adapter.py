#!/usr/bin/python3
'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import codecs
import sys
import select
import time
import itertools
import argparse

from keylime.tpm.tpm_main import tpm
from keylime.tpm.tpm_abstract import config
from keylime.common import algorithms
from keylime import ima_ast

# Instaniate tpm
tpm_instance = tpm(need_hw_tpm=True)


def measure_list(file_path, position, ima_hash_alg, pcr_hash_alg, search_val=None):
    f = open(file_path, encoding="utf-8")
    lines = itertools.islice(f, position, None)

    runninghash = ima_ast.get_START_HASH(pcr_hash_alg)

    if search_val is not None:
        search_val = codecs.decode(search_val.encode('utf-8'), 'hex')

    for line in lines:
        line = line.strip()
        position += 1

        entry = ima_ast.Entry(line, None, ima_hash_alg=ima_hash_alg, pcr_hash_alg=pcr_hash_alg)

        if search_val is None:
            val = codecs.encode(entry.pcr_template_hash, 'hex').decode("utf8")
            tpm_instance.extendPCR(config.IMA_PCR, val, pcr_hash_alg)
        else:
            runninghash = pcr_hash_alg.hash(runninghash + entry.pcr_template_hash)
            if runninghash == search_val:
                return position

    if search_val is not None:
        raise Exception("Unable to find current measurement list position, Resetting the TPM emulator may be neccesary")

    return position


def main(argv=sys.argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--hash_algs', nargs='*', default=['sha1'],  help='PCR banks hash algorithms')
    parser.add_argument('-i', '--ima-hash-alg', default='sha1', help='Set hash algorithm that is used in IMA log')
    parser.add_argument('-f', '--ima-log', default=config.IMA_ML, help='path to the IMA log')
    args = parser.parse_args(argv[1:])

    if not tpm_instance.is_emulator():
        raise Exception("This stub should only be used with a TPM emulator")

    ima_hash_alg = algorithms.Hash(args.ima_hash_alg)
    position = {}
    for pcr_hash_alg in args.hash_algs:
        pcr_hash_alg = algorithms.Hash(pcr_hash_alg)
        position[pcr_hash_alg] = 0

    for pcr_hash_alg in position.keys():
        pcr_val = tpm_instance.readPCR(config.IMA_PCR, pcr_hash_alg)
        if codecs.decode(pcr_val.encode('utf-8'), 'hex') != ima_ast.get_START_HASH(pcr_hash_alg):
            print(f"Warning: IMA PCR is not empty for hash algorithm {pcr_hash_alg}, "
                  "trying to find the last updated file in the measurement list...")
            position[pcr_hash_alg] = measure_list(args.ima_log, position[pcr_hash_alg],
                                                  ima_hash_alg, pcr_hash_alg, pcr_val)

    print(f"Monitoring {args.ima_log}")
    poll_object = select.poll()
    fd_object = open(args.ima_log, encoding="utf-8")
    number = fd_object.fileno()
    poll_object.register(fd_object, select.POLLIN | select.POLLPRI)

    try:
        while True:
            results = poll_object.poll()
            for result in results:
                if result[0] != number:
                    continue
                for pcr_hash_alg, pos in position.items():
                    position[pcr_hash_alg] = measure_list(args.ima_log, pos, ima_hash_alg, pcr_hash_alg)

                time.sleep(0.2)
    except (SystemExit, KeyboardInterrupt):
        fd_object.close()
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv)
