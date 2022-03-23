#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys
import os
import base64

from keylime import crypto


def usage():
    print("Please pass in a file input file to encrypt")
    sys.exit(-1)


def encrypt(contents):
    k = crypto.generate_random_key(32)
    v = crypto.generate_random_key(32)
    u = crypto.strbitxor(k, v)
    ciphertext = crypto.encrypt(contents, k)

    try:
        recovered = crypto.decrypt(ciphertext, k).decode('utf-8')
    except UnicodeDecodeError:
        recovered = crypto.decrypt(ciphertext, k)

    if recovered != contents:
        raise Exception("Test decryption failed")
    return {'u': u, 'v': v, 'k': k, 'ciphertext': ciphertext}


def main(argv=sys.argv):  #pylint: disable=dangerous-default-value
    if len(argv) < 2:
        usage()

    infile = argv[1]

    if not os.path.isfile(infile):
        print(f"ERROR: File %s not found. {infile}")
        usage()

    with open(infile, encoding="utf-8") as f:
        contents = f.read()

    ret = encrypt(contents)

    print("Writing keys to content_keys.txt")
    with open('content_keys.txt', 'w', encoding="utf-8") as f:
        f.write(base64.b64encode(ret['k']).decode('utf-8'))
        f.write('\n')
        f.write(base64.b64encode(ret['v']).decode('utf-8'))
        f.write('\n')
        f.write(base64.b64encode(ret['u']).decode('utf-8'))
        f.write('\n')

    print("Writing encrypted data to content_payload.txt")
    with open('content_payload.txt', 'w', encoding="utf-8") as f:
        f.write(ret['ciphertext'].decode('utf-8'))


if __name__ == "__main__":
    main()
