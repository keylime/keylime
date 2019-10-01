#!/usr/bin/python3

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
import os
import base64

from keylime import crypto

def usage():
	print("please pass in a file input file to encrypt")
	sys.exit(-1)

def encrypt(contents):
	k = crypto.generate_random_key(32)
	v = crypto.generate_random_key(32)
	u = crypto.strbitxor(k,v)
	ciphertext= crypto.encrypt(contents,k)

	try:
	   recovered = crypto.decrypt(ciphertext,k).decode('utf-8')
	except UnicodeDecodeError:
		recovered = crypto.decrypt(ciphertext,k)

	if recovered != contents:
		raise Exception("Test decryption failed")
	return {'u':u,'v':v,'k':k,'ciphertext':ciphertext}

def main(argv=sys.argv):
	if len(argv)<2:
		usage()

	infile = argv[1]

	if not os.path.isfile(infile):
		print("ERROR: File %s not found."%infile)
		usage()

	f = open(infile,'r')
	contents = f.read()

	ret = encrypt(contents)

	print("Writing keys to content_keys.txt")
	f = open('content_keys.txt','w')
	f.write(base64.b64encode(ret['k']))
	f.write('\n')
	f.write(base64.b64encode(ret['v']))
	f.write('\n')
	f.write(base64.b64encode(ret['u']))
	f.write('\n')
	f.close()

	print("Writing encrypted data to content_payload.txt")
	f = open('content_payload.txt','w')
	f.write(ret['ciphertext'])
	f.close()

if __name__=="__main__":
	main()
