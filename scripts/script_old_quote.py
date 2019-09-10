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

from keylime.tpm_quote import create_quote, check_quote
from base64 import b64encode
from timeit import timeit
from keylime.crypto import rsa_import_key

######## actual configurable things
# qruns - how many times to run create_quote
qruns = 1

# cruns - how many times to run check_quote
cruns = 100000

# tcikey - filename of the tci rsa key
tcikey = 'tci_rsa_key'

# quotefile - filename of quote output from create_quote
quotefile = 'quote.bin'

# aikfile - filename of aik publickey (binary)
aikfile = 'aik_pubkey.bin'

# nonce - a nonce
nonce = 42

# pcrmask - a pcrmask
pcrmask = "0x800"

######## real artisanal code
# open generated (private) trusted cloud init key
# and export the public version
f = open(tcikey, 'r')
a = rsa_import_key(f.read())
quote_key = a.publickey().exportKey()

# initialize functions so that timeit will work
qsetup='from __main__ import nonce,quote_key,pcrmask,create_quote'

# do the thing
q = timeit('create_quote(nonce,quote_key,pcrmask)', number=qruns, setup=qsetup)
print("create_quote: %d runs, total time %f, avg %f per run" % (qruns,q,q/qruns))

# take generated quote and AIK pubkey and read 'em
binquotefile = open(quotefile, 'r')
binquote = b64encode(binquotefile.read().encode("zlib"))
binaikfile = open(aikfile, 'r')
binaik = b64encode(binaikfile.read())

# initialize functions so that timeit will work
csetup='from __main__ import nonce,quote_key,binquote,binaik,check_quote'

# do the thing
c = timeit('check_quote(nonce,quote_key,binquote,binaik)', number=cruns, setup=csetup)
print("check_quote: %d runs, total time %f, avg %f per run" % (cruns,c,c/cruns))
