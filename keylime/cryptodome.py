'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import base64

# Crypto implementation using Cryptodomex package

from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import HMAC, SHA384
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Protocol import KDF
from Cryptodome.Signature import pss


def rsa_import_pubkey(buf):
    return RSA.importKey(buf)


def rsa_import_privkey(buf, password=None):
    return RSA.importKey(buf, password)


def rsa_export_pubkey(privkey):
    return privkey.publickey().exportKey()


def rsa_export_privkey(privkey):
    return privkey.exportKey()


def rsa_generate(size):
    return RSA.generate(size)


def rsa_sign(key, message):
    h = SHA384.new(message)
    signature = pss.new(key).sign(h)
    return base64.b64encode(signature)


def rsa_verify(pubkey, received_message, signature):
    h = SHA384.new(received_message)
    verifier = pss.new(pubkey)
    try:
        verifier.verify(h, base64.b64decode(signature))
        return True
    except ValueError:
        return False

# don't use tpm randomness on encrypt to avoid contention for TPM


def rsa_encrypt(key, message):
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)


def rsa_decrypt(key, ciphertext):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)


def generate_random_key(size=32):
    return get_random_bytes(size)


def strbitxor(a, b):
    a = bytearray(a)
    b = bytearray(b)
    retval = bytearray(len(b))
    for i, _ in enumerate(a):
        retval[i] = a[i] ^ b[i]
    return retval


def kdf(password, salt):
    return KDF.PBKDF2(password, salt, dkLen=32, count=2000)


def do_hmac(key, value):
    value = value.encode('utf-8')
    # Let's only encode if its not a byte
    try:
        key = key.encode('utf-8')
    except AttributeError:
        pass

    h = HMAC.new(key, value, digestmod=SHA384.new())
    return h.hexdigest()


def sha2(value):
    return SHA384.new(data=value).hexdigest()


def _pad(s):
    '''
    Returns the string padded with its length such
    that is a multiple of 16
    Appends 10* at the bit level. Following ISO/IEC 9797-1
    - padding mode 2
    '''
    # Let's only encode if its not a byte
    try:
        s = s.encode('utf-8')
    except AttributeError:
        pass
    pad_len = AES.block_size - (len(s) % AES.block_size) - 1
    padding = b'\x80' + b'\0' * pad_len
    return s + padding


def _strip_pad(s):
    '''
    Strips the padding from the string
    '''
    return s.rstrip(b'\0')[:-1]


def _is_multiple_16(s):
    """
    Ensures string's length is a multple of 16
    """
    if not (len(s) % 16) == 0:
        raise Exception("Ciphertext was not a multiple of 16 in length")


def _has_iv_material(s):
    """
    Make sure enough material for IV in ciphertext
    """
    if len(s) < AES.block_size:
        raise Exception("Ciphertext did not contain enough material for an IV")


def encrypt(plaintext, key):
    # Deal with the case when field is empty
    if plaintext is None:
        plaintext = b''

    nonce = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    (cipher_text, digest) = cipher.encrypt_and_digest(_pad(plaintext))
    return base64.b64encode(nonce + cipher_text + digest)


def decrypt(ciphertext, key):

    ciphertext = base64.b64decode(ciphertext)

    # error handling
    _has_iv_material(ciphertext)
    _is_multiple_16(ciphertext)

    nonce = ciphertext[:AES.block_size]
    digest = ciphertext[-AES.block_size:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_text = bytes(ciphertext[AES.block_size:-AES.block_size])
    return _strip_pad(cipher.decrypt_and_verify(cipher_text, digest))
