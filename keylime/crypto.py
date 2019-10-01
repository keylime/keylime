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

import base64
import hmac
import hashlib
import os
import secrets

# Crypto implementation using python cryptography package
from cryptography import exceptions
import cryptography.hazmat.primitives.asymmetric
from cryptography.hazmat.primitives.ciphers import ( Cipher, algorithms, modes )
from cryptography.hazmat.primitives import (hashes,serialization )
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

aes_block_size = 16

def rsa_import_pubkey(pubkey):
    """Import a public key
    We try / except this, as its possible that `pubkey` can arrive as either str or bytes.
    """
    try:
        return serialization.load_pem_public_key(pubkey,backend=default_backend())
    except:
        return serialization.load_pem_public_key(pubkey.encode('utf-8'),backend=default_backend())

def rsa_import_privkey(privkey):
    """Import a private key
    We try / except this, as its possible that `privkey` can arrive as either str or bytes.
    """
    try:
        return serialization.load_pem_private_key(privkey,password=None,backend=default_backend())
    except:
        return serialization.load_pem_private_key(privkey.encode('utf-8'),password=None,backend=default_backend())


def rsa_generate(size):
    """ Generate private key  """
    private_key = generate_private_key(
        65537,
        size,
        default_backend()
        )
    return private_key


def get_public_key(private_key):
    """ Derive public key from private key  """
    public_key = private_key.public_key()
    return public_key


def rsa_sign(key, message):
    """ RSA sign message  """
    signature = key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    return signature

def rsa_verify(public_key, message, signature):
    """ RSA verify message  """
    verifier = public_key.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    verifier.update(message)
    try:
        verifier.verify()
    except exceptions.InvalidSignature:
        return False
    except Exception as e:
        raise e
    return True


def rsa_export_pubkey(private_key):
    """ export public key  """
    return private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

def rsa_export_privkey(private_key):
    """ export private key  """
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())

def rsa_encrypt(key,message):
    """ RSA encrypt message  """
    return key.encrypt(bytes(message),
                       cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                                    algorithm=hashes.SHA1(),
                                    label=None))

def rsa_decrypt(key,ciphertext):
    """ RSA decrypt message  """
    return key.decrypt(ciphertext,cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                                               algorithm=hashes.SHA1(),
                                               label=None))


def get_random_bytes(size):
    """ Generate random bytes  """
    return secrets.token_bytes(size)

def generate_random_key(size=32):
    """ Generate random key using urandom wrapper  """
    return os.urandom(size)

def strbitxor(a,b):
    a = bytearray(a)
    b = bytearray(b)
    retval = bytearray(len(b))
    for i in range(len(a)):
        retval[i] = a[i] ^ b[i]
    return bytes(retval)

def kdf(password,salt):
    mykdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=bytes(salt, encoding='utf8'),iterations=100000,backend=default_backend())
    return mykdf.derive(password.encode('utf-8'))

def do_hmac(key,value):
    """ Generate HMAC  """
    h = hmac.new(key, msg=None, digestmod=hashlib.sha384)
    h.update(value.encode('utf-8'))
    return h.hexdigest()


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
    if len(s) < aes_block_size:
        raise Exception("Ciphertext did not contain enough material for an IV")

def encrypt(plaintext, key):
    """ Encrypt object """
    if plaintext is None:
        plaintext = b''
    iv = generate_random_key(aes_block_size)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    # The following try/except captures both str and bytes
    try:
        cipher_text = encryptor.update(plaintext.encode('ascii')) + encryptor.finalize()
    except:
        cipher_text = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(iv+cipher_text+encryptor.tag)

def decrypt(ciphertext, key):
    """ Decrypt object """
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:aes_block_size]
    tag = ciphertext[-aes_block_size:]
    ciphertext = bytes(ciphertext[aes_block_size:-aes_block_size])

    decryptor = Cipher(algorithms.AES(key),
                       modes.GCM(iv, tag),
                       backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


