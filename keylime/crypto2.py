# '''
# DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
#
# This material is based upon work supported by the Assistant Secretary of Defense for
# Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
# FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
# material are those of the author(s) and do not necessarily reflect the views of the
# Assistant Secretary of Defense for Research and Engineering.
#
# Copyright 2015 Massachusetts Institute of Technology.
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
# 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
# rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
# above. Use of this work other than as specifically authorized by the U.S. Government may
# violate any copyrights that exist in this work.
# '''
#
# import base64
#
# # Crypto implementation using python cryptography package
#
# import cryptography.hazmat.primitives.asymmetric
# from cryptography.hazmat.primitives.ciphers import ( Cipher, algorithms, modes )
# from cryptography.hazmat.primitives import ( hmac,hashes,serialization )
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.backends import default_backend
# import os
#
# def rsa_import_pubkey(buf):
#     return serialization.load_pem_public_key(str(buf),backend=default_backend())
#
# def rsa_import_privkey(buf):
#     return serialization.load_pem_private_key(str(buf),password=None,backend=default_backend())
#
# def rsa_generate(size):
#     return cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(65537, 2048,default_backend())
#
# def rsa_export_pubkey(private_key):
#     return private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
#
# def rsa_export_privkey(private_key):
#     return private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
#
# def rsa_encrypt(key,message):
#     return key.encrypt(message,
#                        cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
#                                     algorithm=hashes.SHA1(),
#                                     label=None))
#
# def rsa_decrypt(key,ciphertext):
#     return key.decrypt(ciphertext,cryptography.hazmat.primitives.asymmetric.padding.OAEP(mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
#                                                algorithm=hashes.SHA1(),
#                                                label=None))
#
# def generate_random_key(size=32):
#     return os.urandom(size)
#
# def strbitxor(a,b):
#     a = bytearray(a)
#     b = bytearray(b)
#     retval = bytearray(len(b))
#     for i in range(len(a)):
#         retval[i] = a[i] ^ b[i]
#     return retval
#
# def kdf(password,salt):
#     mykdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=bytes(salt),iterations=100000,backend=default_backend())
#     return mykdf.derive(password)
#
# def do_hmac(key,value):
#     h = hmac.HMAC(key,hashes.SHA384(),default_backend())
#     h.update(value)
#     return h.finalize().encode('hex')
#
# aes_block_size = 16
#
# def _is_multiple_16(s):
#     """
#     Ensures string's length is a multple of 16
#     """
#     if not (len(s) % 16) == 0:
#         raise Exception("Ciphertext was not a multiple of 16 in length")
#
# def _has_iv_material(s):
#     """
#     Make sure enough material for IV in ciphertext
#     """
#     if len(s) < aes_block_size:
#         raise Exception("Ciphertext did not contain enough material for an IV")
#
# def encrypt(plaintext, key):
#     #Deal with the case when field is empty
#     if plaintext is None:
#         plaintext = ''
#
#     iv = generate_random_key(aes_block_size)
#     encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
#     cipher_text = encryptor.update(plaintext) + encryptor.finalize()
#     return base64.b64encode(iv+cipher_text+encryptor.tag)
#
# def decrypt(ciphertext, key):
#     ciphertext = base64.b64decode(ciphertext)
#
#     iv = ciphertext[:aes_block_size]
#     tag = ciphertext[-aes_block_size:]
#     ciphertext = bytes(ciphertext[aes_block_size:-aes_block_size])
#
#     decryptor = Cipher(algorithms.AES(key),
#                        modes.GCM(iv, tag),
#                        backend=default_backend()).decryptor()
#     return decryptor.update(ciphertext) + decryptor.finalize()
#
# def main():
#     message = b"a secret message!"
#     print "testing crypto..."
#
#     key = rsa_generate(2048)
#     pubkeypem = rsa_export_pubkey(key)
#     print pubkeypem
#     pubkey = rsa_import_pubkey(pubkeypem)
#
#     keypem = rsa_export_privkey(key)
#     print keypem
#     key = rsa_import_privkey(keypem)
#
#     ciphertext = rsa_encrypt(pubkey, message)
#     plain = rsa_decrypt(key, ciphertext)
#     print "rsa test %s"%(plain==message)
#
#     aeskey = kdf(message,'salty-McSaltface')
#     ciphertext = encrypt(message,aeskey)
#     print "aes ciphertext %s"%ciphertext
#     plaintext = decrypt(ciphertext,aeskey)
#     print "aes test passed %s"%(plaintext==message)
#
#     digest = do_hmac(aeskey,message)
#     print digest
#     aeskey2 = kdf(message,'salty-McSaltface')
#     print "hmac test passed %s"%(do_hmac(aeskey2,message)==digest)
#
# if __name__=="__main__":
#     main()