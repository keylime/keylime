import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional, Union

# Crypto implementation using python cryptography package
from cryptography import exceptions, x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey, generate_private_key
from cryptography.hazmat.primitives.ciphers import AEADEncryptionContext, Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

aes_block_size = 16


def rsa_import_pubkey(pubkey: Union[str, bytes]) -> RSAPublicKey:
    """Import a public key
    We try / except this, as its possible that `pubkey` can arrive as either str or bytes.
    """
    if isinstance(pubkey, bytes):
        public_key = serialization.load_pem_public_key(pubkey, backend=default_backend())
    elif isinstance(pubkey, str):
        public_key = serialization.load_pem_public_key(pubkey.encode("utf-8"), backend=default_backend())
    else:
        raise TypeError(f"Unsupported raw pubkey data passed to rsa_import_pubkey: {type(pubkey).__name__}")
    if not isinstance(public_key, RSAPublicKey):
        raise Exception(f"Given public key is not an RSA public key but of type {type(public_key).__name__}")
    return public_key


def rsa_import_privkey(privkey: Union[str, bytes], password: Optional[bytes] = None) -> RSAPrivateKey:
    """Import a private key
    We try / except this, as its possible that `privkey` can arrive as either str or bytes.
    """
    if isinstance(privkey, bytes):
        private_key = serialization.load_pem_private_key(privkey, password, backend=default_backend())
    elif isinstance(privkey, str):
        private_key = serialization.load_pem_private_key(privkey.encode("utf-8"), password, backend=default_backend())
    else:
        raise TypeError(f"Unsupported raw privkey data passed to rsa_import_privkey: {type(privkey).__name__}")
    if not isinstance(private_key, RSAPrivateKey):
        raise Exception(f"Given private key is not an RSA private key but of type {type(private_key).__name__}")
    return private_key


def x509_import_pubkey(pubkey: bytes) -> RSAPublicKey:
    key = x509.load_pem_x509_certificate(pubkey, backend=default_backend())
    public_key = key.public_key()
    if not isinstance(public_key, RSAPublicKey):
        raise Exception(
            f"Given x509 certificate does not have an RSA public key but one of type {type(public_key).__name__}"
        )
    return public_key


def rsa_generate(size: int) -> RSAPrivateKey:
    """Generate private key"""
    private_key = generate_private_key(65537, size, default_backend())
    return private_key


def get_public_key(private_key: RSAPrivateKey) -> RSAPublicKey:
    """Derive public key from private key"""
    public_key = private_key.public_key()
    return public_key


def rsa_sign(key: RSAPrivateKey, message: bytes, paddingt: str = "internal") -> bytes:
    """RSA sign message"""
    _padding: Union[padding.PSS, padding.PKCS1v15]
    if paddingt == "internal":
        _padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

    elif paddingt == "default":
        _padding = padding.PKCS1v15()
    else:
        raise ValueError

    signature = key.sign(message, _padding, hashes.SHA256())
    return base64.b64encode(signature)


def rsa_verify(public_key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """RSA verify message"""
    try:
        public_key.verify(
            base64.b64decode(signature),
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except exceptions.InvalidSignature:
        return False
    except Exception as e:
        raise e
    return True


def rsa_export_pubkey(private_key: RSAPrivateKey) -> bytes:
    """export public key"""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def rsa_export_privkey(private_key: RSAPrivateKey, password: Optional[str] = None) -> bytes:
    """export private key"""

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption(),
    )


def rsa_encrypt(key: RSAPublicKey, message: bytes) -> bytes:
    """RSA encrypt message"""
    return key.encrypt(
        bytes(message),
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def rsa_decrypt(key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """RSA decrypt message"""
    return key.decrypt(
        ciphertext,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )


def get_random_bytes(size: int) -> bytes:
    """Generate random bytes"""
    return secrets.token_bytes(size)


def generate_random_key(size: int = 32) -> bytes:
    """Generate random key using urandom wrapper"""
    return os.urandom(size)


def strbitxor(a: bytes, b: bytes) -> bytes:
    a_bytes = bytearray(a)
    b_bytes = bytearray(b)
    retval = bytearray(len(b_bytes))
    for i, _ in enumerate(a_bytes):
        retval[i] = a_bytes[i] ^ b_bytes[i]
    return bytes(retval)


def kdf(password: str, salt: str) -> bytes:
    mykdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt, encoding="utf8"),
        iterations=100000,
        backend=default_backend(),
    )
    return mykdf.derive(password.encode("utf-8"))


def do_hmac(key: bytes, value: str) -> str:
    """Generate HMAC"""
    h = hmac.new(key, msg=None, digestmod=hashlib.sha384)
    h.update(value.encode("utf-8"))
    return h.hexdigest()


def encrypt(plaintext: Optional[bytes], key: bytes) -> bytes:
    """Encrypt object"""
    if plaintext is None:
        plaintext = b""
    iv = generate_random_key(aes_block_size)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    cipher_text = encryptor.update(plaintext) + encryptor.finalize()
    assert isinstance(encryptor, AEADEncryptionContext)
    return base64.b64encode(iv + cipher_text + encryptor.tag)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt object"""
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:aes_block_size]
    tag = ciphertext[-aes_block_size:]
    ciphertext = bytes(ciphertext[aes_block_size:-aes_block_size])

    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
