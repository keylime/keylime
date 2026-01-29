import base64
import hashlib
import hmac
import os
import secrets
import uuid
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

AES_BLOCK_SIZE = 16


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
        encryption_algorithm=(
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        ),
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
    iv = generate_random_key(AES_BLOCK_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    cipher_text = encryptor.update(plaintext) + encryptor.finalize()
    assert isinstance(encryptor, AEADEncryptionContext)
    return base64.b64encode(iv + cipher_text + encryptor.tag)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt object"""
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES_BLOCK_SIZE]
    tag = ciphertext[-AES_BLOCK_SIZE:]
    ciphertext = bytes(ciphertext[AES_BLOCK_SIZE:-AES_BLOCK_SIZE])

    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def hash_token_for_log(token: str, length: int = 8) -> str:
    """Hash a token for safe logging.

    Returns the first `length` characters of the SHA256 hash of the token.
    This allows tokens to be identified in logs for debugging purposes without
    exposing the actual token value.

    Args:
        token: The authentication token to hash
        length: Number of hash characters to return (default: 8)

    Returns:
        First `length` characters of SHA256 hash, or empty string if token is empty
    """
    if not token:
        return ""
    return hashlib.sha256(token.encode()).hexdigest()[:length]


# PBKDF2 parameters for token hashing (OWASP 2023+ / FIPS-140 compliant)
_TOKEN_HASH_ITERATIONS = 600_000  # OWASP 2023 minimum for PBKDF2-HMAC-SHA256
_TOKEN_SALT_LENGTH = 16  # 128 bits, minimum recommended by NIST


def generate_token_salt() -> str:
    """Generate a random salt for token hashing.

    Generates a cryptographically secure random salt as recommended
    by NIST SP 800-132.

    Returns:
        Hex-encoded random salt (32 characters for 16 bytes)
    """
    return secrets.token_bytes(_TOKEN_SALT_LENGTH).hex()


def generate_session_token(session_id: str, secret_bytes: int = 32) -> str:
    """Generate a session token that embeds the session_id.

    Token format: {session_id}.{random_secret}
    The session_id prefix allows O(1) lookup by primary key.
    The random secret provides the entropy for security.

    Args:
        session_id: The session UUID to embed in the token
        secret_bytes: Number of random bytes for the secret (default: 32)

    Returns:
        Token string in format "session_id.secret"

    Raises:
        ValueError: If session_id is empty
    """
    if not session_id:
        raise ValueError("Session ID cannot be empty")
    secret = secrets.token_urlsafe(secret_bytes)
    return f"{session_id}.{secret}"


def parse_session_token(token: str) -> tuple[str, str]:
    """Parse a session token to extract session_id and secret.

    Args:
        token: The full token in format "session_id.secret"

    Returns:
        Tuple of (session_id, secret)

    Raises:
        ValueError: If token format is invalid
    """
    if not token or "." not in token:
        raise ValueError("Invalid token format")
    session_id, secret = token.split(".", 1)
    if not session_id or not secret:
        raise ValueError("Invalid token format: missing session_id or secret")
    try:
        uuid.UUID(session_id)
    except ValueError as exc:
        raise ValueError("Invalid token format: session_id is not a valid UUID") from exc
    return session_id, secret


def hash_token_for_storage(token: str, salt: str) -> str:
    """Hash a token for secure storage using PBKDF2 with HMAC-SHA-256.

    Uses PBKDF2 with a per-token salt as recommended by NIST SP 800-132
    and OWASP 2023. This provides:
    - Protection against rainbow table attacks (unique salt per token)
    - Computational cost for brute-force attempts (600k iterations per OWASP 2023)
    - FIPS-140 compliant key derivation

    Args:
        token: The authentication token to hash
        salt: Hex-encoded salt (from generate_token_salt())

    Returns:
        Hex-encoded PBKDF2 hash (64 characters for 32 bytes)

    Raises:
        ValueError: If token or salt is empty/invalid
    """
    if not token:
        raise ValueError("Token cannot be empty for storage")
    if not salt or len(salt) != _TOKEN_SALT_LENGTH * 2:
        raise ValueError(f"Salt must be {_TOKEN_SALT_LENGTH * 2} hex characters")

    token_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt),
        iterations=_TOKEN_HASH_ITERATIONS,
        backend=default_backend(),
    )
    return token_kdf.derive(token.encode()).hex()


def verify_token_hash(token: str, salt: str, stored_hash: str) -> bool:
    """Verify a token against a stored PBKDF2 hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        token: The plaintext token to verify
        salt: Hex-encoded salt used when the hash was created
        stored_hash: The hex-encoded PBKDF2 hash from the database

    Returns:
        True if the token matches the stored hash, False otherwise
    """
    if not token or not salt or not stored_hash:
        return False

    try:
        computed_hash = hash_token_for_storage(token, salt)
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False
