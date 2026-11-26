"""JWT signing capability for the V3 evidence verification API.

This module provides the verifier with the ability to sign a set of
claims as a JWT (RFC 7519) using a configured asymmetric signing key,
as specified by enhancement-133 (EAT/EAR signed results). It owns:

- algorithm policy: a denylist (``none`` and the symmetric HS* family)
  plus a structural requirement that the signing key is asymmetric;
- key loading from PEM files, with optional password-based decryption;
- key auto-generation and persistence when no key is configured;
- the standard claims (``iss``, ``iat``, ``nbf``, ``exp``, ``jti``)
  and the ``kid`` header, derived as an RFC 7638 JWK thumbprint.

The JWKS endpoint (SECENGSP-12709) and issuer resolution (SECENGSP-12719)
are handled elsewhere; until an issuer is set, ``JwtSigner.sign()``
refuses to produce tokens.

The signer is initialized by the ``keylime_verifier`` entrypoint
(``keylime.cmd.verifier:main``) before workers are forked; the legacy
``cloud_verifier_tornado.main()`` path does not construct it.
"""

import base64
import fcntl
import json
import os
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Tuple

from jwcrypto.common import JWException
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from keylime import keylime_logging

logger = keylime_logging.init_logging("jwt")

# Algorithm denylist: "none" disables signing entirely; HS* are symmetric
# and must never be used here (the public key is published via the JWKS
# endpoint, so a symmetric secret would be disclosed). Any asymmetric
# algorithm supported by jwcrypto is accepted.
DENIED_ALGORITHMS = frozenset({"none", "HS256", "HS384", "HS512"})

# Key types that may sign JWTs. "oct" (symmetric) is always rejected,
# independently of the algorithm string, so the symmetric family is
# closed by construction rather than by name matching alone. "AKP"
# (algorithm key pairs, e.g. ML-DSA) is admitted so that PQC keys work
# wherever the installed jwcrypto supports them: on builds without AKP
# support no such key can be constructed or imported in the first place,
# so the entry is inert there and the capability is gated by the library
# itself, not by a version check (same approach as the registrar's
# DevID support degrading on older python-cryptography).
ASYMMETRIC_KEY_TYPES = frozenset({"EC", "RSA", "OKP", "AKP"})

# Mapping of the algorithms we can auto-generate keys for, to the key
# type and curve/size parameters jwcrypto expects. This map is the only
# place algorithm-specific generation logic lives; adding a new family
# (e.g., ML-DSA once jwcrypto supports generating it) is one entry.
ALGORITHM_KEY_PARAMS: Dict[str, Tuple[str, Optional[str]]] = {
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "EdDSA": ("OKP", "Ed25519"),
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
}

# Curve required for each EC algorithm (RFC 7518); jwcrypto does not
# enforce the alg/curve binding itself. The curve lives in
# ALGORITHM_KEY_PARAMS above (single source for both checks and
# generation).

# Curves accepted for the EdDSA algorithm. RFC 8037 section 3.1 defines
# the EdDSA variant by the OKP key subtype and registers both Ed25519
# and Ed448, so an operator-provided Ed448 key signs with alg "EdDSA"
# like an Ed25519 one. Auto-generation always produces Ed25519 (the
# first entry); Montgomery curves (X25519/X448) are key-agreement only
# and stay rejected.
EDDSA_CURVES = frozenset({"Ed25519", "Ed448"})

# Key generation parameters for RSA (auto-generation only; operator keys
# only need to pass the minimum modulus size below).
RSA_GENERATION_SIZE = 3072
# Reject smaller keys; warn at exactly this size. NIST SP 800-131A
# disallows RSA-2048 for signing after 2030, so the intent is to raise
# this floor to 3072 in a future release.
MINIMUM_RSA_MODULUS_SIZE = 2048

# Token lifetime bounds (seconds).
DEFAULT_EXPIRATION_SECONDS = 300
MAXIMUM_EXPIRATION_SECONDS = 86400

# JWT "typ" header value (hardcoded per the design; not configurable).
TOKEN_TYPE = "JWT"

# Auto-generated key persistence location, relative to config.WORK_DIR.
AUTOGEN_KEY_DIRNAME = "signing"
AUTOGEN_KEY_FILENAME = "jwt_signing_key.pem"


class JwtSigningError(Exception):
    """Raised when JWT signing cannot be performed or configured."""


class JwtKeyError(JwtSigningError):
    """Raised when a signing key file cannot be read or parsed."""


class JwtKeyFileAbsentError(JwtKeyError):
    """Raised when a signing key file does not exist.

    A subclass so the auto-generation path can distinguish an absent file
    (generate one) from a present-but-unreadable one (hard error). Callers
    that treat all key errors as fatal catch the JwtKeyError parent and
    are unaffected.
    """


class JwtKeyIncompatibleError(JwtSigningError):
    """Raised when a signing key does not match the configured algorithm.

    Carries the kid of the rejected key (when known) so callers can log
    the old/new kid pair around a regeneration.
    """

    def __init__(self, message: str, kid: Optional[str] = None) -> None:
        super().__init__(message)
        self.kid = kid


def _validate_algorithm(algorithm: str) -> str:
    """Check the algorithm against the denylist and return it (stripped).

    JOSE algorithm names are case-sensitive: only surrounding whitespace
    is removed, and an empty value is rejected.
    """
    if not algorithm or not algorithm.strip():
        raise JwtSigningError("jwt_signing_algorithm must not be empty")
    algorithm = algorithm.strip()
    if algorithm in DENIED_ALGORITHMS:
        raise JwtSigningError(
            f"JWT signing algorithm '{algorithm}' is not allowed: 'none' and symmetric (HS*) algorithms are denied"
        )
    return algorithm


def _check_asymmetric(jwk: JWK) -> None:
    if jwk.get("kty") not in ASYMMETRIC_KEY_TYPES:
        raise JwtSigningError(
            f"JWT signing key must be an asymmetric key type (one of {sorted(ASYMMETRIC_KEY_TYPES)}), "
            f"got '{jwk.get('kty')}'"
        )


def _check_key_compatibility(jwk: JWK, algorithm: str) -> None:
    """Verify the key type and curve match the algorithm.

    For algorithms outside ALGORITHM_KEY_PARAMS this performs no static
    check: such algorithms require an operator-provided key and are
    validated by the probe-sign self-test at signer instantiation.
    """
    _check_asymmetric(jwk)

    params = ALGORITHM_KEY_PARAMS.get(algorithm)
    if params is None:
        return
    key_type, curve = params

    if jwk.get("kty") != key_type:
        raise JwtKeyIncompatibleError(
            f"JWT signing algorithm '{algorithm}' requires a {key_type} key, "
            f"but the configured key is {jwk.get('kty')}",
            kid=jwk.get("kid"),
        )

    if jwk.get("kty") == "EC":
        if jwk.get("crv") != curve:
            raise JwtKeyIncompatibleError(
                f"JWT signing algorithm '{algorithm}' requires an EC key on curve {curve}, " f"got {jwk.get('crv')}",
                kid=jwk.get("kid"),
            )
    elif jwk.get("kty") == "OKP":
        if algorithm == "EdDSA":
            if jwk.get("crv") not in EDDSA_CURVES:
                raise JwtKeyIncompatibleError(
                    f"JWT signing algorithm 'EdDSA' requires an OKP key on curve "
                    f"{' or '.join(sorted(EDDSA_CURVES))}, got {jwk.get('crv')}",
                    kid=jwk.get("kid"),
                )
        elif jwk.get("crv") != curve:
            raise JwtKeyIncompatibleError(
                f"JWT signing algorithm '{algorithm}' requires an OKP key on curve {curve}, got {jwk.get('crv')}",
                kid=jwk.get("kid"),
            )
    elif jwk.get("kty") == "RSA":
        modulus_size = _rsa_modulus_size(jwk)
        if modulus_size < MINIMUM_RSA_MODULUS_SIZE:
            raise JwtKeyIncompatibleError(
                f"JWT signing key RSA modulus size {modulus_size} bits is below the required "
                f"{MINIMUM_RSA_MODULUS_SIZE} bits",
                kid=jwk.get("kid"),
            )
        if modulus_size <= MINIMUM_RSA_MODULUS_SIZE:
            logger.warning(
                "JWT signing key uses a %d-bit RSA key; NIST SP 800-131A disallows RSA-2048 for signing after 2030, "
                "consider a larger key",
                modulus_size,
            )


def _rsa_modulus_size(jwk: JWK) -> int:
    n = jwk.export_public(as_dict=True).get("n", "")
    modulus = base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))
    return int.from_bytes(modulus, "big").bit_length()


def _probe_sign(jwk: JWK, algorithm: str) -> None:
    """Sign and verify a dummy payload with the production key.

    This is the authoritative compatibility gate: it proves jwcrypto can
    actually sign with this key under this algorithm (e.g. it rejects an
    X25519 key offered for EdDSA), including for algorithms outside the
    static map. Costs one signature at startup.
    """
    try:
        jws = JWS(json.dumps({"probe": True}))
        jws.add_signature(jwk, alg=algorithm, protected=json.dumps({"alg": algorithm}))
        token = jws.serialize(compact=True)
        verifier = JWS()
        verifier.deserialize(token)
        verifier.verify(jwk.public())
    except (JWException, ValueError, TypeError, NotImplementedError, AttributeError) as e:
        raise JwtKeyIncompatibleError(
            f"JWT signing self-test failed: algorithm '{algorithm}' cannot sign with the configured key: {e}",
            kid=jwk.get("kid"),
        ) from e


def _prepare_key_dir(key_dir: str) -> None:
    """Ensure the signing-key directory exists with mode 0700.

    A freshly created directory is chmod-ed explicitly so the mode does
    not depend on the process umask; a pre-existing directory is left
    alone but flagged when it is looser than 0700.
    """
    if os.path.isdir(key_dir):
        try:
            mode = stat.S_IMODE(os.stat(key_dir).st_mode)
        except OSError as e:
            raise JwtKeyError(f"cannot inspect JWT signing key directory {key_dir}: {e}") from e
        if mode & 0o077:
            logger.warning("JWT signing key directory %s is group/world accessible (mode %o)", key_dir, mode)
    else:
        try:
            os.makedirs(key_dir, mode=0o700, exist_ok=True)
        except OSError as e:
            raise JwtKeyError(f"cannot create JWT signing key directory {key_dir}: {e}") from e
        try:
            os.chmod(key_dir, 0o700)
        except OSError as e:
            raise JwtKeyError(f"cannot set permissions on JWT signing key directory {key_dir}: {e}") from e


def _remove_temp_key_file(path: str) -> None:
    """Best-effort removal of a temporary key file after a failed persist.

    Never raises: a cleanup failure must not mask the persistence error
    that triggered it.
    """
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("could not remove temporary JWT signing key file %s: %s", path, e)


def _persist_key(jwk: JWK, path: str) -> None:
    """Persist a key to ``path`` atomically, with restrictive permissions.

    The file mode is enforced by mechanism (mkstemp plus chmod plus
    atomic replace), never by the process umask. The directory is created
    0700 if absent; a pre-existing looser directory triggers a warning.
    The rename is followed by a directory fsync so a crash cannot lose
    it (a lost rename surfaces as file absence, which regenerates a new
    key — recoverable, but a silent kid rotation).
    """
    key_dir = os.path.dirname(path)
    if not key_dir:
        raise JwtKeyError(
            f"JWT signing key persistence path {path!r} must include a directory component; "
            f"a bare filename would break the same-filesystem atomic rename"
        )
    _prepare_key_dir(key_dir)

    try:
        fd, tmp_path = tempfile.mkstemp(dir=key_dir, prefix=".jwt_signing_key.")
    except OSError as e:
        raise JwtKeyError(f"cannot create a temporary file in the JWT signing key directory {key_dir}: {e}") from e
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(jwk.export_to_pem(private_key=True, password=None))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except OSError as e:
        _remove_temp_key_file(tmp_path)
        raise JwtKeyError(f"cannot persist the JWT signing key to {path}: {e}") from e
    except BaseException:
        _remove_temp_key_file(tmp_path)
        raise

    # fsync the directory so the rename itself survives a crash. Some
    # filesystems (older NFS, some FUSE mounts) do not support directory
    # fsync and return an error even though the rename succeeded, so this
    # is a durability warning rather than a startup failure: the key is
    # already in place and usable.
    try:
        dir_fd = os.open(key_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as e:
        logger.warning("could not fsync JWT signing key directory %s: %s", key_dir, e)


def _set_kid(jwk: JWK) -> JWK:
    """Set the RFC 7638 SHA-256 JWK thumbprint as the key's kid.

    The thumbprint is a pure function of the public key, so it is stable
    across re-provisioning of the same key material. The JWKS endpoint
    (SECENGSP-12709) derives its kids with the same library call.
    """
    jwk["kid"] = jwk.thumbprint()
    return jwk


def load_signing_key(
    path: str, password: Optional[str] = None, algorithm: str = "ES256", *, follow_symlinks: bool = True
) -> JWK:
    """Load a PEM-encoded private signing key.

    Raises JwtKeyError if the file cannot be read or parsed (including a
    wrong or missing password, a public key or certificate offered as a
    key, or a key type the installed jwcrypto does not support), never
    regenerates anything. Group/world-accessible key files are rejected
    even when the OS would allow reading them (the verifier typically
    runs as root, so file permissions are the only guard on key
    secrecy), and the path must resolve to a regular file (a FIFO or
    device node is rejected before anything is read).

    On an operator-chosen path (the default), symlinks are followed —
    standard key-delivery layouts such as Kubernetes Secret volumes and
    certbot's live/ directories publish files as symlinks, and refusing
    them would close nothing: anyone able to plant a symlink in the
    key's directory can replace the file itself. The resolved target is
    still protected: the regular-file and permission checks run on the
    opened file descriptor, so the object checked is always the object
    read, and the resolved path is logged. Callers owning the path
    (the auto-generated key) pass ``follow_symlinks=False`` so a
    symlink there — where the verifier controls the directory — is
    refused.
    """
    algorithm = _validate_algorithm(algorithm)

    # Open first, without blocking: the fstat below then rejects FIFOs,
    # devices and directories before any data is read, and every check
    # operates on the open file descriptor rather than the path (no
    # stat/open swap window). O_NOFOLLOW is applied only when the caller
    # owns the path; see the docstring.
    open_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if not follow_symlinks:
        open_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, open_flags)
    except FileNotFoundError as e:
        raise JwtKeyFileAbsentError(f"JWT signing key file {path} does not exist") from e
    except OSError as e:
        hint = "" if follow_symlinks else " (symlinks are refused on this path)"
        raise JwtKeyError(f"cannot open JWT signing key file {path}{hint}: {e}") from e
    try:
        key_stat = os.fstat(fd)
        if not stat.S_ISREG(key_stat.st_mode):
            raise JwtKeyError(
                f"JWT signing key file {path} is not a regular file; refusing to read it "
                f"(a FIFO, socket or device would block or read indefinitely)"
            )
        mode = stat.S_IMODE(key_stat.st_mode)
        if mode & 0o077:
            raise JwtKeyError(
                f"JWT signing key file {path} must not be group/world accessible (mode {mode:o}); "
                f"run: chmod 600 {path}"
            )
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        pem = b"".join(chunks)
    except OSError as e:
        raise JwtKeyError(f"cannot read JWT signing key file {path}: {e}") from e
    finally:
        os.close(fd)

    try:
        jwk = JWK.from_pem(pem, password=password.encode() if password else None)
    except (ValueError, JWException, TypeError) as e:
        raise JwtKeyError(
            f"cannot load JWT signing key from {path} (wrong password, not a valid PEM private key, "
            f"or a key type the installed jwcrypto does not support?): {e}"
        ) from e

    if not jwk.has_private:
        raise JwtKeyError(
            f"JWT signing key file {path} contains no private key material (a public key or certificate?)"
        )

    _set_kid(jwk)
    _check_key_compatibility(jwk, algorithm)
    real_path = os.path.realpath(path)
    resolved = f" (symlink to {real_path})" if real_path != path else ""
    logger.info("loaded JWT signing key %s%s, kid=%s", path, resolved, jwk.get("kid"))
    return jwk


def generate_signing_key(algorithm: str = "ES256", persist_path: Optional[str] = None) -> JWK:
    """Generate a signing key appropriate for ``algorithm``.

    Only algorithms in ALGORITHM_KEY_PARAMS can be auto-generated; for
    any other algorithm the operator must provide a key via
    jwt_signing_key. If ``persist_path`` is given, the key is persisted
    atomically with restrictive permissions.
    """
    algorithm = _validate_algorithm(algorithm)

    params = ALGORITHM_KEY_PARAMS.get(algorithm)
    if params is None:
        raise JwtSigningError(
            f"cannot auto-generate a JWT signing key for algorithm '{algorithm}': "
            f"set jwt_signing_key to an operator-provided key, or extend the algorithm key-type map"
        )
    key_type, curve = params

    if key_type == "EC":
        jwk = JWK.generate(kty="EC", crv=curve)
    elif key_type == "OKP":
        jwk = JWK.generate(kty="OKP", crv=curve)
    elif key_type == "RSA":
        jwk = JWK.generate(kty="RSA", size=RSA_GENERATION_SIZE)
    else:
        # No silent fallback: a new key family needs explicit generation
        # support here (e.g. AKP keys take alg= instead of crv=), otherwise
        # a map entry would quietly persist a wrong key type.
        raise JwtSigningError(
            f"no key generation support for key type '{key_type}' (algorithm '{algorithm}'); "
            f"extend generate_signing_key alongside the algorithm key-type map"
        )

    _set_kid(jwk)
    if persist_path:
        _persist_key(jwk, persist_path)
        logger.info("generated new JWT signing key %s, kid=%s", persist_path, jwk.get("kid"))
    return jwk


@contextmanager
def _autogen_key_lock(autogen_path: str) -> Iterator[None]:
    """Serialize signing-key resolution across processes sharing the path.

    An exclusive flock is held for the whole load-or-generate decision, so
    concurrent verifier processes using the same working directory
    (multiple instances on one host, or a restart overlapping a dying
    process) converge on a single key instead of each generating their
    own and silently rotating the kid on the next restart. The lock lives
    next to the key file, holds no secrets, and is released by the kernel
    when the holder dies — there are no stale locks to clean up. The lock
    file is opened without following symlinks, its permissions do not
    depend on the umask, and a contended lock is logged before the
    blocking wait.
    """
    key_dir = os.path.dirname(autogen_path) or "."
    _prepare_key_dir(key_dir)
    lock_path = os.path.join(key_dir, f".{os.path.basename(autogen_path)}.lock")
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        raise JwtKeyError(f"cannot open the JWT signing key lock file {lock_path}: {e}") from e
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            logger.info("waiting for another process to release the JWT signing key lock %s", lock_path)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError as e:
                raise JwtKeyError(f"cannot lock the JWT signing key lock file {lock_path}: {e}") from e
        except OSError as e:
            raise JwtKeyError(f"cannot lock the JWT signing key lock file {lock_path}: {e}") from e
        try:
            os.fchmod(lock_fd, 0o600)
        except OSError as e:
            raise JwtKeyError(f"cannot set permissions on the JWT signing key lock file {lock_path}: {e}") from e
        yield
    finally:
        os.close(lock_fd)


def resolve_signing_key(
    configured_path: Optional[str],
    password: Optional[str],
    algorithm: str = "ES256",
    autogen_path: Optional[str] = None,
) -> JWK:
    """Resolve the signing key from configuration.

    With jwt_signing_key set, the operator's key is loaded (any failure
    is fatal). Otherwise, the auto-generated key is loaded from
    ``autogen_path`` when present, or generated and persisted when
    absent; the whole decision runs under a cross-process lock so
    concurrent verifiers sharing the path converge on one key. A
    present-but-unreadable or unparseable auto-generated key file is a
    hard error: silently regenerating would rotate the kid without
    operator intent and mask a possible tampering. The one regenerable
    case is a valid key that no longer matches a later-changed
    jwt_signing_algorithm, which is replaced with a warning.
    """
    algorithm = _validate_algorithm(algorithm)

    if configured_path:
        return load_signing_key(configured_path, password, algorithm)

    if password:
        logger.warning(
            "jwt_signing_key_password is set but jwt_signing_key is empty; "
            "the password only applies to an operator-provided key file and is ignored for auto-generated keys"
        )

    if autogen_path is None:
        raise JwtSigningError("no JWT signing key configured and no auto-generation path given")

    with _autogen_key_lock(autogen_path):
        try:
            jwk = load_signing_key(autogen_path, None, algorithm, follow_symlinks=False)
            # For algorithms outside the map, load_signing_key performed no
            # static compatibility check; probe now so an incompatible key
            # triggers the regeneration path below (with the right message)
            # instead of a later hard error at signer construction.
            if algorithm not in ALGORITHM_KEY_PARAMS:
                _probe_sign(jwk, algorithm)
            return jwk
        except JwtKeyFileAbsentError:
            pass
        except JwtKeyIncompatibleError as e:
            logger.warning(
                "persisted JWT signing key %s is not compatible with the configured algorithm '%s' "
                "(old kid=%s, reason: %s); generating a new key",
                autogen_path,
                algorithm,
                e.kid,
                e,
            )
        except JwtKeyError as e:
            raise JwtKeyError(
                f"the persisted JWT signing key {autogen_path} exists but cannot be loaded "
                f"(it may be corrupt, or its permissions are wrong). Remove the file to regenerate a key, "
                f"or restore a valid key. Error: {e}"
            ) from e

        jwk = generate_signing_key(algorithm, persist_path=autogen_path)
        logger.info("generated new JWT signing key %s, kid=%s", autogen_path, jwk.get("kid"))
        return jwk


class JwtSigner:
    """Signs claim sets as compact JWTs.

    The signer owns the standard claims and the full protected header:
    caller-supplied ``iss``/``iat``/``nbf``/``exp``/``jti`` values are
    overwritten, and no caller-supplied header material is honored.
    ``sign()`` refuses to produce tokens until an issuer is set (issuer
    resolution is SECENGSP-12719's job).
    """

    def __init__(
        self,
        signing_key: JWK,
        algorithm: str = "ES256",
        issuer: Optional[str] = None,
        expiration_seconds: int = DEFAULT_EXPIRATION_SECONDS,
    ) -> None:
        algorithm = _validate_algorithm(algorithm)

        if isinstance(expiration_seconds, bool) or not isinstance(expiration_seconds, int) or expiration_seconds <= 0:
            raise JwtSigningError(f"JWT expiration must be a positive number of seconds, got {expiration_seconds!r}")
        if expiration_seconds > MAXIMUM_EXPIRATION_SECONDS:
            raise JwtSigningError(
                f"JWT expiration {expiration_seconds}s exceeds the maximum of {MAXIMUM_EXPIRATION_SECONDS}s"
            )

        _check_asymmetric(signing_key)
        _check_key_compatibility(signing_key, algorithm)
        _probe_sign(signing_key, algorithm)

        # Unconditional: the kid is always the RFC 7638 thumbprint, even
        # for directly-constructed signers, so token and JWKS kids can
        # never diverge.
        _set_kid(signing_key)

        self._key = signing_key
        self._algorithm = algorithm
        self._issuer = issuer
        self._expiration_seconds = expiration_seconds

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def issuer(self) -> Optional[str]:
        return self._issuer

    @issuer.setter
    def issuer(self, value: str) -> None:
        self._issuer = value

    @property
    def kid(self) -> Optional[str]:
        kid = self._key.get("kid")
        return str(kid) if kid is not None else None

    def sign(self, claims: Dict[str, Any]) -> str:
        """Produce a compact JWT carrying ``claims`` plus the standard claims."""
        if not self._issuer:
            raise JwtSigningError(
                "JWT signer has no issuer configured; set jwt_issuer in the [verifier] section before signing"
            )

        now = int(time.time())
        payload = dict(claims)
        payload.update(
            {
                "iss": self._issuer,
                "iat": now,
                "nbf": now,
                "exp": now + self._expiration_seconds,
                "jti": str(uuid.uuid4()),
            }
        )

        protected: Dict[str, str] = {"alg": self._algorithm, "typ": TOKEN_TYPE}
        kid = self._key.get("kid")
        if kid:
            protected["kid"] = str(kid)

        try:
            jws = JWS(json.dumps(payload))
            jws.add_signature(self._key, alg=self._algorithm, protected=json.dumps(protected))
            return str(jws.serialize(compact=True))
        except (JWException, ValueError, TypeError) as e:
            raise JwtSigningError(f"failed to sign JWT: {e}") from e
