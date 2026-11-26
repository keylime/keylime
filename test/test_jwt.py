import base64
import datetime
import json
import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jwcrypto.common import JWException
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from keylime.jwt import (
    DEFAULT_EXPIRATION_SECONDS,
    JwtKeyError,
    JwtKeyIncompatibleError,
    JwtSigner,
    JwtSigningError,
    generate_signing_key,
    load_signing_key,
    resolve_signing_key,
)


def decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def verify_token(token: str, jwk: JWK) -> dict:
    verifier = JWS()
    verifier.deserialize(token)
    verifier.verify(jwk.public())
    return json.loads(verifier.payload.decode())


def mldsa_available() -> bool:
    """Feature probe: can this jwcrypto/cryptography build produce ML-DSA keys?"""
    try:
        JWK.generate(kty="AKP", alg="ML-DSA-65")  # type: ignore[call-overload]  # AKP missing from jwcrypto's type stubs
        return True
    except (JWException, ValueError, TypeError, ImportError, NotImplementedError):
        return False


class JwtSignerTest(unittest.TestCase):
    ISSUER = "https://verifier.example.com"

    signing_key: JWK

    def _signer(self, algorithm: str = "ES256", **kwargs) -> JwtSigner:
        self.signing_key = generate_signing_key(algorithm)
        return JwtSigner(self.signing_key, algorithm, issuer=self.ISSUER, **kwargs)

    # --- signing basics (AC1) ---

    def test_sign_es256_produces_valid_jwt(self):
        signer = self._signer("ES256")
        token = signer.sign({"sub": "default"})
        header = decode_segment(token.split(".", maxsplit=1)[0])
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(header["typ"], "JWT")
        claims = verify_token(token, self.signing_key)
        self.assertEqual(claims["sub"], "default")
        self.assertEqual(claims["iss"], self.ISSUER)

    def test_sign_supported_algorithm_variants(self):
        for algorithm in ("ES384", "ES512", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
            with self.subTest(algorithm=algorithm):
                signer = self._signer(algorithm)
                token = signer.sign({"alg_test": algorithm})
                claims = verify_token(token, self.signing_key)
                self.assertEqual(claims["alg_test"], algorithm)

    # --- standard claims (AC5, AC6) ---

    def test_jti_unique_across_tokens(self):
        signer = self._signer()
        first = decode_segment(signer.sign({}).split(".")[1])
        second = decode_segment(signer.sign({}).split(".")[1])
        self.assertNotEqual(first["jti"], second["jti"])

    def test_exp_equals_iat_plus_expiration(self):
        signer = self._signer(expiration_seconds=300)
        claims = decode_segment(signer.sign({}).split(".")[1])
        self.assertEqual(claims["exp"], claims["iat"] + 300)
        self.assertEqual(claims["nbf"], claims["iat"])
        self.assertIsInstance(claims["iat"], int)
        self.assertIsInstance(claims["exp"], int)
        # iat must be anchored to wall-clock time, not a fixed value
        self.assertLess(abs(claims["iat"] - time.time()), 60)

    def test_custom_expiration_honored(self):
        signer = self._signer(expiration_seconds=60)
        claims = decode_segment(signer.sign({}).split(".")[1])
        self.assertEqual(claims["exp"], claims["iat"] + 60)

    def test_default_expiration_is_300(self):
        signer = self._signer()
        claims = decode_segment(signer.sign({}).split(".")[1])
        self.assertEqual(claims["exp"], claims["iat"] + DEFAULT_EXPIRATION_SECONDS)

    def test_invalid_expiration_rejected(self):
        jwk = generate_signing_key()
        for expiration in (0, -1, 86401, True):
            with self.subTest(expiration=expiration):
                with self.assertRaises(JwtSigningError):
                    JwtSigner(jwk, "ES256", issuer=self.ISSUER, expiration_seconds=expiration)

    def test_expiration_boundary_values_accepted(self):
        # 1 second and MAXIMUM_EXPIRATION_SECONDS are the smallest and
        # largest legal lifetimes; the bounds are inclusive
        for expiration in (1, 86400):
            with self.subTest(expiration=expiration):
                signer = self._signer(expiration_seconds=expiration)
                claims = decode_segment(signer.sign({}).split(".")[1])
                self.assertEqual(claims["exp"], claims["iat"] + expiration)

    # --- kid (AC4, signer half) ---

    def test_kid_is_rfc7638_thumbprint(self):
        jwk = generate_signing_key("ES256")
        signer = JwtSigner(jwk, "ES256", issuer=self.ISSUER)
        header = decode_segment(signer.sign({}).split(".", maxsplit=1)[0])
        self.assertEqual(header["kid"], jwk.thumbprint())
        self.assertEqual(signer.kid, jwk.thumbprint())

    def test_preset_kid_is_overwritten_by_thumbprint(self):
        # The kid is always the RFC 7638 derivation, even for a directly
        # constructed signer, so token and JWKS kids can never diverge
        jwk = generate_signing_key("ES256")
        jwk["kid"] = "attacker-chosen-kid"
        signer = JwtSigner(jwk, "ES256", issuer=self.ISSUER)
        header = decode_segment(signer.sign({}).split(".", maxsplit=1)[0])
        self.assertEqual(header["kid"], jwk.thumbprint())

    # --- claims injection: the signer owns the standard claims ---

    def test_caller_cannot_forge_standard_claims(self):
        signer = self._signer()
        forged = {
            "iss": "https://evil.example.com",
            "exp": 4102444800,
            "jti": "fixed-value",
            "iat": 1,
            "nbf": 1,
        }
        claims = decode_segment(signer.sign(forged).split(".")[1])
        self.assertEqual(claims["iss"], self.ISSUER)
        self.assertEqual(claims["exp"], claims["iat"] + DEFAULT_EXPIRATION_SECONDS)
        self.assertNotEqual(claims["jti"], "fixed-value")
        self.assertNotEqual(claims["iat"], 1)
        self.assertEqual(claims["nbf"], claims["iat"])

    def test_caller_cannot_inject_header(self):
        signer = self._signer()
        # alg/kid/typ in the claims dict must never reach the header
        header = decode_segment(signer.sign({"alg": "HS256", "kid": "forged", "typ": "JWS"}).split(".", maxsplit=1)[0])
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(header["typ"], "JWT")
        self.assertEqual(header["kid"], signer.kid)

    # --- issuer: fail closed until set (12719 owns resolution) ---

    def test_sign_without_issuer_raises(self):
        jwk = generate_signing_key()
        signer = JwtSigner(jwk, "ES256")
        with self.assertRaises(JwtSigningError):
            signer.sign({})

    def test_issuer_settable_after_construction(self):
        signer = self._signer()
        signer.issuer = "https://other.example.com"
        claims = decode_segment(signer.sign({}).split(".")[1])
        self.assertEqual(claims["iss"], "https://other.example.com")

    # --- denylist (AC2) ---

    def test_denied_algorithm_rejected_on_operator_key_load(self):
        jwk = generate_signing_key("ES256")
        pem = jwk.export_to_pem(private_key=True, password=None)
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "denied-key.pem")
            with open(path, "wb") as f:
                f.write(pem)
            os.chmod(path, 0o600)
            for algorithm in ("HS256", "none", "HS384", "HS512"):
                with self.subTest(algorithm=algorithm):
                    with self.assertRaises(JwtSigningError):
                        load_signing_key(path, None, algorithm)

    def test_denied_algorithm_rejected_on_signer_construction(self):
        jwk = generate_signing_key("ES256")
        for algorithm in ("HS256", "none"):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(JwtSigningError):
                    JwtSigner(jwk, algorithm, issuer=self.ISSUER)

    def test_denied_algorithm_rejected_on_auto_generation(self):
        for algorithm in ("HS256", "none"):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(JwtSigningError):
                    generate_signing_key(algorithm)

    def test_empty_or_whitespace_algorithm_rejected(self):
        jwk = generate_signing_key("ES256")
        for algorithm in ("", "   "):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(JwtSigningError):
                    JwtSigner(jwk, algorithm, issuer=self.ISSUER)

    def test_symmetric_key_structurally_rejected(self):
        # Even if the algorithm string were bypassed, an oct key can never sign
        oct_key = JWK.generate(kty="oct", size=256)
        with self.assertRaises(JwtSigningError):
            JwtSigner(oct_key, "ES256", issuer=self.ISSUER)

    # --- key/algorithm compatibility (curve-level) ---

    def test_es256_with_p384_key_rejected(self):
        jwk = JWK.generate(kty="EC", crv="P-384")
        with self.assertRaises(JwtKeyIncompatibleError):
            JwtSigner(jwk, "ES256", issuer=self.ISSUER)

    def test_es256_with_rsa_key_rejected(self):
        # Key-type mismatch must be caught at construction, not first left
        # to the probe-sign: the error names the required key type
        jwk = JWK.generate(kty="RSA", size=3072)
        with self.assertRaises(JwtKeyIncompatibleError) as ctx:
            JwtSigner(jwk, "ES256", issuer=self.ISSUER)
        self.assertIn("requires a EC key", str(ctx.exception))

    def test_es512_with_p256_key_rejected(self):
        jwk = JWK.generate(kty="EC", crv="P-256")
        with self.assertRaises(JwtKeyIncompatibleError):
            JwtSigner(jwk, "ES512", issuer=self.ISSUER)

    def test_eddsa_with_x25519_key_rejected(self):
        # X25519 is OKP but a key-agreement curve; only the probe-sign
        # (or the explicit curve check) catches it
        jwk = JWK.generate(kty="OKP", crv="X25519")
        with self.assertRaises(JwtKeyIncompatibleError):
            JwtSigner(jwk, "EdDSA", issuer=self.ISSUER)

    def test_eddsa_with_ed448_key_signs(self):
        # RFC 8037 section 3.1 defines the EdDSA variant by the OKP key
        # subtype and registers Ed448 alongside Ed25519; the token carries
        # the interoperable alg name "EdDSA" either way
        jwk = JWK.generate(kty="OKP", crv="Ed448")
        signer = JwtSigner(jwk, "EdDSA", issuer=self.ISSUER)
        token = signer.sign({"curve": "Ed448"})
        header = decode_segment(token.split(".", maxsplit=1)[0])
        self.assertEqual(header["alg"], "EdDSA")
        claims = verify_token(token, jwk)
        self.assertEqual(claims["curve"], "Ed448")

    def test_eddsa_with_x448_key_rejected(self):
        jwk = JWK.generate(kty="OKP", crv="X448")
        with self.assertRaises(JwtKeyIncompatibleError):
            JwtSigner(jwk, "EdDSA", issuer=self.ISSUER)

    def test_eddsa_generation_default_is_ed25519(self):
        jwk = generate_signing_key("EdDSA")
        self.assertEqual(jwk.get("crv"), "Ed25519")

    def test_rsa_below_minimum_modulus_rejected(self):
        jwk = JWK.generate(kty="RSA", size=1024)
        with self.assertRaises(JwtKeyIncompatibleError):
            JwtSigner(jwk, "RS256", issuer=self.ISSUER)

    def test_rsa_2048_accepted_with_warning(self):
        jwk = JWK.generate(kty="RSA", size=2048)
        with self.assertLogs("keylime.jwt", level="WARNING"):
            signer = JwtSigner(jwk, "RS256", issuer=self.ISSUER)
        signer.sign({"ok": True})

    def test_unknown_algorithm_with_operator_key_gated_by_probe_sign(self):
        # ES256K is registered in jwcrypto but not in our map: it needs an
        # operator key, and the probe-sign is the gate.
        # Wrong pairing for an unmapped algorithm: X25519 passes no static
        # check but must fail the probe-sign
        x25519 = JWK.generate(kty="OKP", crv="X25519")
        with self.assertRaises(JwtKeyIncompatibleError):
            JwtSigner(x25519, "ES256K", issuer=self.ISSUER)

    def test_unmapped_algorithm_cannot_auto_generate(self):
        with self.assertRaises(JwtSigningError):
            generate_signing_key("ES256K")

    def test_unknown_algorithm_name_with_operator_key_fails_probe_sign(self):
        # A made-up algorithm name (not registered in JOSE at all, unlike
        # ES256K) can never sign; the probe-sign self-test is the gate and
        # must reject it with the self-test message
        jwk = JWK.generate(kty="EC", crv="P-256")
        with self.assertRaises(JwtKeyIncompatibleError) as ctx:
            JwtSigner(jwk, "XX256", issuer=self.ISSUER)
        self.assertIn("self-test failed", str(ctx.exception))

    def test_unknown_algorithm_name_cannot_auto_generate(self):
        with self.assertRaises(JwtSigningError):
            generate_signing_key("XX256")

    def test_unmapped_algorithm_with_operator_key_signs(self):
        # Positive control for the crypto-agility claim (R2): an algorithm
        # outside the key-type map works with an operator-provided key,
        # gated only by the probe-sign self-test
        jwk = JWK.generate(kty="EC", crv="P-256K")
        signer = JwtSigner(jwk, "ES256K", issuer=self.ISSUER)
        claims = verify_token(signer.sign({"agility": True}), jwk)
        self.assertTrue(claims["agility"])

    @unittest.skipUnless(mldsa_available(), "ML-DSA key support not available in this jwcrypto/cryptography build")
    def test_ml_dsa_operator_key_signs(self):
        # PQC path: ML-DSA keys are kty "AKP"; works wherever the installed
        # jwcrypto supports them, no version check needed
        jwk = JWK.generate(kty="AKP", alg="ML-DSA-65")  # type: ignore[call-overload]  # AKP missing from jwcrypto's type stubs
        signer = JwtSigner(jwk, "ML-DSA-65", issuer=self.ISSUER)
        claims = verify_token(signer.sign({"pqc": True}), jwk)
        self.assertTrue(claims["pqc"])
        self.assertEqual(signer.kid, jwk.thumbprint())


class JwtKeyLifecycleTest(unittest.TestCase):
    """Key loading, auto-generation, persistence (AC3, AC7, AC8, AC9)."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self.key_path = os.path.join(self.tmp_dir, "jwt_signing_key.pem")

    def _write(self, data: bytes) -> None:
        """Write a key file with the permissions load_signing_key requires."""
        with open(self.key_path, "wb") as f:
            f.write(data)
        os.chmod(self.key_path, 0o600)

    def _self_signed_cert_pem(self) -> bytes:
        """Build a minimal self-signed certificate PEM (the classic
        jwt_signing_key-points-at-the-wrong-file mistake)."""
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jwt-test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    def test_encrypted_pem_correct_password(self):
        jwk = generate_signing_key("ES256")
        encrypted = jwk.export_to_pem(private_key=True, password=b"secret")
        self._write(encrypted)
        loaded = load_signing_key(self.key_path, "secret", "ES256")
        self.assertEqual(loaded.thumbprint(), jwk.thumbprint())

    def test_encrypted_pem_wrong_password(self):
        jwk = generate_signing_key("ES256")
        encrypted = jwk.export_to_pem(private_key=True, password=b"secret")
        self._write(encrypted)
        with self.assertRaises(JwtKeyError):
            load_signing_key(self.key_path, "wrong", "ES256")

    def test_encrypted_pem_missing_password(self):
        jwk = generate_signing_key("ES256")
        encrypted = jwk.export_to_pem(private_key=True, password=b"secret")
        self._write(encrypted)
        with self.assertRaises(JwtKeyError):
            load_signing_key(self.key_path, None, "ES256")

    def test_public_key_pem_rejected_with_clear_error(self):
        jwk = generate_signing_key("ES256")
        self._write(jwk.export_to_pem(private_key=False, password=None))
        with self.assertRaises(JwtKeyError) as ctx:
            load_signing_key(self.key_path, None, "ES256")
        self.assertIn("no private key material", str(ctx.exception))

    def test_certificate_pem_rejected_with_clear_error(self):
        self._write(self._self_signed_cert_pem())
        with self.assertRaises(JwtKeyError) as ctx:
            load_signing_key(self.key_path, None, "ES256")
        self.assertIn("no private key material", str(ctx.exception))

    def test_public_pem_at_autogen_path_gets_remediation_message(self):
        jwk = generate_signing_key("ES256")
        self._write(jwk.export_to_pem(private_key=False, password=None))
        with self.assertRaises(JwtKeyError) as ctx:
            resolve_signing_key(None, None, "ES256", self.key_path)
        self.assertIn("Remove the file to regenerate", str(ctx.exception))

    def test_world_readable_key_file_is_hard_error(self):
        # Works when running as root: asserted via stat, not OS denial
        generate_signing_key("ES256", persist_path=self.key_path)
        os.chmod(self.key_path, 0o644)
        with self.assertRaises(JwtKeyError) as ctx:
            resolve_signing_key(None, None, "ES256", self.key_path)
        self.assertIn("group/world accessible", str(ctx.exception))
        # hard error, not a silent regeneration: the file is untouched
        self.assertTrue(os.path.exists(self.key_path))
        self.assertEqual(stat.S_IMODE(os.stat(self.key_path).st_mode), 0o644)

    def test_non_regular_file_is_hard_error(self):
        # A FIFO passes the permission check (0600) but must be rejected
        # before anything is read; the nonblocking open guarantees the
        # check cannot hang on a writer that never appears. The load runs
        # in a thread with a join timeout so a regression (blocking open)
        # fails the test instead of hanging the suite.
        fifo = os.path.join(self.tmp_dir, "key.fifo")
        try:
            os.mkfifo(fifo, 0o600)
        except (AttributeError, OSError):
            self.skipTest("os.mkfifo is not available")
        outcome = {}

        def load():
            try:
                load_signing_key(fifo, None, "ES256")
            except Exception as e:  # pylint: disable=broad-exception-caught
                outcome["error"] = e

        loader = threading.Thread(target=load)
        loader.start()
        loader.join(timeout=10)
        self.assertFalse(loader.is_alive(), "load_signing_key hung on a FIFO instead of rejecting it")
        self.assertIsInstance(outcome.get("error"), JwtKeyError)
        self.assertIn("not a regular file", str(outcome.get("error")))

    def test_symlinked_operator_key_loads(self):
        # Standard key-delivery layouts publish files as symlinks
        # (Kubernetes Secret volumes, certbot live/): the operator path
        # follows them. The fd-bound checks still apply to the target,
        # and the resolved path is logged.
        real = os.path.join(self.tmp_dir, "..data")
        os.mkdir(real, 0o700)
        target = os.path.join(real, "key.pem")
        jwk = generate_signing_key("ES256", persist_path=target)
        link = os.path.join(self.tmp_dir, "key.pem")
        os.symlink(os.path.join("..data", "key.pem"), link)
        with self.assertLogs("keylime.jwt", level="INFO") as logs:
            loaded = load_signing_key(link, None, "ES256")
        self.assertEqual(loaded.thumbprint(), jwk.thumbprint())
        self.assertTrue(any(str(target) in line for line in logs.output), logs.output)

    def test_symlinked_operator_key_target_checks_still_apply(self):
        # Following the symlink must not weaken the target checks: a
        # world-readable target is rejected exactly as a direct one is
        real = os.path.join(self.tmp_dir, "real.pem")
        generate_signing_key("ES256", persist_path=real)
        os.chmod(real, 0o644)
        link = os.path.join(self.tmp_dir, "link.pem")
        os.symlink("real.pem", link)
        with self.assertRaises(JwtKeyError) as ctx:
            load_signing_key(link, None, "ES256")
        self.assertIn("group/world accessible", str(ctx.exception))

    def test_symlinked_autogen_key_is_hard_error(self):
        # A symlink planted at the auto-generation path is a hard error,
        # not a followed load and not a silent regeneration (which would
        # rotate the kid without operator intent): the verifier owns
        # that directory, so a symlink there is refused outright
        real = os.path.join(self.tmp_dir, "real.pem")
        generate_signing_key("ES256", persist_path=real)
        autogen = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        os.makedirs(os.path.dirname(autogen), mode=0o700)
        os.symlink(real, autogen)
        with self.assertRaises(JwtKeyError) as ctx:
            resolve_signing_key(None, None, "ES256", autogen)
        self.assertIn("symlinks are refused", str(ctx.exception))
        self.assertTrue(os.path.islink(autogen))

    def test_directory_as_key_path_is_hard_error(self):
        with self.assertRaises(JwtKeyError) as ctx:
            load_signing_key(self.tmp_dir, None, "ES256")
        self.assertIn("not a regular file", str(ctx.exception))

    def test_nonexistent_key_file_is_hard_error(self):
        with self.assertRaises(JwtKeyError):
            load_signing_key(os.path.join(self.tmp_dir, "absent.pem"), None, "ES256")

    # --- auto-generation (AC7, AC8) ---

    def test_autogenerate_es256_and_sign(self):
        jwk = generate_signing_key("ES256", persist_path=self.key_path)
        signer = JwtSigner(jwk, "ES256", issuer="https://v.example.com")
        claims = verify_token(signer.sign({"auto": True}), jwk)
        self.assertTrue(claims["auto"])
        self.assertTrue(os.path.exists(self.key_path))

    def test_autogenerate_ps384_makes_rsa_key(self):
        jwk = generate_signing_key("PS384", persist_path=self.key_path)
        self.assertEqual(jwk.get("kty"), "RSA")
        signer = JwtSigner(jwk, "PS384", issuer="https://v.example.com")
        verify_token(signer.sign({}), jwk)

    def test_autogenerate_rsa_key_size(self):
        # Auto-generated RSA keys are RSA_GENERATION_SIZE bits, not the
        # 2048-bit minimum operator keys may use. The size is decoded from
        # the public modulus independently of the module's own helper, so a
        # bug in _rsa_modulus_size cannot hide behind this assertion.
        jwk = generate_signing_key("RS256", persist_path=self.key_path)
        n = jwk.export_public(as_dict=True)["n"]
        modulus = int.from_bytes(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4)), "big")
        self.assertEqual(modulus.bit_length(), 3072)

    # --- persistence and restart reuse (AC9) ---

    def test_persisted_key_reused_across_restarts(self):
        first = generate_signing_key("ES256", persist_path=self.key_path)
        resolved = resolve_signing_key(None, None, "ES256", self.key_path)
        self.assertEqual(resolved.thumbprint(), first.thumbprint())
        self.assertEqual(resolved.get("kid"), first.get("kid"))

    def test_deleted_key_file_regenerates_new_kid(self):
        first = generate_signing_key("ES256", persist_path=self.key_path)
        os.unlink(self.key_path)
        second = resolve_signing_key(None, None, "ES256", self.key_path)
        self.assertNotEqual(second.thumbprint(), first.thumbprint())

    def test_corrupt_key_file_is_hard_error_not_regenerated(self):
        generate_signing_key("ES256", persist_path=self.key_path)
        self._write(b"not a pem file at all")
        with self.assertRaises(JwtKeyError):
            resolve_signing_key(None, None, "ES256", self.key_path)
        # the corrupt file must still be there (no silent regeneration)
        self.assertTrue(os.path.exists(self.key_path))

    def test_unreadable_key_file_is_hard_error(self):
        if os.getuid() == 0:
            self.skipTest("permission checks do not apply when running as root")
        generate_signing_key("ES256", persist_path=self.key_path)
        os.chmod(self.key_path, 0o000)
        with self.assertRaises(JwtKeyError):
            resolve_signing_key(None, None, "ES256", self.key_path)

    def test_algorithm_change_regenerates_with_warning(self):
        first = generate_signing_key("ES256", persist_path=self.key_path)
        with self.assertLogs("keylime.jwt", level="WARNING") as logs:
            resolved = resolve_signing_key(None, None, "PS384", self.key_path)
        self.assertEqual(resolved.get("kty"), "RSA")
        self.assertNotEqual(resolved.thumbprint(), first.thumbprint())
        # the warning names the old kid, so the pre/post pair is in the logs
        self.assertTrue(any(str(first.get("kid")) in line for line in logs.output), logs.output)
        # the regenerated key is persisted and reused on the next start
        again = resolve_signing_key(None, None, "PS384", self.key_path)
        self.assertEqual(again.thumbprint(), resolved.thumbprint())

    def test_unmapped_algorithm_without_persisted_key_gives_map_error(self):
        with self.assertRaises(JwtSigningError) as ctx:
            resolve_signing_key(None, None, "ES256K", self.key_path)
        self.assertIn("extend the algorithm key-type map", str(ctx.exception))

    def test_unmapped_algorithm_with_incompatible_persisted_key_warns_then_map_error(self):
        generate_signing_key("ES256", persist_path=self.key_path)
        with self.assertLogs("keylime.jwt", level="WARNING"):
            with self.assertRaises(JwtSigningError) as ctx:
                resolve_signing_key(None, None, "ES256K", self.key_path)
        self.assertIn("extend the algorithm key-type map", str(ctx.exception))

    def test_unmapped_algorithm_with_compatible_persisted_key_is_used(self):
        jwk = JWK.generate(kty="EC", crv="P-256K")
        self._write(jwk.export_to_pem(private_key=True, password=None))
        resolved = resolve_signing_key(None, None, "ES256K", self.key_path)
        self.assertEqual(resolved.thumbprint(), jwk.thumbprint())

    def test_persisted_file_permissions(self):
        generate_signing_key("ES256", persist_path=self.key_path)
        mode = stat.S_IMODE(os.stat(self.key_path).st_mode)
        self.assertEqual(mode, 0o600)
        # assert on a directory created by the persistence code itself
        sub = os.path.join(self.tmp_dir, "signing", "k.pem")
        generate_signing_key("ES256", persist_path=sub)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(sub)).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(sub).st_mode), 0o600)

    def test_persist_warns_on_group_accessible_directory(self):
        # A pre-existing directory looser than 0700 is used (the key file
        # itself is still 0600) but flagged, so the operator can tighten it
        loose_dir = os.path.join(self.tmp_dir, "loose")
        os.mkdir(loose_dir, 0o755)
        with self.assertLogs("keylime.jwt", level="WARNING") as logs:
            generate_signing_key("ES256", persist_path=os.path.join(loose_dir, "k.pem"))
        self.assertTrue(any("group/world accessible" in line for line in logs.output), logs.output)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(loose_dir, "k.pem")).st_mode), 0o600)

    def test_persist_unwritable_directory_is_clear_error(self):
        # A read-only key directory fails at mkstemp; the error must be a
        # JwtKeyError naming the directory, not a raw PermissionError
        if os.getuid() == 0:
            self.skipTest("permission checks do not apply when running as root")
        noperm_dir = os.path.join(self.tmp_dir, "noperm")
        os.mkdir(noperm_dir, 0o500)
        with self.assertRaises(JwtKeyError) as ctx:
            generate_signing_key("ES256", persist_path=os.path.join(noperm_dir, "k.pem"))
        self.assertIn(noperm_dir, str(ctx.exception))
        self.assertIn("temporary file", str(ctx.exception))

    def test_persist_key_directory_is_a_file_is_clear_error(self):
        # makedirs over an existing regular file fails; wrapped, not a raw
        # FileExistsError
        blocker = os.path.join(self.tmp_dir, "blocker")
        with open(blocker, "wb") as f:
            f.write(b"not a directory")
        with self.assertRaises(JwtKeyError) as ctx:
            generate_signing_key("ES256", persist_path=os.path.join(blocker, "k.pem"))
        self.assertIn(blocker, str(ctx.exception))

    def test_persist_target_is_a_directory_is_clear_error(self):
        # os.replace onto a directory fails at the final step; wrapped, not
        # a raw IsADirectoryError, and the temporary file is cleaned up
        target_dir = os.path.join(self.tmp_dir, "target")
        os.mkdir(target_dir, 0o700)
        with self.assertRaises(JwtKeyError) as ctx:
            generate_signing_key("ES256", persist_path=target_dir)
        self.assertIn("persist", str(ctx.exception))
        leftovers = [n for n in os.listdir(self.tmp_dir) if n.startswith(".jwt_signing_key.")]
        self.assertEqual(leftovers, [])

    def test_password_with_empty_key_path_warns(self):
        generate_signing_key("ES256", persist_path=self.key_path)
        with self.assertLogs("keylime.jwt", level="WARNING") as logs:
            resolve_signing_key(None, "some-password", "ES256", self.key_path)
        # the message names both options, so the operator knows which one
        # to fix
        self.assertTrue(
            any("jwt_signing_key_password is set but jwt_signing_key is empty" in line for line in logs.output),
            logs.output,
        )

    def test_missing_operator_key_is_fatal_without_autogen_fallback(self):
        # A typo in jwt_signing_key (or an unmounted secret volume) must
        # stop the verifier; it must never silently fall back to an
        # auto-generated key that relying parties were never provisioned
        # to trust
        absent = os.path.join(self.tmp_dir, "absent.pem")
        autogen = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        with self.assertRaises(JwtKeyError):
            resolve_signing_key(absent, None, "ES256", autogen)
        self.assertFalse(os.path.exists(autogen))

    def test_permission_check_uses_the_opened_file(self):
        # The checks must read the opened file descriptor, not re-stat
        # the path: a file swapped in at the path between the open and
        # the check must not influence the judgment of what was opened.
        # Here the opened file is group-readable (must be rejected) and
        # the decoy swapped onto the path is 0600.
        generate_signing_key("ES256", persist_path=self.key_path)
        os.chmod(self.key_path, 0o644)
        decoy = os.path.join(self.tmp_dir, "decoy.pem")
        generate_signing_key("ES256", persist_path=decoy)
        real_open = os.open

        def open_then_swap(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if path == self.key_path:
                os.replace(decoy, path)
            return fd

        with patch("keylime.jwt.os.open", side_effect=open_then_swap):
            with self.assertRaises(JwtKeyError) as ctx:
                load_signing_key(self.key_path, None, "ES256")
        self.assertIn("group/world accessible", str(ctx.exception))

    def test_operator_key_path_used_when_configured(self):
        jwk = generate_signing_key("ES256")
        pem = jwk.export_to_pem(private_key=True, password=None)
        self._write(pem)
        resolved = resolve_signing_key(self.key_path, None, "ES256", "/nonexistent/autogen.pem")
        self.assertEqual(resolved.thumbprint(), jwk.thumbprint())

    def test_operator_key_corruption_is_hard_error(self):
        self._write(b"garbage")
        with self.assertRaises(JwtKeyError):
            resolve_signing_key(self.key_path, None, "ES256", None)

    # --- concurrent resolution (multiple instances, restart overlap) ---

    def test_concurrent_resolution_converges_on_one_kid(self):
        # Two verifier processes resolving a fresh shared path must end up
        # with the same key: the persisted file and every in-memory signer
        # agree on one kid, so no process silently rotates on the next
        # start. The barrier maximizes overlap; under the lock the result
        # is deterministic, not probabilistic.
        path = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        kids = []
        barrier = threading.Barrier(2)

        def resolve():
            barrier.wait()
            kids.append(resolve_signing_key(None, None, "ES256", path).get("kid"))

        threads = [threading.Thread(target=resolve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(kids[0], kids[1])
        persisted = load_signing_key(path, None, "ES256")
        self.assertEqual(kids[0], persisted.get("kid"))

    def test_concurrent_regeneration_converges_on_one_kid(self):
        # The same convergence requirement when every contender must
        # replace an incompatible persisted key (algorithm change plus a
        # restart overlapping the old process)
        path = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        old = generate_signing_key("ES256", persist_path=path)
        kids = []
        barrier = threading.Barrier(2)

        def resolve():
            barrier.wait()
            kids.append(resolve_signing_key(None, None, "PS384", path).get("kid"))

        threads = [threading.Thread(target=resolve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertNotEqual(kids[0], old.get("kid"))
        self.assertEqual(kids[0], kids[1])
        persisted = load_signing_key(path, None, "PS384")
        self.assertEqual(kids[0], persisted.get("kid"))

    def test_autogen_lock_file_permissions(self):
        # The cross-process lock file carries no secrets but is still
        # created with restrictive permissions, next to the key
        path = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        resolve_signing_key(None, None, "ES256", path)
        lock = os.path.join(self.tmp_dir, "signing", ".jwt_signing_key.pem.lock")
        self.assertEqual(stat.S_IMODE(os.stat(lock).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(lock)).st_mode), 0o700)

    def test_autogen_lock_permissions_are_umask_proof(self):
        # A hostile umask must not degrade the lock directory or file:
        # both modes are enforced by mechanism, like _persist_key
        old_umask = os.umask(0o777)
        self.addCleanup(os.umask, old_umask)
        path = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        resolve_signing_key(None, None, "ES256", path)
        lock = os.path.join(self.tmp_dir, "signing", ".jwt_signing_key.pem.lock")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(lock)).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(lock).st_mode), 0o600)

    def test_autogen_lock_failure_is_wrapped(self):
        # A lock acquisition failure (e.g. ENOLCK on a filesystem without
        # flock support) must surface as JwtKeyError, not a raw OSError
        path = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        with patch("keylime.jwt.fcntl.flock", side_effect=OSError(37, "No locks available")):
            with self.assertRaises(JwtKeyError) as ctx:
                resolve_signing_key(None, None, "ES256", path)
        self.assertIn("lock", str(ctx.exception))

    def test_autogen_lock_wait_is_logged(self):
        # A contended lock logs before blocking, so a hung holder is
        # visible in the journal instead of a silent startup hang
        path = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        calls = []

        def flock_then_succeed(_fd, operation):
            calls.append(operation)
            if len(calls) == 1:
                raise BlockingIOError()  # the non-blocking probe

        with patch("keylime.jwt.fcntl.flock", side_effect=flock_then_succeed):
            with self.assertLogs("keylime.jwt", level="INFO") as logs:
                resolve_signing_key(None, None, "ES256", path)
        self.assertTrue(any("waiting for another process" in line for line in logs.output), logs.output)

    def test_autogen_lock_symlink_is_rejected(self):
        # A symlink planted at the lock file path must not be followed
        # (with O_CREAT it would make the verifier create a file at the
        # symlink's target)
        real = os.path.join(self.tmp_dir, "real-lock")
        with open(real, "wb") as f:
            f.write(b"x")
        signing_dir = os.path.join(self.tmp_dir, "signing")
        os.makedirs(signing_dir, mode=0o700)
        lock = os.path.join(signing_dir, ".jwt_signing_key.pem.lock")
        os.symlink(real, lock)
        with self.assertRaises(JwtKeyError) as ctx:
            resolve_signing_key(None, None, "ES256", os.path.join(signing_dir, "jwt_signing_key.pem"))
        self.assertIn("lock file", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
