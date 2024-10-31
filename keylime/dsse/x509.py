"""x509 signing/verification implementation."""

import base64
import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from . import dsse


class Signer(dsse.Signer):
    def __init__(self, secret_key: ec.EllipticCurvePrivateKey, certificate_path: str):
        self.secret_key = secret_key
        self.certificate = self.construct(secret_key, certificate_path=certificate_path)

    @classmethod
    def create(cls, keypath: str = "private_x509.key", certificate_path: str = "certificate.crt") -> "Signer":
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        with open(keypath, "wb") as pem_out:
            pem_out.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        return Signer(private_key, certificate_path=certificate_path)

    @classmethod
    def construct(
        cls,
        private_key: ec.EllipticCurvePrivateKey,
        subject_name: str = "dsse_lib",
        issuer_name: str = "dsse_lib",
        subject_alternative_name: str = "dsse_lib",
        expiration: int = 30,
        certificate_path: str = "certificate.crt",
    ) -> Certificate:
        one_day = datetime.timedelta(1, 0, 0)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
                ]
            )
        )
        builder = builder.issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
                ]
            )
        )
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * expiration))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject_alternative_name)]), critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )

        with open(certificate_path, "wb") as crt_out:
            crt_out.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
        return certificate

    def sign(self, message: bytes) -> bytes:
        """Returns the signature of `message`."""
        artifact_signature = self.secret_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return artifact_signature

    def keyid(self) -> str:
        """Returns the base64-encoded certificate."""
        return Verifier(self.certificate).keyid()


class Verifier(dsse.Verifier):
    def __init__(self, certificate: Certificate):
        self.certificate = certificate

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""
        try:
            public_key = self.certificate.public_key()
            assert isinstance(public_key, (ec.EllipticCurvePublicKey))
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature as _:
            return False

    def keyid(self) -> str:
        """Returns the base64-encoded certificate."""
        return base64.b64encode(self.certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode()
