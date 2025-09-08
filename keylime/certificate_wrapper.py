"""
X.509 Certificate wrapper that preserves original bytes for malformed certificates.

This module provides a wrapper around cryptography.x509.Certificate that preserves
the original certificate bytes when the certificate required pyasn1 re-encoding
due to ASN.1 DER non-compliance. This ensures signature validity is maintained
throughout the database lifecycle.
"""

import base64
from typing import Any, Dict, Optional

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding


class CertificateWrapper:
    """
    A wrapper around cryptography.x509.Certificate that preserves original bytes
    when malformed certificates require pyasn1 re-encoding.

    This class wraps a cryptography.x509.Certificate and adds the ability
    to store the original certificate bytes when the certificate was malformed
    and required re-encoding using pyasn1. This ensures that signature validation
    works correctly even for certificates that don't strictly follow ASN.1 DER.
    """

    def __init__(self, cert: cryptography.x509.Certificate, original_bytes: Optional[bytes] = None):
        """
        Initialize the wrapper certificate.

        :param cert: The cryptography.x509.Certificate object
        :param original_bytes: The original DER bytes if certificate was re-encoded, None otherwise
        """
        self._cert = cert
        self._original_bytes = original_bytes

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the wrapped certificate."""
        return getattr(self._cert, name)

    def __setstate__(self, state: Dict[str, Any]) -> None:
        """Support for pickling."""
        self.__dict__.update(state)

    def __getstate__(self) -> Dict[str, Any]:
        """Support for pickling."""
        return self.__dict__

    @property
    def has_original_bytes(self) -> bool:
        """Check if this certificate has preserved original bytes."""
        return self._original_bytes is not None

    @property
    def original_bytes(self) -> Optional[bytes]:
        """Return the preserved original bytes if available."""
        return self._original_bytes

    def public_bytes(self, encoding: Encoding) -> bytes:
        """
        Return certificate bytes, using original bytes when available.

        For certificates with preserved original bytes, this method always uses
        the original DER bytes to maintain signature validity. For PEM encoding,
        it converts the original DER bytes to PEM format.
        """
        if self.has_original_bytes:
            if encoding == Encoding.DER:
                return self._original_bytes  # type: ignore[return-value]
            if encoding == Encoding.PEM:
                # Convert original DER bytes to PEM format
                der_b64 = base64.b64encode(self._original_bytes).decode("utf-8")  # type: ignore[arg-type]
                # Split into 64-character lines per PEM specification (RFC 1421)
                lines = [der_b64[i : i + 64] for i in range(0, len(der_b64), 64)]
                # Create PEM format with proper headers
                pem_content = "\n".join(["-----BEGIN CERTIFICATE-----"] + lines + ["-----END CERTIFICATE-----"]) + "\n"
                return pem_content.encode("utf-8")

        # For certificates without original bytes, use standard method
        return self._cert.public_bytes(encoding)

    # Delegate common certificate methods to maintain full compatibility
    def __str__(self) -> str:
        return f"CertificateWrapper(subject={self._cert.subject})"

    def __repr__(self) -> str:
        return f"CertificateWrapper(subject={self._cert.subject}, has_original_bytes={self.has_original_bytes})"


def wrap_certificate(cert: cryptography.x509.Certificate, original_bytes: Optional[bytes] = None) -> CertificateWrapper:
    """
    Factory function to create a wrapped certificate.

    :param cert: The cryptography.x509.Certificate object
    :param original_bytes: The original DER bytes if certificate was re-encoded
    :returns: Wrapped certificate that preserves original bytes
    """
    return CertificateWrapper(cert, original_bytes)
