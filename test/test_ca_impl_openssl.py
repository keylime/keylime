import ipaddress
import os
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import CRLDistributionPoints, SubjectAlternativeName
from cryptography.x509.oid import NameOID

from keylime import ca_impl_openssl

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = f"{PACKAGE_ROOT}/keylime/"

# Custom imports
sys.path.insert(0, CODE_ROOT)

# Explicit `ca` config values for the whole module
CA_TEST_ENV = {
    "KEYLIME_CA_CERT_BITS": "2048",
    "KEYLIME_CA_CERT_COUNTRY": "US",
    "KEYLIME_CA_CERT_STATE": "MA",
    "KEYLIME_CA_CERT_LOCALITY": "Lexington",
    "KEYLIME_CA_CERT_ORGANIZATION": "Keylime",
    "KEYLIME_CA_CERT_ORG_UNIT": "53",
    "KEYLIME_CA_CERT_CA_NAME": "Keylime Certificate Authority",
    "KEYLIME_CA_CERT_CA_LIFETIME": "3650",
    "KEYLIME_CA_CERT_CRL_DIST": "http://localhost:38080/crl",
}

_env_patcher = None


def setUpModule() -> None:
    global _env_patcher
    _env_patcher = mock.patch.dict(os.environ, CA_TEST_ENV)
    _env_patcher.start()


def tearDownModule() -> None:
    assert _env_patcher is not None
    _env_patcher.stop()


class OpenSSL_Test(unittest.TestCase):
    def test_openssl(self):
        _ = ca_impl_openssl.mk_cacert("my ca")
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert()
        cert, _ = ca_impl_openssl.mk_signed_cert(ca_cert, ca_pk, "cert", 4)

        pubkey = ca_cert.public_key()
        assert isinstance(pubkey, RSAPublicKey)
        assert cert.signature_hash_algorithm is not None
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except crypto_exceptions.InvalidSignature:
            self.fail("Certificate signature validation failed.")

        # Make sure serial number in cert is 4.
        self.assertIs(type(cert.serial_number), int)
        self.assertEqual(cert.serial_number, 4)

    def test_openssl_crl_dist(self):
        with mock.patch.dict(os.environ, {"KEYLIME_CA_CERT_CRL_DIST": "http://foobar.org"}):
            _ = ca_impl_openssl.mk_cacert("my ca")
            (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert()
            cert, _ = ca_impl_openssl.mk_signed_cert(ca_cert, ca_pk, "cert", 4)

            pubkey = ca_cert.public_key()
            assert isinstance(pubkey, RSAPublicKey)
            assert cert.signature_hash_algorithm is not None
            try:
                pubkey.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except crypto_exceptions.InvalidSignature:
                self.fail("Certificate signature validation failed.")

            # Make sure serial number in cert is 4.
            self.assertIs(type(cert.serial_number), int)
            self.assertEqual(cert.serial_number, 4)
            self.assertEqual(
                cert.extensions.get_extension_for_class(CRLDistributionPoints).value[0].full_name[0].value,
                os.environ["KEYLIME_CA_CERT_CRL_DIST"],
            )


class TestGetSanEntries(unittest.TestCase):
    """Tests for the get_san_entries function."""

    @mock.patch("keylime.ca_impl_openssl.socket.gethostname")
    @mock.patch("keylime.ca_impl_openssl.socket.getfqdn")
    def test_get_san_entries_with_ip_bind_address(self, mock_getfqdn, mock_gethostname):
        """Test that IP bind address is included in SANs."""
        mock_gethostname.return_value = "testhost"
        mock_getfqdn.return_value = "testhost.example.com"

        dns_names, ip_addresses = ca_impl_openssl.get_san_entries(bind_address="192.168.1.100")

        self.assertIn("localhost", dns_names)
        self.assertIn("testhost", dns_names)
        self.assertIn("testhost.example.com", dns_names)
        self.assertIn("127.0.0.1", ip_addresses)
        self.assertIn("::1", ip_addresses)
        self.assertIn("192.168.1.100", ip_addresses)

    @mock.patch("keylime.ca_impl_openssl.socket.gethostname")
    @mock.patch("keylime.ca_impl_openssl.socket.getfqdn")
    def test_get_san_entries_with_hostname_bind_address(self, mock_getfqdn, mock_gethostname):
        """Test that hostname bind address is included in DNS SANs."""
        mock_gethostname.return_value = "testhost"
        mock_getfqdn.return_value = "testhost.example.com"

        dns_names, ip_addresses = ca_impl_openssl.get_san_entries(bind_address="myserver.local")

        self.assertIn("myserver.local", dns_names)
        self.assertIn("localhost", dns_names)
        self.assertNotIn("myserver.local", ip_addresses)

    @mock.patch("keylime.ca_impl_openssl.socket.gethostname")
    @mock.patch("keylime.ca_impl_openssl.socket.getfqdn")
    def test_get_san_entries_with_wildcard_address(self, mock_getfqdn, mock_gethostname):
        """Test that 0.0.0.0 is not included as an IP SAN."""
        mock_gethostname.return_value = "testhost"
        mock_getfqdn.return_value = "testhost.example.com"

        dns_names, ip_addresses = ca_impl_openssl.get_san_entries(bind_address="0.0.0.0")

        # Should still have localhost entries
        self.assertIn("localhost", dns_names)
        self.assertIn("127.0.0.1", ip_addresses)
        # But not the wildcard address
        self.assertNotIn("0.0.0.0", ip_addresses)

    @mock.patch("keylime.ca_impl_openssl.socket.gethostname")
    @mock.patch("keylime.ca_impl_openssl.socket.getfqdn")
    def test_get_san_entries_with_additional_sans(self, mock_getfqdn, mock_gethostname):
        """Test that additional SANs are included."""
        mock_gethostname.return_value = "testhost"
        mock_getfqdn.return_value = "testhost"

        dns_names, ip_addresses = ca_impl_openssl.get_san_entries(
            bind_address="192.168.1.1",
            additional_dns=["extra.example.com", "another.example.com"],
            additional_ips=["10.0.0.1", "10.0.0.2"],
        )

        self.assertIn("extra.example.com", dns_names)
        self.assertIn("another.example.com", dns_names)
        self.assertIn("10.0.0.1", ip_addresses)
        self.assertIn("10.0.0.2", ip_addresses)

    @mock.patch("keylime.ca_impl_openssl.socket.gethostname")
    @mock.patch("keylime.ca_impl_openssl.socket.getfqdn")
    def test_get_san_entries_with_ipv6(self, mock_getfqdn, mock_gethostname):
        """Test IPv6 addresses in SANs."""
        mock_gethostname.return_value = "testhost"
        mock_getfqdn.return_value = "testhost"

        _, ip_addresses = ca_impl_openssl.get_san_entries(
            bind_address="::1",
            additional_ips=["2001:db8::1"],
        )

        # ::1 is a wildcard-like address, so it's excluded from bind_address
        # but we include it as part of localhost entries
        self.assertIn("::1", ip_addresses)
        self.assertIn("2001:db8::1", ip_addresses)


class TestMkSignedCertWithSans(unittest.TestCase):
    """Tests for mk_signed_cert with SAN parameters."""

    def test_mk_signed_cert_with_dns_sans(self):
        """Test certificate generation with DNS SANs."""
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert()
        cert, _ = ca_impl_openssl.mk_signed_cert(
            ca_cert,
            ca_pk,
            "server",
            5,
            san_dns=["localhost", "myhost.example.com"],
        )

        # Verify the certificate
        pubkey = ca_cert.public_key()
        assert isinstance(pubkey, RSAPublicKey)
        assert cert.signature_hash_algorithm is not None
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except crypto_exceptions.InvalidSignature:
            self.fail("Certificate signature validation failed.")

        # Check SANs
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        dns_names = [name.value for name in san_ext.value if hasattr(name, "value") and isinstance(name.value, str)]
        self.assertIn("localhost", dns_names)
        self.assertIn("myhost.example.com", dns_names)

    def test_mk_signed_cert_with_ip_sans(self):
        """Test certificate generation with IP SANs."""
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert()
        cert, _ = ca_impl_openssl.mk_signed_cert(
            ca_cert,
            ca_pk,
            "server",
            6,
            san_dns=["localhost"],
            san_ips=["127.0.0.1", "192.168.1.100"],
        )

        # Verify the certificate
        pubkey = ca_cert.public_key()
        assert isinstance(pubkey, RSAPublicKey)
        assert cert.signature_hash_algorithm is not None
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except crypto_exceptions.InvalidSignature:
            self.fail("Certificate signature validation failed.")

        # Check SANs
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        ip_addresses = []
        for name in san_ext.value:
            if hasattr(name, "value"):
                if isinstance(name.value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    ip_addresses.append(str(name.value))
        self.assertIn("127.0.0.1", ip_addresses)
        self.assertIn("192.168.1.100", ip_addresses)

    def test_mk_signed_cert_fallback_to_name(self):
        """Test that certificate falls back to name when no SANs provided."""
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert()
        cert, _ = ca_impl_openssl.mk_signed_cert(ca_cert, ca_pk, "server", 7)

        # Check SANs - should contain the fallback name
        san_ext = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        dns_names = [name.value for name in san_ext.value if hasattr(name, "value") and isinstance(name.value, str)]
        self.assertIn("server", dns_names)


class TestCaConfigMapping(unittest.TestCase):
    """Tests that config/env values are actually threaded into the generated certificates."""

    def test_subject_fields_from_config(self):
        (ca_cert, _, _) = ca_impl_openssl.mk_cacert()

        for name in (ca_cert.subject, ca_cert.issuer):
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value, CA_TEST_ENV["KEYLIME_CA_CERT_COUNTRY"]
            )
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value,
                CA_TEST_ENV["KEYLIME_CA_CERT_STATE"],
            )
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value, CA_TEST_ENV["KEYLIME_CA_CERT_LOCALITY"]
            )
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
                CA_TEST_ENV["KEYLIME_CA_CERT_ORGANIZATION"],
            )
            self.assertEqual(
                name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value,
                CA_TEST_ENV["KEYLIME_CA_CERT_ORG_UNIT"],
            )

    def test_ca_name_defaults_to_config(self):
        (ca_cert, _, _) = ca_impl_openssl.mk_cacert()
        cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, CA_TEST_ENV["KEYLIME_CA_CERT_CA_NAME"])

    def test_explicit_name_overrides_config(self):
        (ca_cert, _, _) = ca_impl_openssl.mk_cacert("my ca")
        cn = ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "my ca")

    def test_cert_bits_configurable(self):
        with mock.patch.dict(os.environ, {"KEYLIME_CA_CERT_BITS": "3072"}):
            (ca_cert, ca_pk, ca_pubkey) = ca_impl_openssl.mk_cacert()
            self.assertEqual(ca_pubkey.key_size, 3072)

            cert, privkey = ca_impl_openssl.mk_signed_cert(ca_cert, ca_pk, "server", 8)
            self.assertEqual(privkey.key_size, 3072)
            self.assertIsNotNone(cert)

    def test_cert_ca_lifetime_configurable(self):
        (ca_cert, _, _) = ca_impl_openssl.mk_cacert()
        lifetime = ca_cert.not_valid_after - ca_cert.not_valid_before
        self.assertEqual(lifetime, timedelta(days=int(CA_TEST_ENV["KEYLIME_CA_CERT_CA_LIFETIME"])))

    def test_crl_dist_default_from_config(self):
        (ca_cert, _, _) = ca_impl_openssl.mk_cacert()
        crl_dist = ca_cert.extensions.get_extension_for_class(CRLDistributionPoints).value[0].full_name[0].value
        self.assertEqual(crl_dist, CA_TEST_ENV["KEYLIME_CA_CERT_CRL_DIST"])


if __name__ == "__main__":
    unittest.main()
