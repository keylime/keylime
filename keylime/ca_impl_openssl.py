import datetime
import ipaddress
import socket
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509 import Certificate, CertificateBuilder, Name
from cryptography.x509.oid import NameOID

from keylime import config, keylime_logging
from keylime.types import CERTIFICATE_PRIVATE_KEY_TYPES

logger = keylime_logging.init_logging("ca-impl-openssl")


def get_san_entries(
    bind_address: Optional[str] = None,
    additional_dns: Optional[List[str]] = None,
    additional_ips: Optional[List[str]] = None,
) -> Tuple[List[str], List[str]]:
    """
    Gather Subject Alternative Name (SAN) entries for certificate generation.

    Returns a tuple of (dns_names, ip_addresses) to be included as SANs.

    Args:
        bind_address: The IP address or hostname the server binds to.
                     If "0.0.0.0" or "::", only localhost entries are added.
        additional_dns: Additional DNS names to include in the certificate.
        additional_ips: Additional IP addresses to include in the certificate.

    Returns:
        Tuple of (dns_names, ip_addresses) lists.
    """
    dns_names: set[str] = set()
    ip_addresses: set[str] = set()

    # Always include localhost entries for local testing
    dns_names.add("localhost")
    ip_addresses.add("127.0.0.1")
    ip_addresses.add("::1")

    # Add system hostname
    hostname: Optional[str] = None
    try:
        hostname = socket.gethostname()
        if hostname:
            dns_names.add(hostname)
    except OSError:
        pass

    # Add FQDN if different from hostname
    try:
        fqdn = socket.getfqdn()
        if fqdn and fqdn != hostname:
            dns_names.add(fqdn)
    except OSError:
        pass

    # Process the bind address
    if bind_address:
        try:
            addr = ipaddress.ip_address(bind_address)
            if not addr.is_unspecified:
                ip_addresses.add(bind_address)
        except ValueError:
            # It's a hostname, not an IP
            dns_names.add(bind_address)

    # Add any additional DNS names
    if additional_dns:
        for dns in additional_dns:
            if dns:
                dns_names.add(dns)

    # Add any additional IP addresses
    if additional_ips:
        for ip in additional_ips:
            if ip:
                try:
                    # Validate the IP address
                    ipaddress.ip_address(ip)
                    ip_addresses.add(ip)
                except ValueError:
                    # Invalid IP, skip
                    pass

    return sorted(dns_names), sorted(ip_addresses)


def mk_cert_valid(cert_req: CertificateBuilder, days: int = 365) -> CertificateBuilder:
    """
    Make a cert valid from now and til 'days' from now.
    Args:
       cert_req -- cryptography.x509.base.CertificateBuilder
       days -- number of days cert is valid for from now.
    Returns: updated cryptography.x509.base.CertificateBuilder
    """

    one_day = datetime.timedelta(1, 0, 0)
    today = datetime.datetime.now(datetime.timezone.utc)
    cert_req = cert_req.not_valid_before(today)
    cert_req = cert_req.not_valid_after(today + (one_day * days))
    return cert_req


def mk_name(common_name: str) -> Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, config.get("ca", "cert_country")),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.get("ca", "cert_state")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, config.get("ca", "cert_locality")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get("ca", "cert_organization")),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.get("ca", "cert_org_unit")),
        ]
    )


def mk_request(bits: int, common_name: str) -> Tuple[CertificateBuilder, RSAPrivateKey]:
    """
    Create a X509 request with the given number of bits in they key.
    Args:
      bits -- number of RSA key bits
      common_name -- common name in the request
    Returns a X509 request and the private key
    """

    privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )

    cert_req = x509.CertificateBuilder()

    subject = mk_name(common_name)
    cert_req = cert_req.subject_name(subject)
    return cert_req, privkey


def mk_cacert(name: Optional[str] = None) -> Tuple[Certificate, RSAPrivateKey, RSAPublicKey]:
    """
    Make a CA certificate.
    Returns the certificate, private key and public key.
    """

    if name is None:
        name = config.get("ca", "cert_ca_name")
    cert_req, privkey = mk_request(config.getint("ca", "cert_bits"), name)

    pubkey = privkey.public_key()
    cert_req = cert_req.public_key(pubkey)

    cert_req = cert_req.serial_number(1)
    cert_req = mk_cert_valid(cert_req, config.getint("ca", "cert_ca_lifetime"))
    cert_req = cert_req.issuer_name(mk_name(name))

    # Extensions.
    extensions = [
        # Basic Constraints.
        (x509.BasicConstraints(ca=True, path_length=None), True),
        # Subject Key Identifier.
        (x509.SubjectKeyIdentifier.from_public_key(pubkey), False),
        # CRL Distribution Points.
        (
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(config.get("ca", "cert_crl_dist")),
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    ),
                ]
            ),
            False,
        ),
        # Key Usage.
        (
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        ),
        # Required by RFC 5280 (section 4.2.1.1) and enforced by default in Python 3.13 and up
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(pubkey), False),
    ]

    for ext, critical in extensions:
        cert_req = cert_req.add_extension(ext, critical)

    cert = cert_req.sign(
        private_key=privkey,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return cert, privkey, pubkey


def mk_signed_cert(
    cacert: Certificate,
    ca_privkey: CERTIFICATE_PRIVATE_KEY_TYPES,
    name: str,
    serialnum: int,
    san_dns: Optional[List[str]] = None,
    san_ips: Optional[List[str]] = None,
) -> Tuple[Certificate, RSAPrivateKey]:
    """
    Create a CA cert + server cert + server private key.

    Args:
        cacert: The CA certificate used to sign the new certificate.
        ca_privkey: The CA private key used to sign the new certificate.
        name: The common name for the certificate (e.g., "server" or "client").
        serialnum: The serial number for the certificate.
        san_dns: Optional list of DNS names to include in the Subject Alternative Name.
        san_ips: Optional list of IP addresses to include in the Subject Alternative Name.

    Returns:
        A tuple of (certificate, private_key).
    """

    cert_req, privkey = mk_request(config.getint("ca", "cert_bits"), common_name=name)
    pubkey = privkey.public_key()
    cert_req = cert_req.public_key(pubkey)

    cert_req = cert_req.serial_number(serialnum)
    cert_req = mk_cert_valid(cert_req)
    cert_req = cert_req.issuer_name(cacert.issuer)

    # Build Subject Alternative Name entries
    san_entries: List[x509.GeneralName] = []

    # Add DNS names
    if san_dns:
        for dns in san_dns:
            san_entries.append(x509.DNSName(dns))

    # Add IP addresses
    if san_ips:
        for ip in san_ips:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                logger.debug("Skipping invalid IP address in SAN: '%s'", ip)

    # If no SANs provided, fall back to using the name
    if not san_entries:
        san_entries.append(x509.DNSName(name))

    # Extensions.
    extensions = [
        # OID 2.16.840.1.113730.1.13 is Netscape Comment.
        # http://oid-info.com/get/2.16.840.1.113730.1.13
        x509.UnrecognizedExtension(
            oid=x509.ObjectIdentifier("2.16.840.1.113730.1.13"),
            value=b"SSL Server",
        ),
        # Subject Alternative Name.
        x509.SubjectAlternativeName(san_entries),
        # CRL Distribution Points.
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(config.get("ca", "cert_crl_dist")),
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]
        ),
        # Required by RFC 5280 (section 4.2.1.1) and enforced by default in Python 3.13 and up
        x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),  # type: ignore
    ]

    for ext in extensions:
        cert_req = cert_req.add_extension(ext, critical=False)

    cert = cert_req.sign(
        private_key=ca_privkey,  # pyright: ignore[reportArgumentType]
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )
    return cert, privkey


def gencrl(serials: List[int], cert: str, ca_pk: str) -> bytes:
    ca_cert = x509.load_pem_x509_certificate(cert.encode())
    priv_key = load_pem_private_key(ca_pk.encode(), None, backend=default_backend())
    date_now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.issuer)
    builder = builder.last_update(date_now)
    builder = builder.next_update(date_now)

    for serial in serials:
        cert_builder = x509.RevokedCertificateBuilder()
        cert_builder = cert_builder.serial_number(int(serial))
        cert_builder = cert_builder.revocation_date(date_now)
        builder = builder.add_revoked_certificate(cert_builder.build())

    if not isinstance(
        priv_key, (EllipticCurvePrivateKey, RSAPrivateKey, DSAPrivateKey, Ed448PrivateKey, Ed25519PrivateKey)
    ):
        raise ValueError(f"Unsupported key type {type(priv_key).__name__}")
    crl = builder.sign(private_key=priv_key, algorithm=hashes.SHA256(), backend=default_backend())
    return crl.public_bytes(encoding=Encoding.DER)
