"""Tools for creating a CA cert and signed server certs.

Divined from http://svn.osafoundation.org/m2crypto/trunk/tests/test_x509.py
The mk_temporary_xxx calls return a NamedTemporaryFile with certs.
Usage:
  # Create a temporary CA cert and it's private key
  cacert, cakey = mk_temporary_cacert()
  # Create a temporary server cert+key, signed by the CA
  server_cert = mk_temporary_cert(cacert.name, cakey.name, '*.server.co.uk')

Protips:
  # openssl verify -CAfile cacert.crt cacert.crt cert.crt
  # openssl x509 -in cert.crt -noout -text
  # openssl x509 -in cacert.crt -noout -text

"""

import argparse
import base64
import datetime
import getpass
import glob
import io
import os
import socket
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

try:
    from yaml import CSafeDumper as SafeDumper
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader, SafeDumper  # type: ignore

from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.general_name import UniformResourceIdentifier

from keylime import ca_impl_openssl as ca_impl
from keylime import cmd_exec, config, crypto, fs_util, json, keylime_logging, revocation_notifier

logger = keylime_logging.init_logging("ca-util")

global_password: Optional[str] = None


def load_cert_by_path(cert_path: str) -> Certificate:
    cert = None
    with open(cert_path, "rb") as ca_file:
        cert = x509.load_pem_x509_certificate(
            data=ca_file.read(),
            backend=default_backend(),
        )
    return cert


def setpassword(pw: Optional[str]) -> None:
    global global_password
    if not pw:
        pw = getpass.getpass("Please enter the password to decrypt your keystore: ")

    if not pw:
        raise Exception("You must specify a password!")

    global_password = pw


def cmd_mkcert(workingdir: str, name: str, password: Optional[str] = None) -> None:
    cwd = os.getcwd()
    mask = os.umask(0o037)
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private()
        cacert = load_cert_by_path("cacert.crt")
        ca_pk = serialization.load_pem_private_key(priv[0]["ca"], password=None, backend=default_backend())
        if not isinstance(
            ca_pk, (EllipticCurvePrivateKey, RSAPrivateKey, DSAPrivateKey, Ed448PrivateKey, Ed25519PrivateKey)
        ):
            raise Exception(
                f"Private key of type {type(ca_pk).__name__} cannot be used for creating an x509 certificate"
            )

        cert, pk = ca_impl.mk_signed_cert(cacert, ca_pk, name, priv[0]["lastserial"] + 1)

        with os.fdopen(os.open(f"{name}-cert.crt", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        priv[0][name] = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption(),
        )

        # increment serial number after successful creation
        priv[0]["lastserial"] += 1

        write_private(priv)

        with os.fdopen(os.open(f"{name}-private.pem", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(priv[0][name])

        with os.fdopen(os.open(f"{name}-public.pem", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(
                pk.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        cc = load_cert_by_path(f"{name}-cert.crt")
        pubkey = cacert.public_key()
        assert isinstance(pubkey, rsa.RSAPublicKey)
        assert cc.signature_hash_algorithm is not None
        pubkey.verify(
            cc.signature,
            cc.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cc.signature_hash_algorithm,
        )

        logger.info("Created certificate for name %s successfully in %s", name, workingdir)
    except crypto_exceptions.InvalidSignature:
        logger.error("ERROR: Cert does not validate against CA")
    finally:
        os.umask(mask)
        os.chdir(cwd)


def cmd_init(workingdir: str) -> None:
    cwd = os.getcwd()
    mask = os.umask(0o037)
    try:
        fs_util.ch_dir(workingdir)

        rmfiles("*.pem")
        rmfiles("*.crt")
        rmfiles("*.zip")
        rmfiles("*.der")
        rmfiles("private.yml")

        cacert, ca_pk, _ = ca_impl.mk_cacert()  # pylint: disable=W0632
        priv = read_private()

        # write out keys
        with open("cacert.crt", "wb") as f:
            f.write(cacert.public_bytes(serialization.Encoding.PEM))

        priv[0]["ca"] = ca_pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # store the last serial number created.
        # the CA is always serial # 1
        priv[0]["lastserial"] = 1

        write_private(priv)

        with os.fdopen(os.open("ca-public.pem", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(
                ca_pk.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        # generate an empty crl
        cacert_str = cacert.public_bytes(serialization.Encoding.PEM).decode()
        crl = ca_impl.gencrl([], cacert_str, priv[0]["ca"].decode())

        if isinstance(crl, str):
            crl = crl.encode("utf-8")

        with open("cacrl.der", "wb") as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der", "cacrl.pem")

        # Sanity checks...
        cac = load_cert_by_path("cacert.crt")
        pubkey = cacert.public_key()
        assert isinstance(pubkey, rsa.RSAPublicKey)
        assert cac.signature_hash_algorithm is not None
        pubkey.verify(
            cac.signature,
            cac.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cac.signature_hash_algorithm,
        )

        logger.info("CA certificate created successfully in %s", workingdir)
    except crypto_exceptions.InvalidSignature:
        logger.error("ERROR: Cert does not self validate")
    finally:
        os.chdir(cwd)
        os.umask(mask)


def cmd_certpkg(workingdir: str, name: str, insecure: bool = False) -> Tuple[bytes, int, str]:
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        # zip up the crt, private key, and public key

        with open("cacert.crt", "rb") as f:
            cacert = f.read()

        with open(f"{name}-public.pem", "rb") as f:
            pub = f.read()

        with open(f"{name}-cert.crt", "rb") as f:
            cert = f.read()

        with open("cacrl.der", "rb") as f:
            crl = f.read()

        with open("cacrl.pem", "rb") as f:
            crlpem = f.read()

        cert_obj = x509.load_pem_x509_certificate(
            data=cert,
            backend=default_backend(),
        )

        serial = cert_obj.serial_number
        subject = cert_obj.subject.rfc4514_string()

        priv = read_private()
        private = priv[0][name]

        with open(f"{name}-private.pem", "rb") as f:
            prot_priv = f.read()

        # no compression to avoid extraction errors in tmpfs
        sf = io.BytesIO()
        with zipfile.ZipFile(sf, "w", compression=zipfile.ZIP_STORED) as f:
            f.writestr(f"{name}-public.pem", pub)
            f.writestr(f"{name}-cert.crt", cert)
            f.writestr(f"{name}-private.pem", private)
            f.writestr("cacert.crt", cacert)
            f.writestr("cacrl.der", crl)
            f.writestr("cacrl.pem", crlpem)
        pkg = sf.getvalue()

        if insecure:
            logger.warning("Unprotected private keys in cert package being written to disk")
            with open(f"{name}-pkg.zip", "wb") as f:
                f.write(pkg)
        else:
            # actually output the package to disk with a protected private key
            with zipfile.ZipFile(f"{name}-pkg.zip", "w", compression=zipfile.ZIP_STORED) as f:
                f.writestr(f"{name}-public.pem", pub)
                f.writestr(f"{name}-cert.crt", cert)
                f.writestr(f"{name}-private.pem", prot_priv)
                f.writestr("cacert.crt", cacert)
                f.writestr("cacrl.der", crl)
                f.writestr("cacrl.pem", crlpem)

        logger.info("Creating cert package for %s in %s-pkg.zip", name, name)

        return pkg, serial, subject
    finally:
        os.chdir(cwd)


def convert_crl_to_pem(derfile: str, pemfile: str) -> None:
    with open(derfile, "rb") as der_f, open(pemfile, "wb") as pem_f:
        der_crl = der_f.read()
        pem_f.write(x509.load_der_x509_crl(der_crl).public_bytes(encoding=serialization.Encoding.PEM))


def get_crl_distpoint(cert_path: str) -> Optional[str]:
    cert_obj = load_cert_by_path(cert_path)

    try:
        crl_distpoints = cert_obj.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dstpnt in crl_distpoints:
            for point in dstpnt.full_name:
                if isinstance(point, UniformResourceIdentifier):
                    return point.value
    except ExtensionNotFound:
        pass

    logger.info("No CRL distribution points in %s", cert_path)
    return ""


# to check: openssl crl -inform DER -text -noout -in cacrl.der


def cmd_revoke(workingdir: str, name: Optional[str] = None, serial: Optional[int] = None) -> bytes:
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private()

        if name is not None and serial is not None:
            raise Exception("You may not specify a cert and a serial at the same time")
        if name is None and serial is None:
            raise Exception("You must specify a cert or a serial to revoke")
        if name is not None:
            # load up the cert
            cert = load_cert_by_path(f"{name}-cert.crt")
            serial = cert.serial_number

        # convert serial to string
        serial_str = str(serial)

        # get the ca key cert and keys as strings
        with open("cacert.crt", encoding="utf-8") as f:
            cacert = f.read()
        ca_pk = priv[0]["ca"].decode("utf-8")

        if serial_str not in priv[0]["revoked_keys"]:
            priv[0]["revoked_keys"].append(serial_str)

        crl = ca_impl.gencrl(priv[0]["revoked_keys"], cacert, ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        if os.stat("cacrl.der").st_size:
            with open("cacrl.der", "wb") as f:
                f.write(crl)
            convert_crl_to_pem("cacrl.der", "cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl


# regenerate the crl without revoking anything


def cmd_regencrl(workingdir: str) -> bytes:
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private()

        # get the ca key cert and keys as strings
        with open("cacert.crt", encoding="utf-8") as f:
            cacert = f.read()
        ca_pk = priv[0]["ca"].decode()

        crl = ca_impl.gencrl(priv[0]["revoked_keys"], cacert, ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        with open("cacrl.der", "wb") as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der", "cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl


def cmd_listen(workingdir: str, cert_path: str) -> None:
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        # just load up the password for later
        read_private(True)

        serveraddr = ("", config.CRL_PORT)
        server = ThreadedCRLServer(serveraddr, CRLHandler)
        if os.path.exists("cacrl.der"):
            logger.info("Loading existing crl: %s", os.path.abspath("cacrl.der"))
            with open("cacrl.der", "rb") as f:
                server.setcrl(f.read())
        t = threading.Thread(target=server.serve_forever)
        logger.info("Hosting CRL on %s:%d", socket.getfqdn(), config.CRL_PORT)
        t.start()

        def check_expiration() -> None:
            logger.info("checking CRL for expiration every hour")
            while True:  # pylint: disable=R1702
                try:
                    if os.path.exists("cacrl.der") and os.stat("cacrl.der").st_size:
                        cmd = ("openssl", "crl", "-inform", "der", "-in", "cacrl.der", "-text", "-noout")
                        retout = cmd_exec.run(cmd)["retout"]
                        for line in retout:
                            line = line.strip()
                            if line.startswith(b"Next Update:"):
                                expire = datetime.datetime.strptime(line[13:].decode("utf-8"), "%b %d %H:%M:%S %Y %Z")
                                # check expiration within 6 hours
                                in1hour = datetime.datetime.utcnow() + datetime.timedelta(hours=6)
                                if expire <= in1hour:
                                    logger.info("Certificate to expire soon %s, re-issuing", expire)
                                    cmd_regencrl(workingdir)
                    # check a little less than every hour
                    time.sleep(3540)

                except KeyboardInterrupt:
                    logger.info("TERM Signal received, shutting down...")
                    # server.shutdown()
                    break

        t2 = threading.Thread(target=check_expiration, daemon=True)
        t2.start()

        def revoke_callback(revocation: Dict[str, Union[str, bytes]]) -> None:
            json_meta = json.loads(revocation["meta_data"])
            serial = json_meta["cert_serial"]
            if revocation.get("type", None) != "revocation" or serial is None:
                logger.error("Unsupported revocation message: %s", revocation)
                return

            logger.info("Revoking certificate: %s", serial)
            server.setcrl(cmd_revoke(workingdir, None, serial))

        try:
            while True:
                try:
                    revocation_notifier.await_notifications(revoke_callback, revocation_cert_path=cert_path)
                except Exception as e:
                    logger.exception(e)
                    logger.warning("No connection to revocation server, retrying in 10s...")
                    time.sleep(10)
        except KeyboardInterrupt:
            logger.info("TERM Signal received, shutting down...")
            server.shutdown()
            sys.exit()
    finally:
        os.chdir(cwd)


class ThreadedCRLServer(ThreadingMixIn, HTTPServer):
    published_crl = None

    def setcrl(self, crl: bytes) -> None:
        self.published_crl = crl


class CRLHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        logger.info("GET invoked from %s with uri: %s", str(self.client_address), self.path)

        assert isinstance(self.server, ThreadedCRLServer)
        if self.server.published_crl is None:
            self.send_response(404)
            self.end_headers()
        else:
            # send back the CRL
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.server.published_crl)


def rmfiles(path: str) -> None:
    files = glob.glob(path)
    for f in files:
        os.remove(f)


def write_private(inp: Tuple[Dict[str, Any], str]) -> None:
    priv = inp[0]
    salt = inp[1]

    priv_encoded = yaml.dump(priv, Dumper=SafeDumper)
    assert isinstance(global_password, str)
    key = crypto.kdf(global_password, salt)
    ciphertext = crypto.encrypt(priv_encoded.encode("utf-8"), key)
    towrite = {"salt": salt, "priv": ciphertext}

    mask = os.umask(0o037)
    with os.fdopen(os.open("private.yml", os.O_WRONLY | os.O_CREAT, 0o640), "w", encoding="utf-8") as f:
        yaml.dump(towrite, f, Dumper=SafeDumper)
    os.umask(mask)


def read_private(warn: bool = False) -> Tuple[Dict[str, Any], str]:
    if global_password is None:
        setpassword(getpass.getpass("Please enter the password to decrypt your keystore: "))

    if os.path.exists("private.yml"):
        with open("private.yml", encoding="utf-8") as f:
            toread = yaml.load(f, Loader=SafeLoader)
        assert isinstance(global_password, str)
        key = crypto.kdf(global_password, toread["salt"])
        try:
            plain = crypto.decrypt(toread["priv"], key)
        except ValueError as e:
            raise Exception("Invalid password for keystore") from e

        return yaml.load(plain, Loader=SafeLoader), toread["salt"]

    if warn:
        # file doesn't exist, just invent a salt
        logger.warning("Private certificate data %s does not exist yet.", os.path.abspath("private.yml"))
        logger.warning("Keylime will attempt to load private certificate data again when it is needed.")
    return {"revoked_keys": [], "ca": b""}, base64.b64encode(crypto.generate_random_key()).decode()


def main(argv: List[str] = sys.argv) -> None:  # pylint: disable=dangerous-default-value
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument(
        "-c",
        "--command",
        action="store",
        dest="command",
        required=True,
        help="valid commands are init,create,pkg,revoke,listen",
    )
    parser.add_argument("-n", "--name", action="store", help="the common name of the certificate to create")
    parser.add_argument("-d", "--dir", action="store", help="use a custom directory to store certificates and keys")
    parser.add_argument(
        "-i",
        "--insecure",
        action="store_true",
        default=False,
        help="create cert packages with unprotected private keys and write them to disk.  USE WITH CAUTION!",
    )

    args = parser.parse_args(argv[1:])

    if args.dir is None:
        if not os.access(config.WORK_DIR, os.R_OK + os.W_OK):
            logger.error(
                "If you don't specify a working directory, this process must be run as a user with access to %s",
                config.WORK_DIR,
            )
            sys.exit(-1)
        workingdir = config.CA_WORK_DIR
    else:
        workingdir = args.dir

    # set a conservative general umask
    os.umask(0o077)

    if args.command == "init":
        cmd_init(workingdir)
    elif args.command == "create":
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_mkcert(workingdir, args.name)
    elif args.command == "pkg":
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_certpkg(workingdir, args.name, args.insecure)
    elif args.command == "revoke":
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_revoke(workingdir, args.name)
    elif args.command == "listen":
        if args.name is None:
            args.name = os.path.join(workingdir, "RevocationNotifier-cert.crt")
            logger.warning("using default name for revocation cert %s", args.name)
        cmd_listen(workingdir, args.name)
    else:
        logger.error("Invalid command: %s", args.command)
        parser.print_help()
        sys.exit(-1)
