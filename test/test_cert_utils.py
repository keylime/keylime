"""
SPDX-License-Identifier: Apache-2.0
Copyright 2022 Red Hat, Inc.
"""

import base64
import os
import unittest

import cryptography

from keylime import cert_utils, tpm_ek_ca

CERT_STORE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tpm_cert_store"))

# The certificate listed in issue #944, from Nuvoton. It fails to
# be parsed by python-cryptography with the following error:
# ValueError: error parsing asn1 value: ParseError { kind: InvalidSetOrdering, location: ["RawCertificate::tbs_cert", "TbsCertificate::issuer", "0", "2"] }
nuvoton_ecdsa_sha256_der = """\
MIICBjCCAaygAwIBAgIIP5MvnZk8FrswCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMYTnV2b3RvbiBU
UE0gUm9vdCBDQSAyMTEwMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9uMAkG
A1UEBhMCVFcwHhcNMTUxMDE5MDQzMjAwWhcNMzUxMDE1MDQzMjAwWjBVMVMwHwYDVQQDExhOdXZv
dG9uIFRQTSBSb290IENBIDIxMTAwJQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRp
b24wCQYDVQQGEwJUVzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPv9uK2BNm8/nmIyNsc2/aKH
V0WRptzge3jKAIgUMosQIokl4LE3iopXWD3Hruxjf9vkLMDJrTeK3hWh2ySS4ySjZjBkMA4GA1Ud
DwEB/wQEAwICBDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSfu3mqD1JieL7RUJKacXHp
ajW+9zAfBgNVHSMEGDAWgBSfu3mqD1JieL7RUJKacXHpajW+9zAKBggqhkjOPQQDAgNIADBFAiEA
/jiywhOKpiMOUnTfDmXsXfDFokhKVNTXB6Xtqm7J8L4CICjT3/Y+rrSnf8zrBXqWeHDh8Wi41+w2
ppq6Ev9orZFI
"""
# This cert from STMicroelectronics presents a different issue when
# parsed by python-cryptography:
# ValueError: error parsing asn1 value: ParseError { kind: ExtraData }
st_sha256_with_rsa_der = """\
MIIEjTCCA3WgAwIBAgIUTL0P5h7nYu2yjVCyaPw1hv89XoIwDQYJKoZIhvcNAQELBQAwVTELMAkG
A1UEBhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBOVjEmMCQGA1UEAxMdU1RNIFRQ
TSBFSyBJbnRlcm1lZGlhdGUgQ0EgMDUwHhcNMTgwNzExMDAwMDAwWhcNMjgwNzExMDAwMDAwWjAA
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0oLAsca4NiovvBNEYfij5MUIi6Jz/2hV
gIDET1Qz3lwwIc/WNwZp9PdHlNuL5jbXUcLMiYSEW8j6pk3yLtV/1M9zB38YkD7BaDVq2mWoNJVZ
ifIg5ADePeZ6DfEaR/nPcTdP4F6OYqLt9llb+rqCkQOKStcVimv2D+u8sQQ7weXRFsRXaeLRMBkO
mIem/sIWit1c86005hWzQrAhZxS5mO1YDOub8ku/3u4gGmtWAVbdxJVjlnxsr06F8tMlvLCG+2/G
XefUz0Iy8UiBUU7Y3dsS2lpsfLeqcu05eeAhgFVApQtPdPI9T5dH5VzUVCwBBNKXCb5QkOGEdfK2
SBpSHwIDAQABo4IBqDCCAaQwHwYDVR0jBBgwFoAUGtuZSrWL5XoMybkA54UeGkPAhmAwQgYDVR0g
BDswOTA3BgRVHSAAMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuc3QuY29tL1RQTS9yZXBvc2l0
b3J5LzBZBgNVHREBAf8ETzBNpEswSTEWMBQGBWeBBQIBDAtpZDo1MzU0NEQyMDEXMBUGBWeBBQIC
DAxTVDMzSFRQSEFIQjQxFjAUBgVngQUCAwwLaWQ6MDA0OTAwMDQwZgYDVR0JBF8wXTAWBgVngQUC
EDENMAsMAzIuMAIBAAIBdDBDBgVngQUCEjE6MDgCAQABAf+gAwoBAaEDCgEAogMKAQCjEDAOFgMz
LjEKAQQKAQIBAf+kDzANFgUxNDAtMgoBAgEBADAOBgNVHQ8BAf8EBAMCBSAwDAYDVR0TAQH/BAIw
ADAQBgNVHSUECTAHBgVngQUIATBKBggrBgEFBQcBAQQ+MDwwOgYIKwYBBQUHMAKGLmh0dHA6Ly9z
ZWN1cmUuZ2xvYmFsc2lnbi5jb20vc3RtdHBtZWtpbnQwNS5jcnQwDQYJKoZIhvcNAQELBQADggEB
ADIvysaTZXuvle6wRGQiIBmEs2yQkQAAuN/UcaWwDrUHz+JZsHhFsmxJVARJQuMdQPUtZRGQyXN3
6Lrc7vrge4QGVLl8Vi84dXcXjFqGQSvnHUcFYD46g9bpFMAzTQBNRlS0+34kgXfPTUCfORryw/b3
fk5Au4WSKAJl3fUZMgwYV52FzyJ6NKm3c2tAAYpbpSX5xCadmThZUUm9U6Fi731eYh93arrS2IDQ
WFiAXuTbemVbrcG/OSAKkPm/bmKiDkILmbEkcV+GHmZ8umWtva9GzzadX90KV6mpIN1dbLkxK5b2
rTJ1x4NA2ZtQMYyT29Yy1UlkjocAaXL5u0m3Hvz/////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
/////w==
"""

st_ecdsa_sha256_der = """\
MIIDAzCCAqmgAwIBAgIUIymn2ai+UaVx1bM26/wU7I+sJd8wCgYIKoZIzj0EAwIwVjELMAkGA1UE
BhMCQ0gxHjAcBgNVBAoTFVNUTWljcm9lbGVjdHJvbmljcyBOVjEnMCUGA1UEAxMeU1RNIFRQTSBF
Q0MgSW50ZXJtZWRpYXRlIENBIDAxMB4XDTE4MDcyNjAwMDAwMFoXDTI4MDcyNjAwMDAwMFowADBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBsTz5y2cedVZxG/GsbXQ9bL6EQylWNjx1b/SSp2EHlN
aJjtn43iz2zb+qot2UOhQIwPxS5hMCXhasw4XsFXgnijggGpMIIBpTAfBgNVHSMEGDAWgBR+uDbO
+9+KY3H/czP5utcUYWyWyzBCBgNVHSAEOzA5MDcGBFUdIAAwLzAtBggrBgEFBQcCARYhaHR0cDov
L3d3dy5zdC5jb20vVFBNL3JlcG9zaXRvcnkvMFkGA1UdEQEB/wRPME2kSzBJMRYwFAYFZ4EFAgEM
C2lkOjUzNTQ0RDIwMRcwFQYFZ4EFAgIMDFNUMzNIVFBIQUhCNDEWMBQGBWeBBQIDDAtpZDowMDQ5
MDAwNDBmBgNVHQkEXzBdMBYGBWeBBQIQMQ0wCwwDMi4wAgEAAgF0MEMGBWeBBQISMTowOAIBAAEB
/6ADCgEBoQMKAQCiAwoBAKMQMA4WAzMuMQoBBAoBAgEB/6QPMA0WBTE0MC0yCgECAQEAMAwGA1Ud
EwEB/wQCMAAwEAYDVR0lBAkwBwYFZ4EFCAEwDgYDVR0PAQH/BAQDAgMIMEsGCCsGAQUFBwEBBD8w
PTA7BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9zdG10cG1lY2NpbnQw
MS5jcnQwCgYIKoZIzj0EAwIDSAAwRQIgcNiZkn7poyk6J8Y1Cnwz4nV7YGPb5pBesBg6bk9n6KIC
IQCE/jkHb/aPP/T3GtfLNHAdHL4JnofAbsDEuLQxAseeZA==
"""


def has_strict_x509_parsing():
    """Indicates whether python-cryptography has strict x509 parsing."""

    # Major release where python-cryptography started being strict
    # when parsing x509 certificates.
    PYCRYPTO_STRICT_X509_MAJOR = 35
    return int(cryptography.__version__.split(".", maxsplit=1)[0]) >= PYCRYPTO_STRICT_X509_MAJOR


def expectedFailureIf(condition):
    """The test is marked as an expectedFailure if the condition is satisfied."""

    def wrapper(func):
        if condition:
            return unittest.expectedFailure(func)
        return func

    return wrapper


class Cert_Utils_Test(unittest.TestCase):
    def test_tpm_cert_store(self):
        tpm_ek_ca.check_tpm_cert_store(CERT_STORE_DIR)
        my_trusted_certs = tpm_ek_ca.cert_loader(CERT_STORE_DIR)

        self.assertNotEqual(len(my_trusted_certs), 0)

    def test_cert_store_certs(self):
        my_trusted_certs = tpm_ek_ca.cert_loader(CERT_STORE_DIR)
        for fname, pem_cert in my_trusted_certs.items():
            try:
                cert = cert_utils.x509_pem_cert(pem_cert)
            except Exception as e:
                self.fail(f"Failed to load certificate {fname}: {e}")
            self.assertIsNotNone(cert)

    def test_verify_ek(self):
        tests = [
            {"cert": st_sha256_with_rsa_der, "expected": True},  # RSA, signed by STM_RSA_05I.pem.
            {"cert": st_ecdsa_sha256_der, "expected": True},  # ECC, signed by STM_ECC_01I.pem.
        ]
        for t in tests:
            self.assertEqual(
                cert_utils.verify_ek(base64.b64decode(t["cert"]), CERT_STORE_DIR),
                t["expected"],
                msg=f"Test failed for cert {t['cert']}; expected: {t['expected']}",
            )

    @expectedFailureIf(has_strict_x509_parsing())
    def test_verify_ek_expected_failures(self):
        # The following certificates are not compliant, and will fail the
        # signature verification with python-cryptography, even though they
        # should validate. Marking as expected failure for now.
        tests = [
            {"cert": nuvoton_ecdsa_sha256_der, "expected": True},  # ECC, signed by NUVO_2110.pem.
        ]
        for t in tests:
            self.assertEqual(
                cert_utils.verify_ek(base64.b64decode(t["cert"]), CERT_STORE_DIR),
                t["expected"],
                msg=f"Test failed for cert {t['cert']}; expected: {t['expected']}",
            )

    def test_verify_ek_script(self):
        # We will be using `nuvoton_ecdsa_sha256_der', which is signed by
        # NUVO_2110.pem but fails verification when using python-cryptography
        # as it is a malformed cert -- it is the same one we use in
        # test_verify_ek_expected_failures().
        # With an external script `ek_script_check' that uses openssl, the
        # validation works.
        cert = nuvoton_ecdsa_sha256_der.replace("\n", "")

        self.assertFalse(cert_utils.verify_ek_script(None, None, None))
        self.assertFalse(cert_utils.verify_ek_script("/foo/bar", None, None))

        script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "ek-openssl-verify"))
        # Testing ek-openssl-verify script, but without specifying the
        # EK_CERT env var.
        self.assertFalse(cert_utils.verify_ek_script(script, None, None))

        # Now let's specify the EK_CERT.
        env = os.environ.copy()
        env["EK_CERT"] = cert
        env["TPM_CERT_STORE"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tpm_cert_store"))
        self.assertTrue(cert_utils.verify_ek_script(script, env, None))

        # Now, let us specify the ek_check_script with a relative path.
        script = "ek-openssl-verify"
        cwd = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
        self.assertTrue(cert_utils.verify_ek_script(script, env, cwd))

        # And now we try a bad TPM cert store.
        env["TPM_CERT_STORE"] = "/some/bad/directory"
        self.assertFalse(cert_utils.verify_ek_script(script, env, cwd))
