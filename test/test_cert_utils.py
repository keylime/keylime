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

# These two certs are for testing the iak_idevid_cert_checks() function
# This is an IDevID cert with RSA PSS key that requires crypto >=38
idevid_der = """\
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
"""

iak_der = """\
MIIF9DCCA9ygAwIBAgICEAEwDQYJKoZIhvcNAQEMBQAwbjELMAkGA1UEBhMCR0IxEDAOBgNVBAgM
B0VuZ2xhbmQxEjAQBgNVBAoMCUlzYWFjIEhQRTEVMBMGA1UECwwMSXNhYWMgSFBFIENBMSIwIAYD
VQQDDBlJc2FhYyBIUEUgSW50ZXJtZWRpYXRlIENBMB4XDTIzMDgyMzEwMTczNFoXDTI2MDUxODEw
MTczNFowXzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxEjAQBgNVBAoMCUlzYWFjIEhQ
RTEVMBMGA1UECwwMSXNhYWMgSFBFIENBMRMwEQYDVQQDDApQMzg0NzEtQjIxMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlHJLX9n+kzqFRPeFEn7xMQSEbpsOQDg9mocQy172IE2aAhHy
KOAdcv/aOeGirPHnJZtXs9YbgnEpJWiNOzEJ0hb/mIJjLJhnfQkDXtG+bi/Zxlwwx1RFHkREY/4m
VPNihIlzGBrP/EX6HK3RYobEig/15oGq8vh1NR8JMVljx2LRUS05UIK6iidQnJFGnwRyslr440Sx
IWQtGDmVgLWxjd2ziWdxcwVdtZce3u0bAcQcFIUK0T21oelE2/5SgZ/KUIES6m/8AeZvfTux86Si
Mv7awEA52pT4Nos4LezAcnrDME6SdChpcKOvcbrP1GhPWmqTGU52EeltpjNh+r6ypQIDAQABo4IB
qTCCAaUwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwMwYJYIZIAYb4QgENBCYWJE9wZW5T
U0wgR2VuZXJhdGVkIFNlcnZlciBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUMYn/EfkIH/HTSUXgLssl
6IjQ0XkwgZEGA1UdIwSBiTCBhoAUmAAOKZfGn7MnFQAcB6s5Est2bsKhaqRoMGYxCzAJBgNVBAYT
AkdCMRAwDgYDVQQIDAdFbmdsYW5kMRIwEAYDVQQKDAlJc2FhYyBIUEUxFTATBgNVBAsMDElzYWFj
IEhQRSBDQTEaMBgGA1UEAwwRSXNhYWMgSFBFIFJvb3QgQ0GCAhAAMA4GA1UdDwEB/wQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDATB4BgNVHREEcTBvoG0GCCsGAQUFBwgEoGEwXwYFZ4EFAQIEVlNU
TSA6MUFEQjk5NEFCNThCRTU3QTBDQzlCOTAwRTc4NTFFMUE0M0MwODY2MDo0RDA3QkI1N0Q5RTNB
NjQ1RDc4MTkxRjEyRDFDNzhCQkJBMkMyMEFFMA0GCSqGSIb3DQEBDAUAA4ICAQAm/ipQETo/lyC6
y0McIqR3qZzLe7cSaZEXUiuav+k7Db/nvNeDbgPKhepThjBk/AMZgxGTuDEftVQOn3+wM4uUSwLX
jf4XlD9usaWqKqUilrt0QLFKOM+qKBM+j5EJGCLBkVxnmsEdhTa1vf5uHZVRKhmld885r1In3hIW
tXTW/cSrXyAeoDRy0qKV/tWSJGQbc/biHrq1YG1nAliIiVxHfX3S5QNw1jkdSCoL6Y0O7cr9DOwb
5tj+vpQrqpFpyUGNYrCwaiZ4vOKY4SY9+x5g6LiNa2dIVBe5ihM9FCnnzDYZBCRE8TygojWY6lju
GnwmbQAX6Az/EavrQ51kpTsgrizX8meJzPYxAj2YRj9IRjO78SP9LgUKb420AocVt5sRo4+EhI+t
PqQ2RWK38nMP3HcW9VMxiRNmlb9xkcsbXw1pFnX/dlI+YRZaWREU3fFI1CQjk3ebujjWTcp1X753
9EH6Bp5s+qE14JYsV5WqQsshTmHTfdQkV9QOweArjlLeL1MlL/S6cuE4Pc5giUoqFj11n6S/H9Te
wZSAsdm+F02pUnR2yf0ge83mFbOfFvVH6qTiBAfu5cmcinUYuxrGCpe8viOyJ2IkKSzNGvl7CZRo
Ap5d9wr462Gq3kzXcIW3K6kUJDcboy267Ndl6pcC0Rng/z/p1WdibbcSXfkhVw==
"""


def has_strict_x509_parsing():
    """Indicates whether python-cryptography has strict x509 parsing."""

    # Major release where python-cryptography started being strict
    # when parsing x509 certificates.
    PYCRYPTO_STRICT_X509_MAJOR = 35
    return int(cryptography.__version__.split(".", maxsplit=1)[0]) >= PYCRYPTO_STRICT_X509_MAJOR


def has_rsa_pss_compatibility():
    """Indicates whether python-cryptography can process RSASSA-PSS. If this test fails IAK and IDevID will not be used to register unless cryptography is updated."""

    # Major release where python-cryptography could process RSA PSS
    PYCRYPTO_PSS_X509_MAJOR = 38
    return int(cryptography.__version__.split(".", maxsplit=1)[0]) >= PYCRYPTO_PSS_X509_MAJOR


def expectedFailureIf(condition):
    """The test is marked as an expectedFailure if the condition is satisfied."""

    def wrapper(func):
        if condition:
            return unittest.expectedFailure(func)
        return func

    return wrapper


class Cert_Utils_Test(unittest.TestCase):
    def test_tpm_cert_store(self):
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

    @unittest.skipUnless(
        has_rsa_pss_compatibility(), "Cryptography earlier than v38.0.0 does not support RSAPSS from x509"
    )
    def test_iak_idevid_cert_checks(self):
        # This test is expected to fail with python cryptography version earlier than 38
        # Test for the iak_idevid_cert checks, which checks the public key type in the certs,
        # verifies the certs, and checks they are from a TPM
        # Check that we fail agianst the current cert store
        error, _, _ = cert_utils.iak_idevid_cert_checks(
            base64.b64decode(idevid_der), base64.b64decode(iak_der), CERT_STORE_DIR
        )
        self.assertTrue(error == "Error: IDevID certificate could not be verified")

        # Check that we succeed against the test cert store
        TEST_CERT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test-data/files/idevid-test-ca"))
        error, _, _ = cert_utils.iak_idevid_cert_checks(
            base64.b64decode(idevid_der), base64.b64decode(iak_der), TEST_CERT_DIR
        )
        self.assertTrue(error == "")

    def test_is_x509_cert(self):
        test_cases = [
            {
                "data": b"",
                "valid": False,
            },
            {
                "data": base64.b64decode(
                    """MIIDyDCCArCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJVUzEm
MCQGA1UEAwwdS2V5bGltZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxCzAJBgNVBAgM
Ak1BMRIwEAYDVQQHDAlMZXhpbmd0b24xDjAMBgNVBAoMBU1JVExMMQswCQYDVQQL
DAI1MzAeFw0yNDA2MjIxMjAxMDFaFw0zNDA2MjAxMjAxMDFaMHMxCzAJBgNVBAYT
AlVTMSYwJAYDVQQDDB1LZXlsaW1lIENlcnRpZmljYXRlIEF1dGhvcml0eTELMAkG
A1UECAwCTUExEjAQBgNVBAcMCUxleGluZ3RvbjEOMAwGA1UECgwFTUlUTEwxCzAJ
BgNVBAsMAjUzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgO1/Evq
wn0bJwu3aQ9mhgZ8rA6mGx7IFTCncJx1pFg4WIviFBoFydJhvvdxWw5eavXUNoXK
/EjTEX8RRV/nw/JF2b8Cq2Ypn/Apzjx7TSUFS17A/CidR/+nDEiqfm1OIgzFkG0L
eXLKn3MbkWmyM1LkamizbzM4PSfDpPJyQ+QNWZfaSebLP+a41HFWVyxMYAGnOxlv
uIjjG32uB+2l2lwiHVq5WPzeQyIlF5I/k4rE2EyLaLyQvyzVkMuM/HVfsWw/WhYJ
DM3Z9ZLpL9kEi/d/ytI21jlXkNJFyrh3xudhi9yrvYkRLj90UtCcEXXxsivq5G32
T7via4I0yfkaZwIDAQABo2cwZTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBRd6bco
tMXw+7u2Jed12DefJa/TtDApBgNVHR8EIjAgMB6gHKAahhhodHRwOi8vbG9jYWxo
b3N0L2NybC5wZW0wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAAnRAU
ZujKyl76ZQHE5sbA2oc7Gl13Ki9rj8SjkpkLr0kufaf3fEr89Mk6DDelyqb3YYd3
Is8m8OKPhtA1CBQKph/FYPTV0PUozp7/Tn0qDxRDGVO819Dxe99mwwOh0d0LhH6A
ZWhPWPde+NevjfO3AMQs6F0FrxyJlqV46Gc1ipCLrP6N3nujpIIfu+UJMQ4kiYGT
hlXUEWpfno1blCRGDzyYL86rthQN6ZD+Zj9L2YrfsA2P0sdxFAIBI3KQ5TMVCP/t
LApSvvVeV19fEod6DUYTYBuGkQAD1b88q8/J9NDeSWgfEB6UWEDY0vygHiiRF7iw
VMuvlCzEwd8V/FIw"""
                ),
                "valid": True,
            },
            {
                "data": base64.b64decode(st_sha256_with_rsa_der),
                "valid": True,
            },
            {
                "data": f"-----BEGIN CERTIFICATE-----\n{st_sha256_with_rsa_der}\n-----END CERTIFICATE-----".encode(
                    "UTF-8"
                ),
                "valid": True,
            },
            {
                "data": b"foobar",
                "valid": False,
            },
        ]

        for index, c in enumerate(test_cases):
            self.assertEqual(cert_utils.is_x509_cert(c["data"]), c["valid"], msg=f"index is {index}")
