"""
SPDX-License-Identifier: Apache-2.0
Copyright 2022 Red Hat, Inc.
"""

import base64
import unittest

from keylime import cert_utils


class Cert_Utils_Test(unittest.TestCase):
    def test_read_x509_der_cert_pubkey(self):
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
        certs = [nuvoton_ecdsa_sha256_der, st_sha256_with_rsa_der]
        for c in certs:
            try:
                pubkey = cert_utils.read_x509_der_cert_pubkey(base64.b64decode(c))
            except Exception:
                self.fail("read_x509_der_cert_pubkey() is not expected to raise an exception here")
            self.assertIsNotNone(pubkey)
