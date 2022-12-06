import base64
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import load_der_x509_certificate

from keylime.tpm.tpm2_objects import (
    OA_ADMINWITHPOLICY,
    OA_DECRYPT,
    OA_ENCRYPTEDDUPLICATION,
    OA_FIXEDPARENT,
    OA_FIXEDTPM,
    OA_NODA,
    OA_RESTRICTED,
    OA_SENSITIVEDATAORIGIN,
    OA_SIGN_ENCRYPT,
    OA_STCLEAR,
    OA_USERWITHAUTH,
    ek_low_tpm2b_public_from_pubkey,
    get_tpm2b_public_name,
    get_tpm2b_public_object_attributes,
    object_attributes_description,
    pubkey_from_tpm2b_public,
)


class TestTpm2Objects(unittest.TestCase):
    def test_get_tpm2b_public_name(self) -> None:
        test_pub = base64.b64decode(
            "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDJBIF+SxeEt8TAwcnMZIvJWs3luBARcI"
            "HXC7I/XH7ZXbwLyispm/tpvhRw0w60JbwF4om1LbApQbG9cWR7AOi3ykv5bOgszsIG"
            "DOYJNfWuylW2uQBvMPEeF+ysrCjFTl5HOhXEpaz+E//juoKS2Jh9zYr2kt8rnGAJyj"
            "a10LUsYNt4h6eyeLVrsZIckkKP4tZwPOokfdX+6YCtGy5Y1buTvBSGNWa+VGo6hZVD"
            "649mg6EHyv0geSHXojx0Iqjsl/NQXzOCvyuaf6CBu9pkiIZCePlrl2uD1tXEdX0ipB"
            "B9Fppc/5cJQ2NyJOuvi4MUK5y38QpwnZwd4Utr2WdyEPoF"
        )
        test_pub_correct_name = "000b347dbfebe5bdbc55f6782a3cba91610f9d1b554a1aef07b4db28cf36da939009"
        new_name = get_tpm2b_public_name(test_pub)
        self.assertEqual(new_name, test_pub_correct_name)

    def test_get_tpm2b_public_object_attributes(self) -> None:
        test_pub = base64.b64decode(
            "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDJBIF+SxeEt8TAwcnMZIvJWs3luBARcI"
            "HXC7I/XH7ZXbwLyispm/tpvhRw0w60JbwF4om1LbApQbG9cWR7AOi3ykv5bOgszsIG"
            "DOYJNfWuylW2uQBvMPEeF+ysrCjFTl5HOhXEpaz+E//juoKS2Jh9zYr2kt8rnGAJyj"
            "a10LUsYNt4h6eyeLVrsZIckkKP4tZwPOokfdX+6YCtGy5Y1buTvBSGNWa+VGo6hZVD"
            "649mg6EHyv0geSHXojx0Iqjsl/NQXzOCvyuaf6CBu9pkiIZCePlrl2uD1tXEdX0ipB"
            "B9Fppc/5cJQ2NyJOuvi4MUK5y38QpwnZwd4Utr2WdyEPoF"
        )
        expected_attributes = (
            OA_RESTRICTED | OA_USERWITHAUTH | OA_SIGN_ENCRYPT | OA_FIXEDTPM | OA_FIXEDPARENT | OA_SENSITIVEDATAORIGIN
        )
        new_attributes = get_tpm2b_public_object_attributes(test_pub)
        self.assertEqual(new_attributes, expected_attributes)

    # Testing tpm2b_public_from_pubkey
    # These example certificates were standard EK certificates from a valid TPM,
    #  so these fields are selected according to
    #  TCG EK Credential Profile For TPM Family 2.0
    #  Level 0, Version 2.3, Revision 2"
    # Both are from the Low Ranges
    # The RSA set is according to Template L-1, section B.3.3
    # The EC set is according to Template L-2, section B.3.4

    def test_tpm2b_public_from_pubkey_rsa(self) -> None:
        test_rsa_cert_bytes = base64.b64decode(
            "MIIEnDCCA4SgAwIBAgIEL8wtHjANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCRE"
            "UxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BU"
            "SUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE"
            "1hbnVmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkzM1oXDTMzMDMwMTE0MTkz"
            "M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALaIriXJCSUKdvWRDY"
            "dRbtdTK8i7eCJwHV8NhQ8Cor8NKoVmrnOdDhGqXlrKyJTueA9D2P4yQlWZI+tD9PCV"
            "CHCQiGmqxxHQXgzCzx6z+57HTUNPDi16K6ZFPNs3UkhAQxeGLOy36XD35zpfgadtvc"
            "lxJC8L+UgKfXVAM3/oMj4cDXa4cbVKhlfIQXD9OhcNjvESPWVFw0dj7Q6HM0jEkezM"
            "ew5sJ3I+LET1cIIhUlXvX8fWLu2MHx9+6LIBjkN8SuMLjKBQZjh+rEbHoFuG7Ib9pN"
            "ucrPAycid4EBBQB65j9irZ8C+ZdUUkKM5hsDhcenm/0AdfqAGXsFtsEa8DuDECAwEA"
            "AaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS"
            "5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMzUvT3B0aWdhUnNhTWZyQ0EwMzUu"
            "Y3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDA"
            "tpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUC"
            "AwwHaWQ6MDczZjAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly"
            "9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDM1L09wdGlnYVJzYU1mckNB"
            "MDM1LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFM53FTtuEQ"
            "ykrilxoJhR70mTJiAqMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EF"
            "AhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAIJ7pvW3yj2wAHO1fq"
            "zOeKg/xQjBMZ2hdpqVmhc+gU7F7zCMF85iWodISkThp9aa6p7VptkNcp5BNE1ojx+3"
            "1aJZRAFTCV0b0QxKXELTVsQLvBVmKGtFuaP3FPDVJYIOnQtb8uF+2LduF5P9K6oXdF"
            "TFuh1kG8GU/UUnltA7h6u2qhnj5uvFEDz7pxX1lt/GbI1nTYB+0SYtveIglpFyZK71"
            "0FH9UAvvR8byEbK+adE+teBUOexdXhTC1ZmPZmTvHSqmeRV3UTZFZRnyOTBnN8QlN0"
            "pMVmwFTak931PqxV0xOSXkMcvTre39jzkhEJ+VMb5EOMFfsVn+b4snob9jank="
        )
        correct_rsa_obj = base64.b64decode(
            "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAgAAAAAAAEAtoiuJckJJQp29ZENh1Fu11MryLt4InAdXw2FDwKivw0qhWauc50O"
            "EapeWsrIlO54D0PY/jJCVZkj60P08JUIcJCIaarHEdBeDMLPHrP7nsdNQ08OLXorpk"
            "U82zdSSEBDF4Ys7LfpcPfnOl+Bp229yXEkLwv5SAp9dUAzf+gyPhwNdrhxtUqGV8hB"
            "cP06Fw2O8RI9ZUXDR2PtDoczSMSR7Mx7Dmwncj4sRPVwgiFSVe9fx9Yu7YwfH37osg"
            "GOQ3xK4wuMoFBmOH6sRsegW4bshv2k25ys8DJyJ3gQEFAHrmP2KtnwL5l1RSQozmGw"
            "OFx6eb/QB1+oAZewW2wRrwO4MQ=="
        )
        test_rsa_cert = load_der_x509_certificate(test_rsa_cert_bytes, backend=default_backend())
        test_rsa_pubkey = test_rsa_cert.public_key()
        assert isinstance(test_rsa_pubkey, rsa.RSAPublicKey)
        new_rsa_obj = ek_low_tpm2b_public_from_pubkey(test_rsa_pubkey)
        self.assertEqual(new_rsa_obj.hex(), correct_rsa_obj.hex())

    def test_tpm2b_public_from_pubkey_ec(self) -> None:
        test_ec_cert_bytes = base64.b64decode(
            "MIIDEDCCAragAwIBAgIEcYSJiTAKBggqhkjOPQQDAjCBgzELMAkGA1UEBhMCREUxIT"
            "AfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdB"
            "KFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgRUNDIE1hbn"
            "VmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkxNloXDTMzMDMwMTE0MTkxNlow"
            "ADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNK9AtBnW5bwNG2ZIWDrM8w/h03Ht2"
            "lp3MUosV05DeBHWZEZfmKsHMBqpqDsIKkEgclQawA4BFR5YUvSdrSUDTGjggGYMIIB"
            "lDBbBggrBgEFBQcBAQRPME0wSwYIKwYBBQUHMAKGP2h0dHA6Ly9wa2kuaW5maW5lb2"
            "4uY29tL09wdGlnYUVjY01mckNBMDM1L09wdGlnYUVjY01mckNBMDM1LmNydDAOBgNV"
            "HQ8BAf8EBAMCAAgwWAYDVR0RAQH/BE4wTKRKMEgxFjAUBgVngQUCAQwLaWQ6NDk0Nj"
            "U4MDAxGjAYBgVngQUCAgwPU0xCIDk2NzAgVFBNMi4wMRIwEAYFZ4EFAgMMB2lkOjA3"
            "M2YwDAYDVR0TAQH/BAIwADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vcGtpLmluZm"
            "luZW9uLmNvbS9PcHRpZ2FFY2NNZnJDQTAzNS9PcHRpZ2FFY2NNZnJDQTAzNS5jcmww"
            "FQYDVR0gBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBQ2WY8i7ITDxPZA0hwWfQ"
            "uRE3uQpDAQBgNVHSUECTAHBgVngQUIATAhBgNVHQkEGjAYMBYGBWeBBQIQMQ0wCwwD"
            "Mi4wAgEAAgF0MAoGCCqGSM49BAMCA0gAMEUCIQCdCv3+G+KsM4OiT3SgKqvE8r5ktD"
            "I5elC9xTmS9mDA3AIgcckalMvQVTst1pGMEyAI+OoXTnYA1sBRm27WJ6sZag8="
        )
        correct_ec_obj = base64.b64decode(
            "AHoAIwALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAADABAAINK9AtBnW5bwNG2ZIWDrM8w/h03Ht2lp3MUosV05DeBHACBZkRl+Yqwc"
            "wGqmoOwgqQSByVBrADgEVHlhS9J2tJQNMQ=="
        )
        test_ec_cert = load_der_x509_certificate(test_ec_cert_bytes, backend=default_backend())
        test_ec_pubkey = test_ec_cert.public_key()
        assert isinstance(test_ec_pubkey, ec.EllipticCurvePublicKey)
        new_ec_obj = ek_low_tpm2b_public_from_pubkey(test_ec_pubkey)
        self.assertEqual(new_ec_obj.hex(), correct_ec_obj.hex())

    def test_pubkey_from_tpm2b_public_rsa(self) -> None:
        test_rsa_cert_bytes = base64.b64decode(
            "MIIEnDCCA4SgAwIBAgIEL8wtHjANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCRE"
            "UxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BU"
            "SUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE"
            "1hbnVmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkzM1oXDTMzMDMwMTE0MTkz"
            "M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALaIriXJCSUKdvWRDY"
            "dRbtdTK8i7eCJwHV8NhQ8Cor8NKoVmrnOdDhGqXlrKyJTueA9D2P4yQlWZI+tD9PCV"
            "CHCQiGmqxxHQXgzCzx6z+57HTUNPDi16K6ZFPNs3UkhAQxeGLOy36XD35zpfgadtvc"
            "lxJC8L+UgKfXVAM3/oMj4cDXa4cbVKhlfIQXD9OhcNjvESPWVFw0dj7Q6HM0jEkezM"
            "ew5sJ3I+LET1cIIhUlXvX8fWLu2MHx9+6LIBjkN8SuMLjKBQZjh+rEbHoFuG7Ib9pN"
            "ucrPAycid4EBBQB65j9irZ8C+ZdUUkKM5hsDhcenm/0AdfqAGXsFtsEa8DuDECAwEA"
            "AaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS"
            "5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMzUvT3B0aWdhUnNhTWZyQ0EwMzUu"
            "Y3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDA"
            "tpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUC"
            "AwwHaWQ6MDczZjAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly"
            "9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDM1L09wdGlnYVJzYU1mckNB"
            "MDM1LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFM53FTtuEQ"
            "ykrilxoJhR70mTJiAqMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EF"
            "AhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAIJ7pvW3yj2wAHO1fq"
            "zOeKg/xQjBMZ2hdpqVmhc+gU7F7zCMF85iWodISkThp9aa6p7VptkNcp5BNE1ojx+3"
            "1aJZRAFTCV0b0QxKXELTVsQLvBVmKGtFuaP3FPDVJYIOnQtb8uF+2LduF5P9K6oXdF"
            "TFuh1kG8GU/UUnltA7h6u2qhnj5uvFEDz7pxX1lt/GbI1nTYB+0SYtveIglpFyZK71"
            "0FH9UAvvR8byEbK+adE+teBUOexdXhTC1ZmPZmTvHSqmeRV3UTZFZRnyOTBnN8QlN0"
            "pMVmwFTak931PqxV0xOSXkMcvTre39jzkhEJ+VMb5EOMFfsVn+b4snob9jank="
        )
        test_rsa_cert = load_der_x509_certificate(test_rsa_cert_bytes, backend=default_backend())
        correct_rsa_obj = base64.b64decode(
            "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAgAAAAAAAEAtoiuJckJJQp29ZENh1Fu11MryLt4InAdXw2FDwKivw0qhWauc50O"
            "EapeWsrIlO54D0PY/jJCVZkj60P08JUIcJCIaarHEdBeDMLPHrP7nsdNQ08OLXorpk"
            "U82zdSSEBDF4Ys7LfpcPfnOl+Bp229yXEkLwv5SAp9dUAzf+gyPhwNdrhxtUqGV8hB"
            "cP06Fw2O8RI9ZUXDR2PtDoczSMSR7Mx7Dmwncj4sRPVwgiFSVe9fx9Yu7YwfH37osg"
            "GOQ3xK4wuMoFBmOH6sRsegW4bshv2k25ys8DJyJ3gQEFAHrmP2KtnwL5l1RSQozmGw"
            "OFx6eb/QB1+oAZewW2wRrwO4MQ=="
        )
        new_rsa_pubkey = pubkey_from_tpm2b_public(correct_rsa_obj)
        assert isinstance(new_rsa_pubkey, rsa.RSAPublicKey)
        correct_rsa_pubkey = test_rsa_cert.public_key()
        assert isinstance(correct_rsa_pubkey, rsa.RSAPublicKey)
        new_rsa_pubkey_n = new_rsa_pubkey.public_numbers()
        correct_rsa_pubkey_n = correct_rsa_pubkey.public_numbers()
        self.assertEqual(new_rsa_pubkey.key_size, correct_rsa_pubkey.key_size)
        self.assertEqual(new_rsa_pubkey_n.e, correct_rsa_pubkey_n.e)  # pylint: disable=no-member
        self.assertEqual(new_rsa_pubkey_n.n, correct_rsa_pubkey_n.n)  # pylint: disable=no-member

    def test_pubkey_from_tpm2b_public_rsa_without_encryption(self) -> None:
        new_rsa_pubkey = pubkey_from_tpm2b_public(
            bytes.fromhex(
                "01180001000b00050072000000100014000b0800000000000100cac43903c6"
                "16bba049ce413c961c901b56181392c7999e672e6e5ecdd7a625d4702c3d78"
                "deac81e1372b0ca1894ac0f16add636bb53d3d5b112d8f3b169ccadef6bac0"
                "d909067d1ff81dae34b26cd538a52fa20ee7bbf3b16214417d35bde80cbb0f"
                "1b3267fd6211ecfb652f771f7eaeff560b91ef2f374ab1d37bba5a7a1c7cd4"
                "4961cdd7351ee060947f43244f45fc42ea6a1ea783aaa18dc8cce90d9a97f8"
                "da09e72637a0167fdbf4cc0d09f2f752d864d45bd34ed387acc0bcddca26c6"
                "1ebe9056013a35cd1d8011336af93579afa424fe50fd7e2b03270518505710"
                "82fcae891e2897e3117fd28bd03d2d2ffdfcfa0ff95f76af9383e3c9e59fe4"
                "dde753"
            )
        )
        assert isinstance(new_rsa_pubkey, rsa.RSAPublicKey)
        new_rsa_pubkey_n = new_rsa_pubkey.public_numbers()

        self.assertEqual(new_rsa_pubkey.key_size, 2048)
        self.assertEqual(new_rsa_pubkey_n.e, 65537)  # pylint: disable=no-member
        self.assertEqual(
            str(new_rsa_pubkey_n.n),  # pylint: disable=no-member
            "255968986296679270326283402717529063492526907681140893873754141432"
            "890531031973586937300971300465026177966018575012122367284728088154"
            "485873651193407172159946655006581809152369460009001515677703036255"
            "837234635576083087037905135410736640524495731191518154258439490758"
            "531740360767515943902821573272461751306668217217601399605319344343"
            "524504419559281243744525835687758392857402638332592577865592671234"
            "679107983328133731582503713366603521336278457142403979969779706740"
            "010077961630324526931687863526905140593203113247551679416434551326"
            "587069716966112452602019925398408142602185862884082705845069125895"
            "71106286823536420841299",
        )

    def test_pubkey_from_tpm2b_public_ec(self) -> None:
        test_ec_cert_bytes = base64.b64decode(
            "MIIDEDCCAragAwIBAgIEcYSJiTAKBggqhkjOPQQDAjCBgzELMAkGA1UEBhMCREUxIT"
            "AfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdB"
            "KFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgRUNDIE1hbn"
            "VmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkxNloXDTMzMDMwMTE0MTkxNlow"
            "ADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNK9AtBnW5bwNG2ZIWDrM8w/h03Ht2"
            "lp3MUosV05DeBHWZEZfmKsHMBqpqDsIKkEgclQawA4BFR5YUvSdrSUDTGjggGYMIIB"
            "lDBbBggrBgEFBQcBAQRPME0wSwYIKwYBBQUHMAKGP2h0dHA6Ly9wa2kuaW5maW5lb2"
            "4uY29tL09wdGlnYUVjY01mckNBMDM1L09wdGlnYUVjY01mckNBMDM1LmNydDAOBgNV"
            "HQ8BAf8EBAMCAAgwWAYDVR0RAQH/BE4wTKRKMEgxFjAUBgVngQUCAQwLaWQ6NDk0Nj"
            "U4MDAxGjAYBgVngQUCAgwPU0xCIDk2NzAgVFBNMi4wMRIwEAYFZ4EFAgMMB2lkOjA3"
            "M2YwDAYDVR0TAQH/BAIwADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vcGtpLmluZm"
            "luZW9uLmNvbS9PcHRpZ2FFY2NNZnJDQTAzNS9PcHRpZ2FFY2NNZnJDQTAzNS5jcmww"
            "FQYDVR0gBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBQ2WY8i7ITDxPZA0hwWfQ"
            "uRE3uQpDAQBgNVHSUECTAHBgVngQUIATAhBgNVHQkEGjAYMBYGBWeBBQIQMQ0wCwwD"
            "Mi4wAgEAAgF0MAoGCCqGSM49BAMCA0gAMEUCIQCdCv3+G+KsM4OiT3SgKqvE8r5ktD"
            "I5elC9xTmS9mDA3AIgcckalMvQVTst1pGMEyAI+OoXTnYA1sBRm27WJ6sZag8="
        )
        correct_ec_obj = base64.b64decode(
            "AHoAIwALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAADABAAINK9AtBnW5bwNG2ZIWDrM8w/h03Ht2lp3MUosV05DeBHACBZkRl+Yqwc"
            "wGqmoOwgqQSByVBrADgEVHlhS9J2tJQNMQ=="
        )
        test_ec_cert = load_der_x509_certificate(test_ec_cert_bytes, backend=default_backend())
        new_ec_pubkey = pubkey_from_tpm2b_public(correct_ec_obj)
        assert isinstance(new_ec_pubkey, ec.EllipticCurvePublicKey)

        correct_ec_pubkey = test_ec_cert.public_key()
        assert isinstance(correct_ec_pubkey, ec.EllipticCurvePublicKey)
        new_ec_pubkey_n = new_ec_pubkey.public_numbers()
        correct_ec_pubkey_n = correct_ec_pubkey.public_numbers()
        self.assertEqual(new_ec_pubkey_n.curve.name, correct_ec_pubkey_n.curve.name)
        self.assertEqual(new_ec_pubkey_n.x, correct_ec_pubkey_n.x)
        self.assertEqual(new_ec_pubkey_n.y, correct_ec_pubkey_n.y)

    def test_pubkey_from_tpm2b_public_ec_without_encryption(self) -> None:
        new_ec_pubkey = pubkey_from_tpm2b_public(
            bytes.fromhex(
                "00580023000b00050072000000100018000b000300100020c74568135840f4"
                "97ad575ebeabe6d01f3f098b5a768111ab423d5f26b259a4f000205ec0f586"
                "b53e348bc916b43a015e6ceefd947d685e59ff65357499f2c4788cba"
            )
        )
        assert isinstance(new_ec_pubkey, ec.EllipticCurvePublicKey)
        new_ec_pubkey_n = new_ec_pubkey.public_numbers()

        self.assertEqual(new_ec_pubkey_n.curve.name, "secp256r1")
        self.assertEqual(
            str(new_ec_pubkey_n.x),
            "90132887618692975484254453731651094410483286444689191401164175504334705501424",
        )
        self.assertEqual(
            str(new_ec_pubkey_n.y),
            "42858336962839421935559570622369777529185491150475599613778789950332157332666",
        )

    def test_object_attributes_description(self) -> None:
        with self.subTest(attrs="sign-encrypt"):
            val = object_attributes_description((OA_SIGN_ENCRYPT))
            self.assertEqual(val, "sign-encrypt")

        with self.subTest(attrs="<empty>"):
            val = object_attributes_description((0))
            self.assertEqual(val, "")

        with self.subTest(attrs="<all>"):
            val = object_attributes_description(
                (
                    OA_FIXEDTPM
                    | OA_STCLEAR
                    | OA_FIXEDPARENT
                    | OA_SENSITIVEDATAORIGIN
                    | OA_USERWITHAUTH
                    | OA_ADMINWITHPOLICY
                    | OA_NODA
                    | OA_ENCRYPTEDDUPLICATION
                    | OA_RESTRICTED
                    | OA_DECRYPT
                    | OA_SIGN_ENCRYPT
                )
            )
            self.assertEqual(
                val,
                "fixed-tpm | st-clear | fixed-parent | sensitive-data-origin | "
                "user-with-auth | admin-with-policy | no-da | "
                "encrypted-duplication | restricted | decrypt | sign-encrypt",
            )


if __name__ == "__main__":
    unittest.main()
