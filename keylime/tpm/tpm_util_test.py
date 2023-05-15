import base64
import unittest
from unittest import mock

from keylime.tpm.tpm_util import checkquote, makecredential


class TestTpmUtil(unittest.TestCase):
    def test_checkquote(self) -> None:
        aikblob = bytes(
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw3owm7uitOaspMCDlhEv\n"
            "bxNgGsxa1MpbHytT/Y9K0sdpTxgay571B8zvLOUbJHEJ0gt4NHY0+/NCzIAzT6kB\n"
            "n7aL67BV8QiyKBcywlVGS9PqYGoB9uxozDap/O9Bc5WrQUCso4m4TxrW1QOOBkNX\n"
            "x5OnresvsRv5O3m6BYZeUk2pJOyiBXM0HEkEC/Q/hxsfF1KfJG3JYOhpdF0E//dy\n"
            "LHOtdW9FP8Dt3YZuchJmyhFDjMKuxF2Zt7YVk9Pg4ZvmJ64CmOtshUj9k+Ctj44Z\n"
            "gMS/cIVmMrk7cdUBEBtq8x3g0cARZ5cUb4KB+dO0v/fvZkb4Qt5zwym1eUzmvVfD\n"
            "6QIDAQAB\n"
            "-----END PUBLIC KEY-----",
            "utf-8",
        )
        sigblob = base64.b64decode(
            "ABQACwEAgkUGLLuWpJETl3E5G2mvoVqbgVxzwAluOtyUwkoZEC2j4DeqOrl/q7jLaAC2KxDcoJbk"
            "QPqu2sgwV84lfZOqRNhCydiwxbBTPIXImoDsCnkpkYwrk9NJcM+18qm/+f5V2/8QBQQmbN+6EV3I"
            "gpSOYor2XcVntHCIrcloh/qN2gjihXDSjtHH9aSwOH7Z69gzyTt/4yVul7QRAOQCjqnasaSEGvoA"
            "vtIin0aJLfD9wo1wlRzRDU62t3oHKLY49tMA3hQYF15+If/NsTKCTmUKmiKLBTk3yWAE64ThCxpB"
            "EED6peiJlSxhdkyRm632IWAt8ahuyrfi/iEDVfyV+LnTBw=="
        )
        quoteblob = base64.b64decode(
            "/1RDR4AYACIACzi1x2WoenP+buZXpt2LdpW0GTj5lBE6PXQmPZ0upQM0ABRBaTVNNVNqWWpua3l2"
            "NFA3aXRIMQAAAABMlE7mAAAAAwAAAAABIBkQIwAWNjYAAAABAAsDAAABACBtTTdJEy9iVxchZM1f"
            "8xNfRHlz1KXITgGJAfZ1NwW3AQ=="
        )
        pcrblob = base64.b64decode(
            "AQAAAAsAAwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAgANRxwGdJUfDvB1rs3UL776bspgGYIK3QvSItHE5i"
            "Qs5vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        )
        nonce = "Ai5M5SjYjnkyv4P7itH1"

        try:
            checkquote(aikblob, nonce, sigblob, quoteblob, pcrblob, "sha256")
        except Exception as e:
            self.fail(f"checkquote failed with {e}")

    @staticmethod
    def not_random(numbytes: int) -> bytes:
        return b"\x12" * numbytes

    def test_makecredential(self) -> None:
        with mock.patch("os.urandom", TestTpmUtil.not_random):
            ek_tpm = bytes.fromhex(
                "013a0001000b000300b20020837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1"
                "da1b331469aa00060080004300100800000000000100aef12278a9b8d8a1e5700fb835ff3d9b"
                "613d0d6fc17df186711260244f3f24847eb3ef1f5ff9b53d01cfebf291104385fbd71ead80a8"
                "294ebc76f671859b7c3c9a998300f30859ef3fdba00c5229f17092fd97f19128243000205cfe"
                "5ba24f5fc55538e52bf849c6f777690919929c7d2d9328070a2a6bdd67355a516b94afdceda0"
                "0a0d27988a28644b30ac11beae23a51d9038cd9d789ae39cae15c1312ef174e217449771a602"
                "ade4daf35b20e072017c85a2f211fe5512319184059ddeaab94fa331c49c3f213bc3fbccd1e8"
                "56b8984353ac92e3df0f72f1e5c0b97b9cdc333702872e9e63565c809d81fa8bb6c6da86867c"
                "ead2adedc0cee80bb6617183"
            )
            challenge = bytes.fromhex("5a4e524b4f4e6e777552754831683734785a466a42416f314758676c484d4149")
            aik_name = bytes.fromhex("000b9601163463aacdb45be7ad1f6d11ad3dae0578d5aeeb5125e1075c5601b7c7fa")

            credential = makecredential(ek_tpm, challenge, aik_name)

            # the signature is not 'constant' due to OAEP padding
            self.assertEqual(
                credential[:80],
                bytes.fromhex(
                    "badcc0de00000001004400206f0c4b08cfa00f21b474ca75623d098309c2cd7fac8d10"
                    "ae3caf0da40162496db140cc6a5ae79a2bd7c22dc52cee372f34b356bf9bcd5176fa94"
                    "239ee93191a0a75d0100"
                ),
            )
