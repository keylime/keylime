import os
import unittest

from keylime.common.algorithms import Hash
from keylime.mba import mba


class TestMBAParsing(unittest.TestCase):
    def test_parse_bootlog(self):
        """Test parsing binary measured boot event log"""
        mba.load_imports()
        # Use the file that triggered https://github.com/keylime/keylime/issues/1153
        mb_log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/mb_log.b64"))
        with open(mb_log_path, encoding="utf-8") as f:
            # Read the base64 input and remove the newlines
            b64 = "".join(f.read().splitlines())
            pcr_hashes, boot_aggregates, measurement_data, failure = mba.bootlog_parse(b64, Hash.SHA256)

            self.assertFalse(
                failure, f"Parsing of measured boot log failed with: {list(map(lambda x: x.context, failure.events))}"
            )
            self.assertTrue(isinstance(pcr_hashes, dict))
            self.assertTrue(isinstance(boot_aggregates, dict))
            self.assertTrue(isinstance(measurement_data, dict))


if __name__ == "__main__":
    unittest.main()
