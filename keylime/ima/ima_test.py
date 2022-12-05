import tempfile
import unittest

from keylime.ima import ima


class TestIMA(unittest.TestCase):
    def test_read_measurement_list(self) -> None:
        filedata = "0-entry\n1-entry\n2-entry\n"
        with tempfile.NamedTemporaryFile(delete=True) as tf:
            tf.write(filedata.encode("utf-8"))
            tf.flush()

            # Open file again to get str on read()
            with open(tf.name, "r", encoding="utf-8") as ima_log_file:

                # Request the 2nd entry, which is available
                ml, nth_entry, num_entries = ima.read_measurement_list(ima_log_file, 2)
                self.assertEqual(num_entries, 3)
                self.assertEqual(nth_entry, 2)
                self.assertIsNotNone(ml)
                assert ml is not None  # redundant but it makes type-checking happy
                self.assertTrue(ml.startswith("2-entry"))

                # Request the 3rd entry, which is not available yet, thus we get an empty list
                ml, nth_entry, num_entries = ima.read_measurement_list(ima_log_file, 3)
                self.assertEqual(num_entries, 3)
                self.assertEqual(nth_entry, 3)
                self.assertTrue(ml == "")

                # Request the 4th entry, which is beyond the next entry; since this is wrong,
                # we expect the entire list now.
                ml, nth_entry, num_entries = ima.read_measurement_list(ima_log_file, 4)
                self.assertEqual(num_entries, 3)
                self.assertEqual(nth_entry, 0)
                self.assertIsNotNone(ml)
                assert ml is not None  # redundant but it makes type-checking happy
                self.assertTrue(ml.startswith("0-entry"))


if __name__ == "__main__":
    unittest.main()
