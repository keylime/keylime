import unittest
from unittest.mock import patch

from keylime import secure_mount


class TestSecureMount(unittest.TestCase):

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_not_found(self, open_mock, logger_mock):
        """Test when secdir is not mounted."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            )
        self.assertFalse(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found(self, open_mock, logger_mock):
        """Test when secdir is mounted."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime shared:130 - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
            )
        self.assertTrue(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_zero_optional_fields(self, open_mock, logger_mock):
        """Test when secdir is mounted when there are no optional fields."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
        )
        self.assertTrue(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_extra_optional_fields(self, open_mock, logger_mock):
        """Test when secdir is mounted when there are extra optional fields."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime shared:130 extra:1 - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
        )
        self.assertTrue(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_wrong_fs(self, open_mock, logger_mock):
        """Test when secdir is mounted but under a wrong fs."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime shared:130 - btrfs /dev/sda2 rw",
            )
        with self.assertRaises(Exception) as e:
            secure_mount.check_mounted("/secdir")
        self.assertTrue("wrong file system" in str(e.exception))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_spaces(self, open_mock, logger_mock):
        """Test when secdir is mounted and contains spaces."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            r"303 154 0:69 / /sec\040dir rw,relatime shared:130 - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
            )
        self.assertTrue(secure_mount.check_mounted("/sec dir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_wrong_format(self, open_mock, logger_mock):
        """Test when the mount info lines are wrong."""
        open_mock.return_value = ("invalid line",)
        with self.assertRaises(Exception) as e:
            secure_mount.check_mounted("/secdir")
        self.assertTrue("cannot be parsed" in str(e.exception))


if __name__ == "__main__":
    unittest.main()
