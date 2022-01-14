import tempfile
import unittest
from unittest.mock import patch

from keylime import secure_mount


class TestSecureMount(unittest.TestCase):
    def setUp(self):
        """Remove global state from secure_mount module."""
        # pylint: disable=protected-access
        secure_mount._MOUNTED = []

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_not_found(self, open_mock, _logger_mock):
        """Test when secdir is not mounted."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
        )
        self.assertFalse(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found(self, open_mock, _logger_mock):
        """Test when secdir is mounted."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime shared:130 - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
        )
        self.assertTrue(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_zero_optional_fields(self, open_mock, _logger_mock):
        """Test when secdir is mounted when there are no optional fields."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
        )
        self.assertTrue(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_extra_optional_fields(self, open_mock, _logger_mock):
        """Test when secdir is mounted when there are extra optional fields."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            "303 154 0:69 / /secdir rw,relatime shared:130 extra:1 - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
        )
        self.assertTrue(secure_mount.check_mounted("/secdir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_found_wrong_fs(self, open_mock, _logger_mock):
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
    def test_check_mounted_found_spaces(self, open_mock, _logger_mock):
        """Test when secdir is mounted and contains spaces."""
        open_mock.return_value = (
            "23 106 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw",
            r"303 154 0:69 / /sec\040dir rw,relatime shared:130 - tmpfs tmpfs rw,size=1024k,mode=700,inode64",
        )
        self.assertTrue(secure_mount.check_mounted("/sec dir"))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.open")
    def test_check_mounted_wrong_format(self, open_mock, _logger_mock):
        """Test when the mount info lines are wrong."""
        open_mock.return_value = ("invalid line",)
        with self.assertRaises(Exception) as e:
            secure_mount.check_mounted("/secdir")
        self.assertTrue("cannot be parsed" in str(e.exception))

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.config")
    def test_check_mount_no_secure(self, config_mock, _logger_mock):
        """Test when mounted outside tmpfs."""
        config_mock.MOUNT_SECURE = False

        with tempfile.TemporaryDirectory() as tmpdirname:
            config_mock.WORK_DIR = tmpdirname
            self.assertEqual(secure_mount.mount(), f"{tmpdirname}/tmpfs-dev")
            # pylint: disable=protected-access
            self.assertEqual(secure_mount._MOUNTED, [])

    @patch("keylime.secure_mount.check_mounted")
    @patch("keylime.secure_mount.config")
    def test_check_mount_secure_already_mounted(self, config_mock, check_mounted_mock):
        """Test when mounting in tmpfs but is already present."""
        config_mock.MOUNT_SECURE = True
        check_mounted_mock.return_value = True

        with tempfile.TemporaryDirectory() as tmpdirname:
            config_mock.WORK_DIR = tmpdirname
            self.assertEqual(secure_mount.mount(), f"{tmpdirname}/secure")
            # pylint: disable=protected-access
            self.assertEqual(secure_mount._MOUNTED, [])

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.check_mounted")
    @patch("keylime.secure_mount.config")
    @patch("keylime.secure_mount.os.path.exists")
    @patch("keylime.secure_mount.cmd_exec")
    def test_check_mount_secure_already_created(
        self, _cmd_exec_mock, exists_mock, config_mock, check_mounted_mock, _logger_mock
    ):
        """Test when mounting in tmpfs but the mount point is present."""
        exists_mock.return_value = True
        config_mock.MOUNT_SECURE = True
        check_mounted_mock.return_value = False

        with tempfile.TemporaryDirectory() as tmpdirname:
            config_mock.WORK_DIR = tmpdirname
            self.assertEqual(secure_mount.mount(), f"{tmpdirname}/secure")
            # pylint: disable=protected-access
            self.assertEqual(secure_mount._MOUNTED, [f"{tmpdirname}/secure"])

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.check_mounted")
    @patch("keylime.secure_mount.config")
    @patch("keylime.secure_mount.os.path.exists")
    @patch("keylime.secure_mount.os.makedirs")
    @patch("keylime.secure_mount.cmd_exec")
    def test_check_mount(
        self,
        _cmd_exec_mock,
        _makedirs_mock,
        exists_mock,
        config_mock,
        check_mounted_mock,
        _logger_mock,
    ):
        """Test when mounting in tmpfs but the mount point is not present."""
        exists_mock.return_value = False
        config_mock.MOUNT_SECURE = True
        check_mounted_mock.return_value = False

        with tempfile.TemporaryDirectory() as tmpdirname:
            config_mock.WORK_DIR = tmpdirname
            self.assertEqual(secure_mount.mount(), f"{tmpdirname}/secure")
            # pylint: disable=protected-access
            self.assertEqual(secure_mount._MOUNTED, [f"{tmpdirname}/secure"])

    def test_check_umount_empty(self):
        """Test umount when there are nothing to clean."""
        secure_mount.umount()
        # pylint: disable=protected-access
        self.assertEqual(secure_mount._MOUNTED, [])

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.check_mounted")
    @patch("keylime.secure_mount.cmd_exec")
    def test_check_umount_mount(self, cmd_exec_mock, check_mounted_mock, logger_mock):
        """Test umount for a single mount."""
        # pylint: disable=protected-access
        secure_mount._MOUNTED = ["/secdir"]
        check_mounted_mock.return_value = True
        cmd_exec_mock.run.return_value = {"code": 0}
        secure_mount.umount()
        self.assertEqual(secure_mount._MOUNTED, [])
        cmd_exec_mock.run.assert_called_once()
        logger_mock.error.assert_not_called()
        logger_mock.warning.assert_not_called()

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.check_mounted")
    @patch("keylime.secure_mount.cmd_exec")
    def test_check_umount_mount_busy(
        self, cmd_exec_mock, check_mounted_mock, logger_mock
    ):
        """Test umount for a single mount that fail."""
        # pylint: disable=protected-access
        secure_mount._MOUNTED = ["/secdir"]
        check_mounted_mock.return_value = True
        cmd_exec_mock.run.return_value = {"code": 1, "reterr": "Device busy"}
        secure_mount.umount()
        self.assertEqual(secure_mount._MOUNTED, [])
        cmd_exec_mock.run.assert_called_once()
        logger_mock.error.assert_called_once()
        logger_mock.warning.assert_not_called()

    @patch("keylime.secure_mount.logger")
    @patch("keylime.secure_mount.check_mounted")
    @patch("keylime.secure_mount.cmd_exec")
    def test_check_umount_umount(self, cmd_exec_mock, check_mounted_mock, logger_mock):
        """Test umount for a single umount and no creation."""
        # pylint: disable=protected-access
        secure_mount._MOUNTED = ["/secdir"]
        check_mounted_mock.return_value = False
        secure_mount.umount()
        self.assertEqual(secure_mount._MOUNTED, [])
        cmd_exec_mock.run.assert_not_called()
        logger_mock.error.assert_not_called()
        logger_mock.warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
