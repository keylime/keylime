import unittest
from unittest.mock import patch

from keylime import fs_util


class TestChDir(unittest.TestCase):
    @patch("keylime.fs_util.os.path.exists")
    @patch("keylime.fs_util.os.makedirs")
    @patch("keylime.fs_util.os.chdir")
    # "no-self-use" warning has been reassigned from R0201 to R6301:
    # https://pylint.pycqa.org/en/latest/user_guide/messages/refactor/old-no-self-use.html
    # pylint: disable-next=R
    def test_ch_dir_present(self, chdir_mock, makedirs_mock, exists_mock):
        """Test ch_dir when the directory exists."""
        exists_mock.return_value = True

        fs_util.ch_dir("/tmp/dir")
        makedirs_mock.assert_not_called()
        chdir_mock.assert_called_once()

    @patch("keylime.fs_util.os.path.exists")
    @patch("keylime.fs_util.os.makedirs")
    @patch("keylime.fs_util.os.chdir")
    # "no-self-use" warning has been reassigned from R0201 to R6301:
    # https://pylint.pycqa.org/en/latest/user_guide/messages/refactor/old-no-self-use.html
    # pylint: disable-next=R
    def test_ch_dir_missing(self, chdir_mock, makedirs_mock, exists_mock):
        """Test ch_dir when the directory is missing."""
        exists_mock.return_value = False

        fs_util.ch_dir("/tmp/dir")
        makedirs_mock.assert_called_once()
        chdir_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
