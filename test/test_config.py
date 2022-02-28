import importlib
import os
import unittest

from keylime import config

CONFIG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/config"))


class TestConfig(unittest.TestCase):
    def setUp(self):
        """The config module should be reloaded."""
        # Because we can alter global state, we should reload the
        # config module before every test
        importlib.reload(config)
        # Remove a side effect of some variables pre-loading the
        # configuration files
        del config.get_config.config

    def test_default_config_files(self):
        """Test default config file list."""
        self.assertEqual(
            config.CONFIG_FILES,
            [
                "/usr/etc/keylime.conf",
                "/etc/keylime.conf",
                os.path.expanduser("~/.config/keylime.conf"),
            ],
        )

    def test_no_config(self):
        """Test that no config files is an empty set."""
        c = config.get_config()
        self.assertEqual(c.get("default", "value_1", fallback=None), None)

    def test_single_config(self):
        """Test reading a single config file."""
        config.CONFIG_FILES = [os.path.join(CONFIG_DIR, "keylime-1.conf")]
        c = config.get_config()
        self.assertEqual(c.get("default", "attribute_1"), "value_1")

    def test_multiple_config(self):
        """Test reading multiple config files."""
        config.CONFIG_FILES = [
            os.path.join(CONFIG_DIR, "keylime-1.conf"),
            os.path.join(CONFIG_DIR, "keylime-2.conf"),
        ]
        c = config.get_config()
        self.assertEqual(c.get("default", "attribute_1"), "value_1")
        self.assertEqual(c.get("default", "attribute_2"), "value_2")

    def test_merge_config(self):
        """Test reading multiple config files and merging them."""
        config.CONFIG_FILES = [
            os.path.join(CONFIG_DIR, "keylime-1.conf"),
            os.path.join(CONFIG_DIR, "keylime-2.conf"),
            os.path.join(CONFIG_DIR, "keylime-3.conf"),
        ]
        c = config.get_config()
        self.assertEqual(c.get("default", "attribute_1"), "value_1_3")
        self.assertEqual(c.get("default", "attribute_2"), "value_2")
        self.assertEqual(c.get("default", "attribute_3"), "value_3")

    def test_cache_config(self):
        """Test the config is properly cached between calls."""
        c = config.get_config()
        self.assertEqual(c.get("default", "attribute", fallback=None), None)

        c.add_section("default")
        c.set("default", "attribute", "value")
        self.assertEqual(c.get("default", "attribute"), "value")

        c_copy = config.get_config()
        self.assertEqual(c_copy.get("default", "attribute"), "value")

    def test_reexport_function(self):
        """Test re-exported functions to access data."""
        self.assertEqual(config.get("default", "attribute", fallback=None), None)


if __name__ == "__main__":
    unittest.main()
