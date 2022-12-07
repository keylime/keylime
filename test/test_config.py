import importlib
import os
import unittest
from configparser import NoOptionError

from keylime import config

CONFIG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/config"))


class TestConfig(unittest.TestCase):
    def setUp(self):
        """Dummy setup so that the tearDown() is executed"""
        # See the following documentation:
        # https://docs.python.org/3/library/unittest.html#unittest.TestCase.tearDown
        return

    def tearDown(self):
        """The config module should be reloaded."""
        # Because we can alter global state, we should reload the
        # config module after every test
        importlib.reload(config)

    def test_default_config_files(self):
        """Test default config file list."""
        self.assertEqual(
            config.CONFIG_FILES,
            {
                "agent": ["/etc/keylime/agent.conf", "/usr/etc/keylime/agent.conf"],
                "verifier": ["/etc/keylime/verifier.conf", "/usr/etc/keylime/verifier.conf"],
                "tenant": ["/etc/keylime/tenant.conf", "/usr/etc/keylime/tenant.conf"],
                "registrar": ["/etc/keylime/registrar.conf", "/usr/etc/keylime/registrar.conf"],
                "ca": ["/etc/keylime/ca.conf", "/usr/etc/keylime/ca.conf"],
                "logging": ["/etc/keylime/logging.conf", "/usr/etc/keylime/logging.conf"],
            },
        )

    def test_no_component(self):
        """Test that no component causes exception"""
        self.assertRaises(Exception, config.get, "")

    def test_invalid_env(self):
        """Test that invalid CONFIG_ENV causes exception"""
        config.CONFIG_ENV = []
        self.assertRaises(Exception, config.get_config, "test")

    def test_invalid_files(self):
        """Test that invalid CONFIG_FILES causes exception"""
        config.CONFIG_FILES = []
        self.assertRaises(Exception, config.get_config, "test")

    def test_invalid_component(self):
        """Test that invalid component causes exception"""
        self.assertRaises(Exception, config.get_config, "test")

    def test_single_config(self):
        """Test reading a single config file."""
        config.CONFIG_FILES = {"test": [os.path.join(CONFIG_DIR, "keylime-1.conf")]}
        config.CONFIG_ENV = {"test": ""}
        config.CONFIG_SNIPPETS_DIRS = {"test": ""}
        c = config.get_config("test")
        self.assertEqual(c.get("default", "attribute_1"), "value_1")

    def test_first_base_file_used(self):
        """Test giving multiple possibilities for base file."""
        config.CONFIG_FILES = {
            "test": [
                os.path.join(CONFIG_DIR, "keylime-1.conf"),
                os.path.join(CONFIG_DIR, "keylime-2.conf"),
            ]
        }
        config.CONFIG_ENV = {"test": ""}
        config.CONFIG_SNIPPETS_DIRS = {"test": ""}
        c = config.get_config("test")
        self.assertEqual(c.get("default", "attribute_1"), "value_1")
        # Assert that if the first file is found, the second is ignored
        self.assertRaises(NoOptionError, c.get, "default", "attribute_2")

    def test_missing_base_file_ignored(self):
        """Test that if a file is missing, it tries the next."""
        # Now use a non-existent first file to test if the second file is used
        # instead
        config.CONFIG_FILES = {
            "test": [
                os.path.join(CONFIG_DIR, "non-existent.conf"),
                os.path.join(CONFIG_DIR, "keylime-2.conf"),
            ]
        }
        config.CONFIG_ENV = {"test": ""}
        config.CONFIG_SNIPPETS_DIRS = {"test": ""}
        c = config.get_config("test")
        self.assertRaises(NoOptionError, c.get, "default", "attribute_1")
        self.assertEqual(c.get("default", "attribute_2"), "value_2")

    def test_merge_config(self):
        """Test reading multiple config files and merging them."""
        config.CONFIG_FILES = {"agent": [os.path.join(CONFIG_DIR, "agent.conf")]}
        config.CONFIG_ENV = {"agent": ""}
        config.CONFIG_SNIPPETS_DIRS = {"agent": [os.path.join(CONFIG_DIR, "agent.conf.d")]}
        c = config.get_config("agent")
        self.assertEqual(c.get("agent", "attribute_1"), "value_1_3")
        self.assertEqual(c.get("agent", "attribute_2"), "value_2")
        self.assertEqual(c.get("agent", "attribute_3"), "value_3")

    def test_cache_config(self):
        """Test the config is properly cached between calls."""
        config.CONFIG_FILES = {"agent": [os.path.join(CONFIG_DIR, "agent.conf")]}
        config.CONFIG_ENV = {"agent": ""}
        config.CONFIG_SNIPPETS_DIRS = {"agent": ""}
        c = config.get_config("agent")
        self.assertEqual(c.get("agent", "attribute", fallback=None), None)

        c.set("agent", "attribute", "value")
        self.assertEqual(c.get("agent", "attribute"), "value")

        c_copy = config.get_config("agent")
        self.assertEqual(c_copy.get("agent", "attribute"), "value")

    def test_reexport_function(self):
        """Test re-exported functions to access data."""
        config.CONFIG_FILES = {"test": [os.path.join(CONFIG_DIR, "keylime-1.conf")]}
        config.CONFIG_ENV = {"test": ""}
        config.CONFIG_SNIPPETS_DIRS = {"test": ""}
        self.assertEqual(config.get("test", "attribute", section="default", fallback=""), "")

    def test_env_overrides_all(self):
        """Test that using an env var to set config ignore other files"""

        os.environ["KEYLIME_AGENT_CONFIG"] = os.path.join(CONFIG_DIR, "agent.conf")

        # Reload the configuration to use the set environment variable on setup
        importlib.reload(config)
        config.CONFIG_SNIPPETS_DIRS = {"agent": [os.path.join(CONFIG_DIR, "agent.conf.d")]}
        c = config.get_config("agent")
        self.assertEqual(c.get("agent", "attribute_1"), "value_1")
        self.assertRaises(Exception, c.get, "agent", "attribute_2")
        self.assertRaises(Exception, c.get, "agent", "attribute_3")

        # Unset the variable to not affect other tests
        os.environ["KEYLIME_AGENT_CONFIG"] = ""

    def test_get(self) -> None:
        """Sanity test for config.get()"""

        config.CONFIG_FILES = {"agent": [os.path.join(CONFIG_DIR, "agent.conf")]}
        config.CONFIG_ENV = {"agent": ""}
        config.CONFIG_SNIPPETS_DIRS = {"agent": ""}

        # Check that non-existing option will fallback
        self.assertEqual(config.get("agent", "attribute", fallback="fallback"), "fallback")

        # Check that existing option is properly obtained
        self.assertEqual(config.get("agent", "attribute_1", fallback="fallback"), "value_1")

        # Check that quoted option is unquoted
        self.assertEqual(config.get("agent", "quoted"), "unquoted")

        # Check that quotes and trailing spaces are properly removed
        self.assertEqual(config.get("agent", "quotes_spaces"), "unquoted")


if __name__ == "__main__":
    unittest.main()
