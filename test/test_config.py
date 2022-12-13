import importlib
import logging
import os
import shutil
import tempfile
import unittest
from configparser import NoOptionError

from keylime import config

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CONFIG_DIR = os.path.abspath(os.path.join(DATA_DIR, "config"))


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

        if "KEYLIME_AGENT_CONFIG" in os.environ:
            env_bkp = os.environ["KEYLIME_AGENT_CONFIG"]
        else:
            env_bkp = ""

        os.environ["KEYLIME_AGENT_CONFIG"] = os.path.join(CONFIG_DIR, "agent.conf")

        # Reload the configuration to use the set environment variable on setup
        importlib.reload(config)
        config.CONFIG_SNIPPETS_DIRS = {"agent": [os.path.join(CONFIG_DIR, "agent.conf.d")]}
        c = config.get_config("agent")
        self.assertEqual(c.get("agent", "attribute_1"), "value_1")
        self.assertRaises(Exception, c.get, "agent", "attribute_2")
        self.assertRaises(Exception, c.get, "agent", "attribute_3")

        # Unset the variable to not affect other tests
        os.environ["KEYLIME_AGENT_CONFIG"] = env_bkp

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

    def test_check_version(self) -> None:
        """Sanity check for check_version"""

        config.CONFIG_FILES = {"comp1": [os.path.join(CONFIG_DIR, "comp1_old.conf")]}
        config.CONFIG_ENV = {"comp1": ""}
        config.CONFIG_SNIPPETS_DIRS = {"comp1": ""}
        config.TEMPLATES_DIR = os.path.join(DATA_DIR, "templates")

        self.assertTrue(os.path.exists(config.TEMPLATES_DIR))
        self.assertTrue(config.check_version("comp1"))

        with self.assertLogs("test_config", level="DEBUG") as cm:
            logger = logging.getLogger("test_config")

            # Check with non-existing directory
            config.TEMPLATES_DIR = "non-existing"
            self.assertFalse(config.check_version("comp1", logger=logger))
            self.assertTrue(
                f"WARNING:test_config:The configuration upgrade templates path {config.TEMPLATES_DIR} does not exist"
                in cm.output
            )

            # Check with existing file that is not a directory
            config.TEMPLATES_DIR = os.path.join(CONFIG_DIR, "comp1.conf")
            self.assertTrue(os.path.exists(config.TEMPLATES_DIR))
            self.assertFalse(config.check_version("comp1", logger=logger))
            self.assertTrue(f"WARNING:test_config:The path {config.TEMPLATES_DIR} is not a directory" in cm.output)

            with tempfile.TemporaryDirectory() as tempdir:
                config.TEMPLATES_DIR = tempdir

                logger = logging.getLogger("test_config")

                # Check with empty directory
                self.assertFalse(config.check_version("comp1", logger=logger))
                self.assertTrue(
                    f"WARNING:test_config:The path {tempdir} does not contain version directories for config upgrade templates"
                    in cm.output
                )

                # Check with up-to-date version
                shutil.copytree(os.path.join(DATA_DIR, "templates/1.0"), os.path.join(tempdir, "1.0"))
                self.assertFalse(config.check_version("comp1"))

                # Check with minor update available
                shutil.copytree(os.path.join(DATA_DIR, "templates/1.0"), os.path.join(tempdir, "1.2"))
                self.assertTrue(config.check_version("comp1", logger=logger))
                self.assertTrue(
                    "INFO:test_config:A minor configuration upgrade is available (from 1.0 to 1.2). Run 'keylime_upgrade_config' to upgrade the configuration"
                    in cm.output
                )

                # Check with major update available
                shutil.copytree(os.path.join(DATA_DIR, "templates/2.0"), os.path.join(tempdir, "2.0"))
                self.assertTrue(config.check_version("comp1", logger=logger))
                print(cm.output)
                self.assertTrue(
                    "WARNING:test_config:A major configuration upgrade is available (from 1.0 to 2.0). Run 'keylime_upgrade_config' to upgrade the configuration"
                    in cm.output
                )

            with tempfile.TemporaryDirectory() as tempdir:
                config.TEMPLATES_DIR = tempdir

                # Check with invalid directory naming (should be version number)
                shutil.copytree(os.path.join(DATA_DIR, "templates/2.0"), os.path.join(tempdir, "not_version"))
                self.assertFalse(config.check_version("comp1", logger=logger))
                self.assertTrue(
                    f"WARNING:test_config:The path {tempdir} does not contain valid config version upgrade directories"
                    in cm.output
                )


if __name__ == "__main__":
    unittest.main()
