import configparser
import importlib
import logging
import os
import tempfile
import unittest

from keylime.cmd import convert_config

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CONFIG_DIR = os.path.abspath(os.path.join(DATA_DIR, "config"))
TEMPLATES_DIR = os.path.abspath(os.path.join(DATA_DIR, "templates"))
MAPPINGS_DIR = os.path.abspath(os.path.join(DATA_DIR, "mappings"))
COMPONENTS = ["comp1", "comp2"]


class TestConvertConfig(unittest.TestCase):
    def setUp(self) -> None:
        # Set configuration files used for testing
        convert_config.CONFIG_FILES = list(os.path.join(CONFIG_DIR, f"{comp}.conf") for comp in COMPONENTS)
        convert_config.OLD_CONFIG_FILES = list(os.path.join(CONFIG_DIR, f"{comp}_old.conf") for comp in COMPONENTS)

    def tearDown(self) -> None:
        importlib.reload(convert_config)

    def test_get_config(self) -> None:
        """Sanity test for get_config()"""

        existing_path = os.path.join(CONFIG_DIR, "comp1_exist.conf")
        self.assertTrue(os.path.exists(existing_path))

        # Provide existing file as input
        config = convert_config.get_config([[existing_path]])

        value = config.get("comp1", "test_option", fallback="Not found")
        # Check that the file was correctly parsed
        self.assertEqual(value, "existing")

    def test_get_config_no_input(self) -> None:
        """Test get_config() without providing input"""

        # Provide no input
        config = convert_config.get_config([[]])

        # Check that CONFIG_FILES were correctly parsed
        value = config.get("comp1", "test_option", fallback="Not found")

        self.assertEqual(value, "current")

    def test_get_config_none_existing(self) -> None:
        """Test get_config() where none of the files exist"""

        # Provide non-existing files as input and expect exception
        self.assertRaises(Exception, convert_config.get_config, "non-existing.conf")

    def test_get_config_old(self) -> None:
        """Test get_config() when it should fall back to old file"""

        # Set CONFIG_FILES to non existing files
        convert_config.CONFIG_FILES = ["non-existing.conf"]

        # Give no input
        config = convert_config.get_config([[]])

        # Check that OLD_CONFIG_FILES were correctly parsed
        value = config.get("comp1", "test_option", fallback="Not found")

        self.assertEqual(value, "old")

    def test_get_config_default(self) -> None:
        """Test get_config() when it should use default values"""

        # Set CONFIG_FILES to non existing files
        convert_config.CONFIG_FILES = ["non-existing.conf"]

        # Set OLD_CONFIG_FILES to non existing files
        convert_config.OLD_CONFIG_FILES = ["non-existing.conf"]

        # Give no input
        config = convert_config.get_config([[]])

        # Check that an empty RawConfigParser was returned
        self.assertTrue(isinstance(config, configparser.RawConfigParser))
        self.assertEqual(len(config.keys()), 1)
        self.assertEqual(list(config.keys()), ["DEFAULT"])
        self.assertEqual(len(list(config.items("DEFAULT"))), 0)

    def test_output_component(self) -> None:
        """Test that given a config and template, the output is generated"""

        template_path = os.path.join(TEMPLATES_DIR, "2.0/comp1.j2")
        self.assertTrue(os.path.exists(template_path))

        # Create a configuration
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "2.0"
        config["comp1"]["test_option"] = "generated"
        config["comp1"]["test_adjust"] = "generated"
        config.add_section("subcomp1")
        config["subcomp1"]["suboption"] = "generated"

        # Provide configuration and template
        with tempfile.TemporaryDirectory() as tempdir:
            outfile = os.path.join(tempdir, "output.conf")
            convert_config.output_component("comp1", config, template_path, outfile)

            # Check that the file was correctly generated
            self.assertTrue(os.path.exists(outfile))

            generated = configparser.ConfigParser()
            l = generated.read(outfile)
            self.assertTrue(outfile in l)
            self.assertEqual(generated.get("comp1", "test_option"), "generated")
            self.assertEqual(generated.get("comp1", "test_adjust"), "generated")
            self.assertEqual(generated.get("subcomp1", "suboption"), "generated")

    def test_output_no_version(self) -> None:
        """Test that if the version doesn't exist, the output fails"""

        # Provide config where the template for a given component version
        # doesn't exist and check that it raises Exception

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "5.0"

        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(Exception, convert_config.output, ["comp1"], config, TEMPLATES_DIR, tempdir)

    def test_output_no_template(self) -> None:
        """Test that if the template is not available, the output fails"""

        # Provide config where the version directory exists, but the template
        # for the given component doesn't and check that it raises Exception

        config = configparser.RawConfigParser()
        config.add_section("comp3")
        config["comp3"]["version"] = "2.0"

        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(Exception, convert_config.output, ["comp3"], config, TEMPLATES_DIR, tempdir)

    def test_output(self) -> None:
        """Sanity test for output()"""

        # Create a configuration
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "2.0"
        config["comp1"]["test_option"] = "generated"
        config["comp1"]["test_adjust"] = "generated"
        config.add_section("subcomp1")
        config["subcomp1"]["suboption"] = "generated"

        with tempfile.TemporaryDirectory() as tempdir:
            convert_config.output(["comp1"], config, TEMPLATES_DIR, tempdir)

            outfile = os.path.join(tempdir, "comp1.conf")
            self.assertTrue(os.path.exists(outfile))

            generated = configparser.ConfigParser()
            l = generated.read(outfile)
            self.assertTrue(outfile in l)
            self.assertEqual(generated.get("comp1", "test_option"), "generated")
            self.assertEqual(generated.get("comp1", "test_adjust"), "generated")
            self.assertEqual(generated.get("subcomp1", "suboption"), "generated")

    def test_needs_update(self) -> None:
        """Test needs_update()"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")

        # Assert that without version, it will always need update
        self.assertTrue(convert_config.needs_update("comp1", config, (0, 0)))

        config["comp1"]["version"] = "2.0"
        self.assertTrue(convert_config.needs_update("comp1", config, (3, 0)))
        self.assertFalse(convert_config.needs_update("comp1", config, (2, 0)))

    def test_process_mapping(self) -> None:
        """Sanity test for process_mapping()"""

        # Use default configuration files
        config = convert_config.get_config([[]])

        # Use sanity mapping (default)
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        with self.assertLogs("process_mapping", level="DEBUG") as cm:
            l = logging.getLogger("process_mapping")
            result = convert_config.process_mapping(COMPONENTS, config, TEMPLATES_DIR, mapping, False, logger=l)

        self.assertTrue(isinstance(result, configparser.RawConfigParser))

        # Check that option not found uses default value
        self.assertTrue("test_default" in result["comp1"])
        self.assertEqual(result.get("comp1", "test_default"), "default")

        # Check that added option is present
        self.assertTrue("test_added" in result["comp1"])

        # Check removed option is not present
        self.assertFalse("test_option" in result["comp2"])

        # Check that adjust is correctly applied
        self.assertEqual(result.get("comp1", "test_adjust"), "adjusted 3.0")

        # Check that when the component does not have a version, the smallest
        # number is used
        self.assertTrue(
            "DEBUG:process_mapping:No version found in old configuration for comp1, using '1.0'" in cm.output
        )

    def test_process_non_existing_mapping(self) -> None:
        """Check that non-existing mapping raises Exception"""
        config = configparser.RawConfigParser()
        self.assertRaises(
            Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, "non-existing-mapping"
        )

    def test_process_mapping_no_version(self) -> None:
        """Check that mapping without version raises Exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "no-version.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def test_process_mapping_no_components(self) -> None:
        """Check that mapping without components raises exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "no-components.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def test_process_mapping_invalid_version(self) -> None:
        """Check that invalid version number (not parseable) raises exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "invalid-version.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def test_process_mapping_already_updated(self) -> None:
        """Check that if all components are updated, the process is short
        circuited and returns earlier"""
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "3.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "3.0"
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        with self.assertLogs("already_updated", level="DEBUG") as cm:
            l = logging.getLogger("already_updated")
            result = convert_config.process_mapping(COMPONENTS, config, TEMPLATES_DIR, mapping, False, logger=l)
            self.assertEqual(result, config)

        # Check that the output shows that the updated version was skipped
        self.assertTrue("INFO:already_updated:Skipping version 3.0" in cm.output)

    def test_process_mapping_missing_version(self) -> None:
        """Check that missing version in templates directory raises exception"""
        config = configparser.RawConfigParser()
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        # Use empty directory as the templates directory and check that raises
        # Exception
        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, tempdir, mapping)

    def test_process_mapping_invalid_component_version(self) -> None:
        """Check that if a component in the config does not have a parseable
        version, it raises exception
        """
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "notversion"

        # Use string not parseable as version and check that raises Exception
        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")
        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, TEMPLATES_DIR, mapping)

    def test_process_mapping_missing_adjust_method(self) -> None:
        """Check that adjust script without adjust() method it raises
        exception
        """

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"

        template = os.path.join(DATA_DIR, "template-no-adjust")
        self.assertTrue(os.path.exists(template))

        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, template, mapping)

    def test_process_mapping_invalid_adjust_file(self) -> None:
        """Check that invalid file as adjust script raises exception (not python
        loadable)
        """

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"

        template = os.path.join(DATA_DIR, "template-invalid-adjust")
        self.assertTrue(os.path.exists(template))

        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, template, mapping)

    def test_process_mapping_adjust_exception(self) -> None:
        """Check that if adjust raises exception, the exception is re-raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"

        template = os.path.join(DATA_DIR, "template-adjust-exception")
        self.assertTrue(os.path.exists(template))

        mapping = os.path.join(MAPPINGS_DIR, "sanity.json")

        self.assertRaises(Exception, convert_config.process_mapping, COMPONENTS, config, template, mapping)

    def test_process_versions(self) -> None:
        """Sanity test for the config upgrade process through all versions"""

        config = convert_config.get_config([[]])

        result = convert_config.process_versions(COMPONENTS, TEMPLATES_DIR, config, False)

        value = result.get("comp1", "test_option")
        # Check that the file was correctly parsed
        self.assertEqual(value, "current")
        value = result.get("comp1", "test_adjust")
        self.assertEqual(value, "adjusted 3.0")
        value = result.get("comp1", "version")
        self.assertEqual(value, "3.0")

        # Check that versions lower than the current version are skipped for
        # each component.
        self.assertEqual(result.get("comp1", "oldest_used"), "2.0")
        self.assertEqual(result.get("comp2", "oldest_used"), "3.0")

        # Check that subcomponent correctly inherits version from parent
        self.assertEqual(result.get("subcomp1", "version"), "3.0")

    def test_process_versions_target_version(self) -> None:
        """Check that the update stops at the target version, when it is set"""

        config = convert_config.get_config([[]])
        result = convert_config.process_versions(COMPONENTS, TEMPLATES_DIR, config, False, target_version="2.0")
        self.assertEqual(result.get("comp1", "version"), "2.0")
        self.assertEqual(result.get("comp2", "version"), "2.0")

    def test_strip_quotes(self) -> None:
        """Test stripping surrounding quotes and spaces from config"""
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["test_option"] = '"unquoted"'
        config.add_section("comp2")
        config["comp2"]["test_option"] = '   " unquoted  """"'

        # Strip surrounding quotes and spaces from all options
        convert_config.strip_quotes(config)

        self.assertEqual(config.get("comp1", "test_option"), "unquoted")
        self.assertEqual(config.get("comp2", "test_option"), "unquoted")

    def test_process_versions_using_toml(self) -> None:
        """Test that using TOML files as old configs does not break"""
        toml = os.path.join(CONFIG_DIR, "comp1.toml")
        self.assertTrue(os.path.exists(toml))

        config = convert_config.get_config([[toml]])

        result = convert_config.process_versions(["comp1"], TEMPLATES_DIR, config, False)
        self.assertEqual(result.get("comp1", "version"), "3.0")
        self.assertEqual(result.get("comp1", "test_option"), "current")
        self.assertEqual(result.get("comp1", "test_adjust"), "adjusted 3.0")
        self.assertEqual(result.get("subcomp1", "suboption"), "current")

        # Output file using template with quotes on every string (TOML)
        template_path = os.path.join(DATA_DIR, "template-with-quotes.j2")
        self.assertTrue(os.path.exists(template_path))

        with tempfile.TemporaryDirectory() as tempdir:
            outfile = os.path.join(tempdir, "output.conf")
            convert_config.output_component("comp1", result, template_path, outfile)

            # Check that the file was correctly generated
            self.assertTrue(os.path.exists(outfile))

            quoted = configparser.ConfigParser()
            l = quoted.read(outfile)
            self.assertTrue(outfile in l)

            # Check that reading config directly the quotes are still present
            self.assertEqual(quoted.get("comp1", "test_option"), '"current"')
            self.assertEqual(quoted.get("comp1", "test_adjust"), '"adjusted 3.0"')
            self.assertEqual(quoted.get("subcomp1", "suboption"), '"current"')

            result = convert_config.process_versions(["comp1"], TEMPLATES_DIR, quoted, False)

            # Check that the result doesn't come with surrounding quotes
            self.assertEqual(result.get("comp1", "test_option"), "current")
            self.assertEqual(result.get("comp1", "test_adjust"), "adjusted 3.0")
            self.assertEqual(result.get("subcomp1", "suboption"), "current")

    def test_update_add(self) -> None:
        """Test mapping update adding options"""
        # Use default configuration files
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "3.0"
        config["comp1"]["unused_option"] = "unused"
        config.add_section("subcomp1")
        config["subcomp1"]["unused_option"] = "unused"
        config.add_section("comp2")
        config["comp2"]["version"] = "3.0"
        config["comp2"]["unused_option"] = "unused"
        config.add_section("subcomp2")
        config["subcomp2"]["unused_option"] = "unused"

        template = os.path.join(DATA_DIR, "templates-update-add")
        self.assertTrue(os.path.exists(template))

        result = convert_config.process_versions(COMPONENTS, template, config, False)

        # Check that the new options were properly added
        self.assertTrue("added_option" in result["comp1"])
        self.assertTrue("added_option" in result["subcomp1"])
        self.assertTrue("added_option" in result["comp2"])
        self.assertTrue("added_option" in result["subcomp2"])

        # Check that the version of the components were updated
        self.assertEqual("3.1", result.get("comp1", "version"))
        self.assertEqual("3.1", result.get("subcomp1", "version"))
        self.assertEqual("3.1", result.get("comp2", "version"))
        self.assertEqual("3.1", result.get("subcomp2", "version"))

    def test_update_remove(self) -> None:
        """Test mapping update removing options"""
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["unused_option"] = "unused"
        config.add_section("subcomp1")
        config["subcomp1"]["version"] = "1.0"
        config["subcomp1"]["unused_option"] = "unused"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"
        config["comp2"]["unused_option"] = "unused"
        config.add_section("subcomp2")
        config["subcomp2"]["version"] = "1.0"
        config["subcomp2"]["unused_option"] = "unused"

        template = os.path.join(DATA_DIR, "templates-update-remove")
        self.assertTrue(os.path.exists(template))

        result = convert_config.process_versions(COMPONENTS, template, config, False)

        # Check that options were removed from the result
        self.assertTrue("unused_option" not in result["comp1"])
        self.assertTrue("unused_option" not in result["subcomp1"])
        self.assertTrue("unused_option" not in result["comp2"])
        self.assertTrue("unused_option" not in result["subcomp2"])

        # Check that the versions of the components were updated
        self.assertEqual("3.1", result.get("comp1", "version"))
        self.assertEqual("3.1", result.get("subcomp1", "version"))
        self.assertEqual("3.1", result.get("comp2", "version"))
        self.assertEqual("3.1", result.get("subcomp2", "version"))

    def test_update_replace(self) -> None:
        """Test mapping update replacing options"""
        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["old_option"] = "old_value"
        config.add_section("subcomp1")
        config["subcomp1"]["version"] = "1.0"
        config["subcomp1"]["old_option"] = "old_value"
        config.add_section("comp2")
        config["comp2"]["version"] = "1.0"
        config["comp2"]["old_option"] = "old_value"
        config.add_section("subcomp2")
        config["subcomp2"]["version"] = "1.0"
        config["subcomp2"]["old_option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-update-replace")
        self.assertTrue(os.path.exists(template))

        result = convert_config.process_versions(COMPONENTS, template, config, False)

        # Check that options with the old name are not present
        self.assertTrue("old_option" not in result["comp1"])
        self.assertTrue("old_option" not in result["subcomp1"])
        self.assertTrue("old_option" not in result["comp2"])
        self.assertTrue("old_option" not in result["subcomp2"])

        # Check that options with the new name are present
        self.assertTrue("new_option" in result["comp1"])
        self.assertTrue("new_option" in result["subcomp1"])
        self.assertTrue("new_option" in result["comp2"])
        self.assertTrue("new_option" in result["subcomp2"])

        # Check that the values of the options were kept
        self.assertEqual("old_value", result.get("comp1", "new_option"))
        self.assertEqual("old_value", result.get("subcomp1", "new_option"))
        self.assertEqual("old_value", result.get("comp2", "new_option"))
        self.assertEqual("old_value", result.get("subcomp2", "new_option"))

        # Check that the version of the components were updated
        self.assertEqual("3.1", result.get("comp1", "version"))
        self.assertEqual("3.1", result.get("subcomp1", "version"))
        self.assertEqual("3.1", result.get("comp2", "version"))
        self.assertEqual("3.1", result.get("subcomp2", "version"))

    def test_update_mixed_corner_cases(self) -> None:
        """Test some corner cases on update"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["existing_option"] = "old_value"
        config["comp1"]["other_existing"] = "old_value"
        config["comp1"]["to_replace"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-update-corner-cases")
        self.assertTrue(os.path.exists(template))

        with self.assertLogs("corner_cases", level="DEBUG") as cm:
            l = logging.getLogger("corner_cases")
            result = convert_config.process_versions(COMPONENTS, template, config, False, logger=l)

        # Check that adding existing option does not choke the update and the old
        # value is preserved
        self.assertTrue(
            'DEBUG:corner_cases:[comp1]: Skipped adding already existing option "existing_option"' in cm.output
        )
        self.assertEqual("old_value", result.get("comp1", "existing_option"))

        # Check that removing non-existing options does not choke the processing
        self.assertTrue(
            'DEBUG:corner_cases:[comp1]: Skipped removing unexisting option "non_existing_option"' in cm.output
        )

        # Check that replacing an option with an already existing option results
        # on the replaced option removed and existing option value preserved
        self.assertTrue('DEBUG:corner_cases:[comp1]: Skipped removing unexisting option "non_existing"' in cm.output)
        self.assertEqual("old_value", result.get("comp1", "other_existing"))

        # Check that replacing non-existing option results in option added with
        # default value
        self.assertTrue('DEBUG:corner_cases:[comp1]: Skipped removing unexisting option "non_existing"' in cm.output)
        self.assertEqual("new_value", result.get("comp1", "non_existing_replacement"))

        # Check that new sections and options are added correctly
        self.assertTrue('INFO:corner_cases:Added new section "[new_comp]"' in cm.output)
        self.assertTrue('DEBUG:corner_cases:[new_comp]: Added new option "new_option" = "new_value"' in cm.output)
        self.assertEqual("new_value", result.get("new_comp", "new_option"))

        # Check that bogus operations in new sections generate warnings
        self.assertTrue('WARNING:corner_cases:Bogus "remove" operation in new section "[new_comp]"' in cm.output)
        self.assertTrue('WARNING:corner_cases:Bogus "replace" operation in new section "[new_comp]"' in cm.output)

    def test_update_invalid_mapping_type(self) -> None:
        """Test that invalid mapping type causes an exception to be raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-invalid-mapping-type")
        self.assertRaises(Exception, convert_config.process_versions, COMPONENTS, template, config)

    def test_update_invalid_mapping_version(self) -> None:
        """Test that invalid version causes an exception to be raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-invalid-mapping-version")
        self.assertRaises(Exception, convert_config.process_versions, COMPONENTS, template, config)

    def test_update_invalid_component_version(self) -> None:
        """Test that invalid version causes an exception to be raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "invalid_version"
        config["comp1"]["option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-update-corner-cases")
        self.assertRaises(Exception, convert_config.process_versions, COMPONENTS, template, config)

    def test_update_missing_section(self) -> None:
        """Test that missing section in replace causes an exception to be raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-update-missing-section")
        self.assertRaises(Exception, convert_config.process_versions, COMPONENTS, template, config)

    def test_update_missing_option(self) -> None:
        """Test that missing option in replace causes an exception to be raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-update-missing-option")
        self.assertRaises(Exception, convert_config.process_versions, COMPONENTS, template, config)

    def test_update_missing_default(self) -> None:
        """Test that missing default in replace causes an exception to be raised"""

        config = configparser.RawConfigParser()
        config.add_section("comp1")
        config["comp1"]["version"] = "1.0"
        config["comp1"]["option"] = "old_value"

        template = os.path.join(DATA_DIR, "templates-update-missing-default")
        self.assertRaises(Exception, convert_config.process_versions, COMPONENTS, template, config)
