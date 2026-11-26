"""Unit tests for verifier startup logging and deprecated options warnings."""

# pylint: disable=protected-access

import unittest
from unittest.mock import MagicMock, patch

from keylime.cmd.verifier import _log_startup_info


class TestVerifierStartupLogging(unittest.TestCase):
    """Test cases for verifier startup logging."""

    @patch("keylime.cmd.verifier.logger")
    @patch("keylime.cmd.verifier.api_version")
    @patch("keylime.cmd.verifier.config")
    def test_startup_default_options_no_deprecation_warnings(
        self, mock_config: MagicMock, _mock_api: MagicMock, mock_logger: MagicMock
    ) -> None:
        """Verify no deprecation warnings when options use default values."""
        mock_config.get.side_effect = lambda comp, opt, fallback="": {
            ("verifier", "mode"): "pull",
            ("verifier", "registrar_ip"): "127.0.0.1",
            ("verifier", "registrar_port"): "8891",
        }.get((comp, opt), fallback)

        _log_startup_info()

        warning_messages = [call.args[0] % call.args[1:] for call in mock_logger.warning.call_args_list if call.args]
        deprecation_warnings = [msg for msg in warning_messages if "deprecated and unused" in msg]
        self.assertEqual(deprecation_warnings, [])

    @patch("keylime.cmd.verifier.logger")
    @patch("keylime.cmd.verifier.api_version")
    @patch("keylime.cmd.verifier.config")
    def test_startup_custom_registrar_ip_warning(
        self, mock_config: MagicMock, _mock_api: MagicMock, mock_logger: MagicMock
    ) -> None:
        """Verify a warning is logged when registrar_ip is set to a non-default value."""
        mock_config.get.side_effect = lambda comp, opt, fallback="": {
            ("verifier", "mode"): "pull",
            ("verifier", "registrar_ip"): "192.168.1.100",
            ("verifier", "registrar_port"): "8891",
        }.get((comp, opt), fallback)

        _log_startup_info()

        warning_messages = [call.args[0] % call.args[1:] for call in mock_logger.warning.call_args_list if call.args]
        deprecation_warnings = [msg for msg in warning_messages if "deprecated and unused" in msg]
        self.assertEqual(len(deprecation_warnings), 1)
        self.assertIn("verifier.registrar_ip", deprecation_warnings[0])
        self.assertIn("since v6.4.0", deprecation_warnings[0])

    @patch("keylime.cmd.verifier.logger")
    @patch("keylime.cmd.verifier.api_version")
    @patch("keylime.cmd.verifier.config")
    def test_startup_custom_registrar_port_warning(
        self, mock_config: MagicMock, _mock_api: MagicMock, mock_logger: MagicMock
    ) -> None:
        """Verify a warning is logged when registrar_port is set to a non-default value."""
        mock_config.get.side_effect = lambda comp, opt, fallback="": {
            ("verifier", "mode"): "pull",
            ("verifier", "registrar_ip"): "127.0.0.1",
            ("verifier", "registrar_port"): "8895",
        }.get((comp, opt), fallback)

        _log_startup_info()

        warning_messages = [call.args[0] % call.args[1:] for call in mock_logger.warning.call_args_list if call.args]
        deprecation_warnings = [msg for msg in warning_messages if "deprecated and unused" in msg]
        self.assertEqual(len(deprecation_warnings), 1)
        self.assertIn("verifier.registrar_port", deprecation_warnings[0])
        self.assertIn("since v6.4.0", deprecation_warnings[0])

    @patch("keylime.cmd.verifier.logger")
    @patch("keylime.cmd.verifier.api_version")
    @patch("keylime.cmd.verifier.config")
    def test_startup_both_custom_options_warns(
        self, mock_config: MagicMock, _mock_api: MagicMock, mock_logger: MagicMock
    ) -> None:
        """Verify warnings are logged when both registrar options are non-default."""
        mock_config.get.side_effect = lambda comp, opt, fallback="": {
            ("verifier", "mode"): "pull",
            ("verifier", "registrar_ip"): "10.0.0.5",
            ("verifier", "registrar_port"): "9999",
        }.get((comp, opt), fallback)

        _log_startup_info()

        warning_messages = [call.args[0] % call.args[1:] for call in mock_logger.warning.call_args_list if call.args]
        deprecation_warnings = [msg for msg in warning_messages if "deprecated and unused" in msg]
        self.assertEqual(len(deprecation_warnings), 2)
        self.assertTrue(any("verifier.registrar_ip" in msg for msg in deprecation_warnings))
        self.assertTrue(any("verifier.registrar_port" in msg for msg in deprecation_warnings))


if __name__ == "__main__":
    unittest.main()
