import http.server
import unittest
from unittest.mock import MagicMock, patch

import tornado.web

from keylime import json, web_util


class TestConfig(unittest.TestCase):
    @patch("keylime.web_util.config")
    def test_get_restful_params(self, _):
        """Tests if the parsing of the parameters works"""
        version_url = "/v1.0/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&vmask=0x808000&partial=0"
        version_params = {
            "api_version": "1.0",
            "quotes": "integrity",
            "nonce": "1234567890ABCDEFHIJ",
            "mask": "0x408000",
            "vmask": "0x808000",
            "partial": "0",
        }
        self.assertEqual(web_util.get_restful_params(version_url), version_params)

        basic_url = "/version"
        basic_params = {"version": None, "api_version": "0"}
        self.assertEqual(web_util.get_restful_params(basic_url), basic_params)

    def test_json_response_tornado(self):
        """Tests JSON response output for Tornado"""
        mock_handler = MagicMock(spec=tornado.web.RequestHandler)
        test_data = {"key_1": "value", "key_2": 2}
        expected_output = json.dumps(
            {
                "code": 200,
                "status": "Success",
                "results": test_data,
            }
        ).encode("utf-8")
        res = web_util.echo_json_response(mock_handler, 200, "Success", test_data)
        self.assertTrue(res)
        mock_handler.set_status.assert_called_once_with(200)
        mock_handler.set_header.assert_called_once_with("Content-Type", "application/json")
        mock_handler.write.assert_called_once_with(expected_output)
        mock_handler.finish.assert_called_once()

    def test_json_response_http_server(self):
        """Tests JSON response output for Tornado"""
        mock_handler = MagicMock(spec=http.server.BaseHTTPRequestHandler)
        mock_handler.wfile = MagicMock()
        test_data = {"key_1": "value", "key_2": 2}
        expected_output = json.dumps(
            {
                "code": 200,
                "status": "Success",
                "results": test_data,
            }
        ).encode("utf-8")
        res = web_util.echo_json_response(mock_handler, 200, "Success", test_data)
        self.assertTrue(res)
        mock_handler.send_response.assert_called_once_with(200)
        mock_handler.send_header.assert_called_once_with("Content-Type", "application/json")
        mock_handler.end_headers.assert_called_once()
        mock_handler.wfile.write.assert_called_once_with(expected_output)


if __name__ == "__main__":
    unittest.main()
