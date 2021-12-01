"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Red Hat, Inc.
"""

import unittest

from keylime import json as keylime_json


class JSON_Test(unittest.TestCase):
    def test_dumps(self):
        fixtures = [
            {"input": {}, "expected": "{}"},
            {"input": {"foo": "bar"}, "expected": '{"foo": "bar"}'},
            {"input": {"foo": b"bar"}, "expected": '{"foo": "bar"}'},
            {
                "input": {"foo": {"foo": {"foo": b"bar"}}},
                "expected": '{"foo": {"foo": {"foo": "bar"}}}',
            },
            {"input": [], "expected": "[]"},
            {"input": (), "expected": "[]"},
            {"input": [b"a", b"b", 1, 2.0], "expected": '["a", "b", 1, 2.0]'},
            {"input": {"foo": [b"bar"]}, "expected": '{"foo": ["bar"]}'},
            {
                "input": (
                    1,
                    2,
                    b"a",
                ),
                "expected": '[1, 2, "a"]',
            },
        ]
        for f in fixtures:
            self.assertEqual(keylime_json.dumps(f["input"]), f["expected"])
