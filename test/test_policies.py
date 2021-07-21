"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 SUSE LCC
"""

import json
import sys
import unittest
import unittest.mock

# Mock the keylime.config module, so there is no need to create the
# keylime configuration file
config_mock = unittest.mock.MagicMock()
config_mock.MEASUREDBOOT_IMPORTS = []
sys.modules["keylime.config"] = config_mock

# pylint: disable=C0413
from keylime.elchecking import policies, tests


class TestSimple(unittest.TestCase):
    """Test Simple policies defined via JSON"""

    def test_illformed(self):
        """Test building a ill-formed combinator."""
        policy = """
          {"missing": {}}
        """
        with self.assertRaises(Exception) as cm:
            policies.Simple.from_json_str(json.loads(policy))
            self.assertEqual(cm.msg, "Test missing not found")

    def test_acceptall(self):
        """Test building "acceptall" combinator."""
        policy = """
          {"acceptall": {}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.AcceptAll()

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "")

    def test_rejectall(self):
        """Test building "rejectall" combinator."""
        policy = """
          {"rejectall": "RejectAll"}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.RejectAll("RejectAll")

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "RejectAll")

    def test_and_true(self):
        """Test building "and" combinator."""
        policy = """
          {"and": [{"acceptall": {}}, {"acceptall": {}}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.And(tests.AcceptAll(), tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(len(test.tests), 2)
        self.assertEqual(test.tests[0].__class__, expected_test.tests[0].__class__)
        self.assertEqual(test.tests[1].__class__, expected_test.tests[1].__class__)
        self.assertEqual(test.why_not({}, {}), "")

    def test_and_false(self):
        """Test building "and" combinator."""
        policy = """
          {"and": [{"acceptall": {}}, {"rejectall": "RejectAll"}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.And(tests.AcceptAll(), tests.RejectAll("RejectAll"))

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(len(test.tests), 2)
        self.assertEqual(test.tests[0].__class__, expected_test.tests[0].__class__)
        self.assertEqual(test.tests[1].__class__, expected_test.tests[1].__class__)
        self.assertEqual(test.why_not({}, {}), "RejectAll")

    def test_or_true(self):
        """Test building "or" combinator."""
        policy = """
          {"or": [{"acceptall": {}}, {"rejectall": "RejectAll"}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.Or(tests.AcceptAll(), tests.RejectAll("RejectAll"))

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(len(test.tests), 2)
        self.assertEqual(test.tests[0].__class__, expected_test.tests[0].__class__)
        self.assertEqual(test.tests[1].__class__, expected_test.tests[1].__class__)
        self.assertEqual(test.why_not({}, {}), "")

    def test_or_false(self):
        """Test building "or" combinator."""
        policy = """
          {"or": [{"rejectall": "RejectAll1"}, {"rejectall": "RejectAll2"}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.Or(
            tests.RejectAll("RejectAll1"), tests.RejectAll("RejectAll2")
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(len(test.tests), 2)
        self.assertEqual(test.tests[0].__class__, expected_test.tests[0].__class__)
        self.assertEqual(test.tests[1].__class__, expected_test.tests[1].__class__)
        self.assertEqual(test.why_not({}, {}), "[RejectAll1, RejectAll2]")

    def test_dispatcher(self):
        """Test building "dispatcher" combinator."""
        policy = """
          {
            "dispatcher": {
              "keys": ["key1", "key2"],
              "tests": [
                {
                  "values": ["val1", "val2"],
                  "test": {"acceptall": {}}
                },
                {
                  "values": ["val3", "val4"],
                  "test": {"acceptall": {}}
                }
              ]
            }
          }
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.Dispatcher(("key1", "key2"))
        expected_test.set(("val1", "val2"), tests.AcceptAll())
        expected_test.set(("val3", "val4"), tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.key_names, expected_test.key_names)
        self.assertEqual(len(test.tests), 2)
        self.assertEqual(
            test.tests[("val1", "val2")].__class__,
            expected_test.tests[("val1", "val2")].__class__,
        )
        self.assertEqual(
            test.tests[("val3", "val4")].__class__,
            expected_test.tests[("val3", "val4")].__class__,
        )

        self.assertEqual(test.why_not({}, {"key1": "val1", "key2": "val2"}), "")
        self.assertEqual(test.why_not({}, {"key1": "val3", "key2": "val4"}), "")
        self.assertEqual(
            test.why_not({}, {"key1": "val5", "key2": "val6"}),
            "has unexpected ('key1', 'key2') combination ('val5', 'val6')",
        )
        self.assertEqual(test.why_not({}, {"key1": "val1"}), "has no key2")

    def test_fieldtest(self):
        """Test building "fieldtest" combinator."""
        policy = """
          {"fieldtest": {"field": "field1", "test": {"acceptall": {}}}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.FieldTest("field1", tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.field_name, expected_test.field_name)
        self.assertEqual(test.field_test.__class__, expected_test.field_test.__class__)

        self.assertEqual(test.why_not({}, {"field1": "val1"}), "")
        self.assertEqual(test.why_not({}, {"field2": "val1"}), "has no 'field1' field")

    def test_fieldstest(self):
        """Test building "fieldstest" combinator."""
        policy = """
          {
            "fieldstest": [
              {"field": "field1", "test": {"acceptall": {}}},
              {"field": "field2", "test": {"acceptall": {}}}
            ]
          }
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.FieldsTest(
            field1=tests.AcceptAll(), field2=tests.AcceptAll()
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(len(test.tests), 2)
        self.assertEqual(test.tests[0].__class__, expected_test.tests[0].__class__)
        self.assertEqual(test.tests[1].__class__, expected_test.tests[1].__class__)

        self.assertEqual(test.why_not({}, {"field1": "val1", "field2": "val2"}), "")
        self.assertEqual(test.why_not({}, {"field1": "val1"}), "has no 'field2' field")

    def test_iteratetest(self):
        """Test building "iteratetest" combinator."""
        policy = """
          {"iteratetest": {"acceptall": {}}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.IterateTest(tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.elt_test.__class__, expected_test.elt_test.__class__)

        self.assertEqual(test.why_not({}, []), "")
        self.assertEqual(test.why_not({}, [1, 2, 3]), "")

    def test_tupletest(self):
        """Test building "tupletest" combinator."""
        policy = """
          {"tupletest": [{"acceptall": {}}, {"acceptall": {}}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.TupleTest(tests.AcceptAll(), tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(len(test.member_tests), 2)
        self.assertEqual(
            test.member_tests[0].__class__, expected_test.member_tests[0].__class__
        )
        self.assertEqual(
            test.member_tests[1].__class__, expected_test.member_tests[1].__class__
        )

        self.assertEqual(test.why_not({}, [1, 2]), "")
        self.assertEqual(
            test.why_not({}, []), "is shorter (0) than the applicable tests (2)"
        )
        self.assertEqual(
            test.why_not({}, [1, 2, 3]), "is longer (3) than the applicable tests (2)"
        )

    def test_delayedfield(self):
        """Test building "delayedfield" combinator."""
        policy = """
          {"delayedfield": {"delayer": {"acceptall": {}}, "field": "field1"}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.DelayedField(tests.AcceptAll(), "field1")

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.delayer.__class__, expected_test.delayer.__class__)
        self.assertEqual(test.field_name, "field1")

        values = []
        self.assertEqual(test.why_not({"field1": values}, {}), "")
        self.assertEqual(values, [{}])
        self.assertEqual(
            test.why_not({"field1": {}}, {}),
            "malformed test: global field1 is not a list",
        )

    def test_delayinitializer(self):
        """Test building "delayinitializer" combinator."""
        policy = """
          {"delayinitializer": {"acceptall": {}}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.DelayInitializer(tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.delayer.__class__, expected_test.delayer.__class__)

    def test_delaytofields(self):
        """Test building "delaytofields" combinator."""
        policy = """
          {"delaytofields": {"test": {"acceptall": {}}, "fields": ["field1", "field2"]}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.DelayToFields(tests.AcceptAll(), "field1", "field2")

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.field_names, ("field1", "field2"))
        self.assertEqual(
            test.fields_test.__class__, expected_test.fields_test.__class__
        )

        self.assertEqual(test.why_not({}, {}), "")
        # TODO: better test of the evaluator, not sure how to use it

    def test_intequeal(self):
        """Test building "intequal" combinator."""
        policy = """
          {"intequal": 42}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.IntEqual(42)

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.expected, 42)

        self.assertEqual(test.why_not({}, 42), "")
        self.assertEqual(test.why_not({}, "42"), "is not an int")
        self.assertEqual(test.why_not({}, 43), "is not 42")

    def test_stringequeal(self):
        """Test building "stringequal" combinator."""
        policy = """
          {"stringequal": "hi"}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.StringEqual("hi")

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.expected, "hi")

        self.assertEqual(test.why_not({}, "hi"), "")
        self.assertEqual(test.why_not({}, 42), "is not a str")
        self.assertEqual(test.why_not({}, "bye"), "is not 'hi'")

    def test_regexp(self):
        """Test building "regexp" combinator."""
        policy = """
          {"regexp": "a.*"}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.RegExp(r"a.*")

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.regexp.pattern, r"a.*")

        self.assertEqual(test.why_not({}, "aa"), "")
        self.assertEqual(test.why_not({}, 42), "is not a str")
        self.assertEqual(test.why_not({}, "bb"), "does not match a.*")

    def test_digeststest(self):
        """Test building "digeststest" combinator."""
        policy = """
          {"digeststest": [
            {"md5": "5bb062356cddb5d2c0ef41eb2660cb06",
             "sha1": "5ce32910021e48c3c9dd983c12c44cf50297a332"},
            {"md5": "1b61f2a016f7478478fcb13130fcec7b",
             "sha1": "cd4bf5db2601ec9075425102d2b12a9ee5413d4a"}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.DigestsTest(
            [
                {
                    "md5": "5bb062356cddb5d2c0ef41eb2660cb06",
                    "sha1": "5ce32910021e48c3c9dd983c12c44cf50297a332",
                },
                {
                    "md5": "1b61f2a016f7478478fcb13130fcec7b",
                    "sha1": "cd4bf5db2601ec9075425102d2b12a9ee5413d4a",
                },
            ]
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(
            test.good_digests,
            {
                "md5": {
                    "5bb062356cddb5d2c0ef41eb2660cb06",
                    "1b61f2a016f7478478fcb13130fcec7b",
                },
                "sha1": {
                    "5ce32910021e48c3c9dd983c12c44cf50297a332",
                    "cd4bf5db2601ec9075425102d2b12a9ee5413d4a",
                },
            },
        )

        self.assertEqual(test.why_not({}, []), "is not a dict")
        self.assertEqual(test.why_not({}, {}), "has no Digests")
        self.assertEqual(test.why_not({}, {"Digests": {}}), "Digests is not a list")
        self.assertEqual(
            test.why_not({}, {"Digests": [1]}), "Digests[0] is 1, not a dict"
        )
        self.assertEqual(
            test.why_not({}, {"Digests": [{}]}), "digest 0 has no AlgorithmId"
        )
        self.assertEqual(
            test.why_not({}, {"Digests": [{"AlgorithmId": 1}]}),
            "Digests[0].AlgorithmId is 1, not a str",
        )
        self.assertEqual(
            test.why_not({}, {"Digests": [{"AlgorithmId": "md5"}]}),
            "digest 0 has no Digest",
        )
        self.assertEqual(
            test.why_not({}, {"Digests": [{"AlgorithmId": "md5", "Digest": 1}]}),
            "Digests[0].Digest is 1, not a str",
        )
        self.assertEqual(
            test.why_not(
                {},
                {
                    "Digests": [
                        {
                            "AlgorithmId": "md5",
                            "Digest": "5bb062356cddb5d2c0ef41eb2660cb06",
                        }
                    ]
                },
            ),
            "",
        )
        self.assertTrue(
            test.why_not(
                {}, {"Digests": [{"AlgorithmId": "md5", "Digest": ""}]}
            ).startswith("has no digest approved")
        )
        self.assertTrue(
            test.why_not({}, {"Digests": []}).startswith("has no digest approved")
        )

    def test_digesttest(self):
        """Test building "digesttest" combinator."""
        policy = """
          {"digesttest":
            {"md5": "5bb062356cddb5d2c0ef41eb2660cb06",
             "sha1": "5ce32910021e48c3c9dd983c12c44cf50297a332"}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.DigestTest(
            {
                "md5": "5bb062356cddb5d2c0ef41eb2660cb06",
                "sha1": "5ce32910021e48c3c9dd983c12c44cf50297a332",
            }
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(
            test.good_digests,
            {
                "md5": {"5bb062356cddb5d2c0ef41eb2660cb06"},
                "sha1": {"5ce32910021e48c3c9dd983c12c44cf50297a332"},
            },
        )

        self.assertEqual(
            test.why_not(
                {},
                {
                    "Digests": [
                        {
                            "AlgorithmId": "md5",
                            "Digest": "5bb062356cddb5d2c0ef41eb2660cb06",
                        }
                    ]
                },
            ),
            "",
        )
        self.assertTrue(
            test.why_not(
                {}, {"Digests": [{"AlgorithmId": "md5", "Digest": ""}]}
            ).startswith("has no digest approved")
        )

    def test_variabletest(self):
        """Test building "variabletest" combinator."""
        policy = """
          {"variabletest": {"variable": "var", "unicode": "var", "test": {"acceptall":{}}}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.VariableTest("var", "var", tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.variable_name, "var")
        self.assertEqual(test.unicode_name, "var")
        self.assertEqual(test.data_test.__class__, expected_test.data_test.__class__)

        self.assertEqual(test.why_not({}, []), "is not a dict")
        self.assertEqual(test.why_not({}, {}), "has no Event field")
        self.assertEqual(test.why_not({}, {"Event": []}), "Event is not a dict")
        self.assertEqual(
            test.why_not({}, {"Event": {}}), "Event has no VariableName field"
        )
        self.assertEqual(
            test.why_not({}, {"Event": {"VariableName": "foo"}}),
            "Event.VariableName is foo rather than var",
        )
        self.assertEqual(
            test.why_not({}, {"Event": {"VariableName": "var"}}),
            "Event has no UnicodeName field",
        )
        self.assertEqual(
            test.why_not({}, {"Event": {"VariableName": "var", "UnicodeName": ""}}),
            "Event has no VariableData field",
        )
        self.assertEqual(
            test.why_not(
                {},
                {
                    "Event": {
                        "VariableName": "var",
                        "UnicodeName": 1,
                        "VariableData": "",
                    }
                },
            ),
            "Event.UnicodeName is not a str",
        )
        self.assertEqual(
            test.why_not(
                {},
                {
                    "Event": {
                        "VariableName": "var",
                        "UnicodeName": "foo",
                        "VariableData": "",
                    }
                },
            ),
            "Event.UnicodeName is foo rather than var",
        )
        self.assertEqual(
            test.why_not(
                {},
                {
                    "Event": {
                        "VariableName": "var",
                        "UnicodeName": "var",
                        "VariableData": "",
                    }
                },
            ),
            "",
        )

    def test_variabledispatch(self):
        """Test building "variabledispatch" combinator."""
        policy = """
          {"variabledispatch": [
            {"variable": "var", "unicode": "var", "test": {"acceptall": {}}}
          ]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.VariableDispatch()
        expected_test.set("var", "var", tests.AcceptAll())

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "has no 'Event' field")
        self.assertEqual(
            test.why_not(
                {},
                {
                    "Event": {
                        "VariableName": "var",
                        "UnicodeName": "var",
                        "VariableData": "",
                    }
                },
            ),
            "",
        )

    def test_signaturetest(self):
        """Test building "signaturetest" combinator."""
        policy = """
          {"signaturetest": {"owner": "hash1", "data": "hash2"}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.SignatureTest("hash1", "hash2")

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "has no 'SignatureOwner' field")
        self.assertEqual(
            test.why_not(
                {},
                {
                    "SignatureOwner": "wrong1",
                    "SignatureData": "wrong2",
                },
            ),
            "SignatureOwner is not 'hash1'",
        )
        self.assertEqual(
            test.why_not(
                {},
                {
                    "SignatureOwner": "hash1",
                    "SignatureData": "hash2",
                },
            ),
            "",
        )

    def test_signaturesetmember(self):
        """Test building "signaturesetmember" combinator."""
        policy = """
          {"signaturesetmember": [{"owner": "hash1", "data": "hash2"}]}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.SignatureSetMember(
            [{"SignatureOwner": "hash1", "SignatureData": "hash2"}]
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "[has no 'SignatureOwner' field]")
        self.assertEqual(
            test.why_not(
                {},
                {
                    "SignatureOwner": "wrong1",
                    "SignatureData": "wrong2",
                },
            ),
            "[SignatureOwner is not 'hash1']",
        )
        self.assertEqual(
            test.why_not(
                {},
                {
                    "SignatureOwner": "hash1",
                    "SignatureData": "hash2",
                },
            ),
            "",
        )

    def test_keysubset(self):
        """Test building "keysubset" combinator."""
        policy = """
          {"keysubset": {"type": "uuid", "keys": [{"owner": "hash1", "data": "hash2"}]}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.KeySubset(
            "uuid", [{"SignatureOwner": "hash1", "SignatureData": "hash2"}]
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "is not a list")
        self.assertEqual(
            test.why_not(
                {},
                [
                    {
                        "SignatureType": "uuid",
                        "Keys": [
                            {
                                "SignatureOwner": "hash1",
                                "SignatureData": "hash2",
                            }
                        ],
                    }
                ],
            ),
            "",
        )

    def test_supersetofdicts(self):
        """Test building "supersetofdicts" combinator."""
        policy = """
          {"supersetofdicts": {"dicts": [{"f1": "a", "f2": "b"}, {"f1": "c", "f2": "d"}],
                               "fields": ["f1", "f2"]}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.SupersetOfDicts(
            [{"f1": "a", "f2": "b"}, {"f1": "c", "f2": "d"}], ("f1", "f2")
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.field_names, ("f1", "f2"))
        self.assertEqual(test.reqs, {("a", "b"), ("c", "d")})

        self.assertEqual(test.why_not({}, {}), "is not a list")
        self.assertEqual(test.why_not({}, [1]), "member 1 is not a dict")
        self.assertEqual(
            test.why_not({}, [{}]),
            "member {} does not have the right set of field names ('f1', 'f2')",
        )
        self.assertIn(
            test.why_not({}, [{"f1": "x", "f2": "y"}]),
            (
                "lacks ('f1', 'f2') combinations {('a', 'b'), ('c', 'd')}",
                "lacks ('f1', 'f2') combinations {('c', 'd'), ('a', 'b')}",
            ),
        )
        self.assertEqual(
            test.why_not({}, [{"f1": "a", "f2": "b"}]),
            "lacks ('f1', 'f2') combinations {('c', 'd')}",
        )
        self.assertEqual(
            test.why_not({}, [{"f1": "a", "f2": "b"}, {"f1": "c", "f2": "d"}]), ""
        )

    def test_keysuperset(self):
        """Test building "keysuperset" combinator."""
        policy = """
          {"keysuperset": {"type": "uuid", "keys": [{"owner": "hash1", "data": "hash2"}]}}
        """
        test = policies.Simple.from_json_str(policy)

        expected_test = tests.KeySuperset(
            "uuid", [{"SignatureOwner": "hash1", "SignatureData": "hash2"}]
        )

        self.assertEqual(test.__class__, expected_test.__class__)
        self.assertEqual(test.why_not({}, {}), "is not a list")
        self.assertEqual(
            test.why_not(
                {},
                [
                    {
                        "SignatureType": "uuid",
                        "Keys": [
                            {
                                "SignatureOwner": "hash1",
                                "SignatureData": "hash2",
                            }
                        ],
                    }
                ],
            ),
            "",
        )
