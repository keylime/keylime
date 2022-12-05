import abc
import codecs
import re
import typing

from keylime.common.algorithms import Hash

# This module defines the abstraction of a Test (of JSON data)
# and several specific test classes.
# A Test can be used multiple times, even concurrently.

# Data is the type of Python data that corresponds to JSON values.
Data = typing.Union[
    int, float, str, bool, typing.Tuple["Data", ...], typing.Mapping[str, "Data"], typing.List["Data"], None
]

# Globals is a dict of variables for communication among tests.
# There is a distinct dict for each top-level use of a test.
Globals = typing.Dict[str, Data]

# PCR_Contents maps digest name to map from PCR index to PCR value.
# Here digest name is something like 'sha256'.
# Each PCR index is a decimal string, so that this can be JSON data
PCR_Contents = typing.Mapping[str, typing.Mapping[str, int]]


class Test(metaclass=abc.ABCMeta):
    """Test is something that can examine a value and either approve it or give a reason for rejection"""

    @abc.abstractmethod
    def why_not(self, globs: Globals, subject: Data) -> str:
        """Test the given value, return empty string for pass, explanation for fail.

        The explanation is (except in deliberate exceptions) English that
        makes a sentence when placed after a noun phrase identifying the subject.
        The test can read and write in the given globs dict.
        """
        raise NotImplementedError


# type_test constructs a test of data type that is expected to pass.
# This and the following are used to check reference state for bugs.
def type_test(t: typing.Type[typing.Any]) -> typing.Callable[[typing.Any], bool]:
    """Returns a lambda that tests against the given type.
    The lambda returns True on pass, raises Exception on fail."""

    def test(v: typing.Any) -> bool:
        if isinstance(v, t):
            return True
        raise Exception(f"{v!r} is a {type(v)} rather than a {t}")

    return test


def list_test(elt_test: typing.Callable[[typing.Any], bool]) -> typing.Callable[[typing.Any], bool]:
    """Return a lambda that tests for list with certain type of element"""

    def test(dat: typing.Any) -> bool:
        type_test(list)(dat)
        for elt in dat:
            elt_test(elt)
        return True

    return test


def dict_test(
    dom_test: typing.Callable[[typing.Any], bool], rng_test: typing.Callable[[typing.Any], bool]
) -> typing.Callable[[typing.Any], bool]:
    """Return a lambda that tests for dict with certain type key and value"""

    def test(dat: typing.Any) -> bool:
        type_test(dict)(dat)
        for dom, rng in dat.items():
            dom_test(dom)
            rng_test(rng)
        return True

    return test


def obj_test(**field_tests: typing.Callable[[typing.Any], bool]) -> typing.Callable[[typing.Any], bool]:
    """Return a lambda that tests for dict with string keys and a particular type for each key"""

    def test(dat: typing.Any) -> bool:
        type_test(dict)(dat)
        dom_test = type_test(str)
        for dom, rng in dat.items():
            dom_test(dom)
            if dom not in field_tests:
                continue
            rng_test = field_tests[dom]
            rng_test(rng)
        missing = set(field_tests.keys()) - set(dat.keys())
        if missing:
            raise Exception(f"{dat!r} lacks fields {missing}")
        return True

    return test


class AcceptAll(Test):
    """Every value passes this test"""

    def why_not(self, _: Globals, subject: Data) -> str:
        return ""


class RejectAll(Test):
    """No value passes this test"""

    def __init__(self, why: str):
        super().__init__()
        if not why:
            raise Exception(f"the truth value of {why!r} is false")
        self.why = why

    def why_not(self, _: Globals, subject: Data) -> str:
        return self.why


class And(Test):
    """Conjunction of given tests

    The tests are run in series, stopping as soon as one fails."""

    def __init__(self, *tests: Test):
        super().__init__()
        list(map(type_test(Test), tests))
        self.tests = tests

    def why_not(self, globs: Globals, subject: Data) -> str:
        for test in self.tests:
            reason = test.why_not(globs, subject)
            if reason:
                return reason
        return ""


class Or(Test):
    """Disjunction of given tests

    The tests are run in series, stopping as soon as one succeeds."""

    def __init__(self, *tests: Test):
        super().__init__()
        list(map(type_test(Test), tests))
        self.tests = tests

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not self.tests:
            return "does not pass empty disjunction"
        reasons = []
        for test in self.tests:
            reason = test.why_not(globs, subject)
            if not reason:
                return ""
            reasons.append(reason)
        return "[" + ", ".join(reasons) + "]"


class Dispatcher(Test):
    """Apply a specific test for each key tuple.

    This kind of test applies when the subject is a dict and
    it is desired to apply a different test depending on
    the value(s) of one or more entries."""

    key_names: typing.Tuple[str, ...]
    tests: typing.Dict[typing.Tuple[typing.Union[int, str], ...], Test]

    def __init__(self, key_names: typing.Tuple[str, ...]):
        """Initialize a Dispatcher Test.

        key_names identifies the subject dict entries that determine
        which subsidiary test to apply."""
        super().__init__()
        if len(key_names) < 1:
            raise Exception("Dispatcher given empty list of key names")
        list(map(type_test(str), key_names))
        self.key_names = key_names
        self.tests = {}

    def set(self, key_vals: typing.Tuple[typing.Union[int, str], ...], test: Test) -> None:
        """Set the test for the given value tuple"""
        if len(key_vals) != len(self.key_names):
            raise Exception(f"{key_vals!a} does not match length of {self.key_names}")
        if key_vals in self.tests:
            raise Exception(f"multiple tests for {key_vals!a}")
        self.tests[key_vals] = test

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not isinstance(subject, dict):
            return "is not a dict"
        key_vals: typing.Tuple[typing.Union[int, str], ...] = tuple()
        for kn in self.key_names:
            if kn not in subject:
                return f"has no {kn}"
            key_vals += (subject[kn],)
        test: typing.Optional[Test] = self.tests.get(key_vals)
        if test is None:
            return f"has unexpected {self.key_names} combination {key_vals}"
        return test.why_not(globs, subject)


class FieldTest(Test):
    """Applies given test to field having given name"""

    def __init__(self, field_name: str, field_test: Test, show_name: bool = True):
        super().__init__()
        type_test(str)(field_name)
        type_test(Test)(field_test)
        self.field_name = field_name
        self.field_test = field_test
        self.show_name = show_name

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not isinstance(subject, dict):
            return "is not a dict"
        if self.field_name not in subject:
            return f"has no {self.field_name!a} field"
        reason = self.field_test.why_not(globs, subject[self.field_name])
        if reason and self.show_name:
            return self.field_name + " " + reason
        return reason


class FieldsTest(And):
    """Tests a collection of fields"""

    def __init__(self, **fields: Test):
        tests = [FieldTest(field_name, field_test) for field_name, field_test in fields.items()]
        super().__init__(*tests)


class IterateTest(Test):
    """Applies a test to every member of a list"""

    def __init__(self, elt_test: Test, show_elt: bool = False):
        super().__init__()
        self.elt_test = elt_test
        self.show_elt = show_elt

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not isinstance(subject, list):
            return "is not a list"
        for idx, elt in enumerate(subject):
            reason = self.elt_test.why_not(globs, elt)
            if not reason:
                continue
            if self.show_elt:
                return f"{elt!a} " + reason
            return f"[{idx}] " + reason
        return ""


class TupleTest(Test):
    """Applies a sequence of tests to a sequence of values

    The tests are run in series, stopping as soon as one fails"""

    def __init__(self, *member_tests: Test, pad: bool = False):
        super().__init__()
        list(map(type_test(Test), member_tests))
        self.member_tests = member_tests
        self.pad = pad

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not isinstance(subject, list):
            return "is not a list"
        subject_len = len(subject)
        test_len = len(self.member_tests)
        if subject_len > test_len:
            return f" is longer ({subject_len}) than the applicable tests ({test_len})"
        if (subject_len < test_len) and not self.pad:
            return f" is shorter ({subject_len}) than the applicable tests ({test_len})"
        for idx, test in enumerate(self.member_tests):
            subject_elt = subject[idx] if idx < subject_len else None
            reason = test.why_not(globs, subject_elt)
            if reason:
                return f"[{idx}] " + reason
        return ""


class DelayedField(Test):
    """Remembers a field value for later testing"""

    def __init__(self, delayer: "DelayToFields", field_name: str):
        super().__init__()
        self.delayer = delayer
        self.field_name = field_name

    def why_not(self, globs: Globals, subject: Data) -> str:
        """Add the value to the list stashed for later testing"""
        val_list = globs[self.field_name]
        if not isinstance(val_list, list):
            return f"malformed test: global {self.field_name} is not a list"
        val_list.append(subject)
        return ""


class DelayInitializer(Test):
    """A Test that initializes the globals used by a DelayToFields and reports acceptance"""

    def __init__(self, delayer: "DelayToFields"):
        super().__init__()
        self.delayer = delayer

    def why_not(self, globs: Globals, subject: Data) -> str:
        self.delayer.initialize_globals(globs)
        return ""


class DelayToFields(Test):
    """A test to apply after stashing fields to test.

    For each field, accumulates a list of values
    in a correspondingly-named global.
    As a test, ignores the given subject and instead applies the
    configured fields_test to the record of accumulated value lists.
    """

    field_names: typing.Tuple[str, ...]
    fields_test: Test

    def __init__(self, fields_test: Test, *field_names: str):
        super().__init__()
        self.field_names = field_names
        self.fields_test = fields_test

    def initialize_globals(self, globs: Globals) -> None:
        """Initialize for a new pass over data"""
        for field_name in self.field_names:
            globs[field_name] = []

    def get_initializer(self) -> DelayInitializer:
        """Get a Test that accepts the subject and initializes the relevant globals"""
        return DelayInitializer(self)

    def get(self, field_name: str) -> DelayedField:
        """Return a Test that adds the subject to the list stashed for later evaulation"""
        if field_name not in self.field_names:
            raise Exception(f"{field_name} not in {self.field_names}")
        return DelayedField(self, field_name)

    def why_not(self, globs: Globals, subject: Data) -> str:
        """Test the stashed field values"""
        delayed = {}
        for field_name in self.field_names:
            delayed[field_name] = globs.get(field_name, None)
        return self.fields_test.why_not(globs, delayed)


class IntEqual(Test):
    """Compares with a given int"""

    def __init__(self, expected: int):
        super().__init__()
        type_test(int)(expected)
        self.expected = expected

    def why_not(self, _: Globals, subject: Data) -> str:
        if not isinstance(subject, int):
            return "is not a int"
        if subject == self.expected:
            return ""
        return f"is not {self.expected}"


class StringEqual(Test):
    """Compares with a given string"""

    def __init__(self, expected: str):
        super().__init__()
        type_test(str)(expected)
        self.expected = expected

    def why_not(self, _: Globals, subject: Data) -> str:
        if not isinstance(subject, str):
            return "is not a str"
        if subject == self.expected:
            return ""
        return f"is not {self.expected!a}"


class RegExp(Test):
    """Does a full match against a regular expression"""

    def __init__(self, pattern: str, flags: typing.Union[int, re.RegexFlag] = 0) -> None:
        super().__init__()
        self.regexp = re.compile(pattern, flags)

    def why_not(self, _: Globals, subject: Data) -> str:
        if not isinstance(subject, str):
            return "is not a str"
        if self.regexp.fullmatch(subject):
            return ""
        return f"does not match {self.regexp.pattern}"


# hash algorithm -> hash value in hex (sans leading 0x)
Digest = typing.Mapping[str, str]


class DigestsTest(Test):
    """Tests whether subject has a digest that is in a list of good ones"""

    good_digests: typing.Dict[str, typing.Set[str]]

    def __init__(self, good_digests_list: typing.Iterable[Digest]):
        """good_digests_list is a list of good {alg:hash}"""
        super().__init__()
        self.good_digests = {}
        "map from alg to set of good digests"
        for good_digests in good_digests_list:
            type_test(dict)(good_digests)
            for alg, hash_val in good_digests.items():
                if alg in self.good_digests:
                    self.good_digests[alg].add(hash_val)
                else:
                    self.good_digests[alg] = {hash_val}

    def why_not(self, _: Globals, subject: Data) -> str:
        if not isinstance(subject, dict):
            return "is not a dict"
        if "Digests" not in subject:
            return "has no Digests"
        digest_list = subject["Digests"]
        if not isinstance(digest_list, list):
            return "Digests is not a list"
        for idx, subject_digest in enumerate(digest_list):
            if not isinstance(subject_digest, dict):
                return f"Digests[{idx}] is {subject_digest!r}, not a dict"
            if "AlgorithmId" not in subject_digest:
                return f"digest {idx} has no AlgorithmId"
            alg = subject_digest["AlgorithmId"]
            if not isinstance(alg, str):
                return f"Digests[{idx}].AlgorithmId is {alg!r}, not a str"
            if "Digest" not in subject_digest:
                return f"digest {idx} has no Digest"
            hash_val = subject_digest["Digest"]
            if not isinstance(hash_val, str):
                return f"Digests[{idx}].Digest is {hash_val!r}, not a str"
            if alg not in self.good_digests:
                continue
            if hash_val in self.good_digests[alg]:
                return ""
        return f"has no digest approved by {self.good_digests}"


class DigestTest(DigestsTest):
    """Tests whether subject has a digest that equals a given one"""

    def __init__(self, good_digest: Digest):
        super().__init__([good_digest])


StrOrRE = typing.Union[str, typing.Pattern]


class VariableTest(Test):
    """Test whether a given variable has value passing given test"""

    def __init__(self, variable_name: str, unicode_name: StrOrRE, data_test: Test):
        """variable_name and unicode_name are as in the parsed event; data_test applies to VariableData"""
        super().__init__()
        self.variable_name = variable_name
        # pylint: disable=isinstance-second-argument-not-valid-type
        if not isinstance(unicode_name, (str, typing.Pattern)):
            # pylint: enable=isinstance-second-argument-not-valid-type
            raise Exception(f"unicode_name={unicode_name!r} is neither a str nor an re.Pattern")
        self.unicode_name = unicode_name
        self.data_test = data_test

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not isinstance(subject, dict):
            return "is not a dict"
        if "Event" not in subject:
            return "has no Event field"
        evt = subject["Event"]
        if not isinstance(evt, dict):
            return "Event is not a dict"
        if "VariableName" not in evt:
            return "Event has no VariableName field"
        variable_name = evt["VariableName"]
        if variable_name != self.variable_name:
            return f"Event.VariableName is {variable_name} rather than {self.variable_name}"
        if "UnicodeName" not in evt:
            return "Event has no UnicodeName field"
        unicode_name = evt["UnicodeName"]
        if "VariableData" not in evt:
            return "Event has no VariableData field"
        if not isinstance(unicode_name, str):
            return "Event.UnicodeName is not a str"
        variable_data = evt["VariableData"]
        if isinstance(self.unicode_name, str):
            if unicode_name != self.unicode_name:
                return f"Event.UnicodeName is {unicode_name} rather than {self.unicode_name}"
        elif not self.unicode_name.fullmatch(unicode_name):
            return f"Event.UnicodeName, {unicode_name}, does not match {self.unicode_name.pattern}"
        return self.data_test.why_not(globs, variable_data)


class VariableDispatch(FieldTest):
    """Do a specific test for each variable"""

    vd: Dispatcher

    def __init__(self) -> None:
        self.vd = Dispatcher(("VariableName", "UnicodeName"))
        super().__init__("Event", self.vd)

    def set(self, variable_name: str, unicode_name: str, data_test: Test) -> None:
        """Define the test for a specific variable"""
        self.vd.set((variable_name, unicode_name), FieldTest("VariableData", data_test))


# Signature has the following fields.
# - SignatureOwner, value is a string UUID
# - SignatureData, value is a hex string without leading 0x


Signature = typing.Mapping[str, str]


class SignatureTest(And):
    """Compares to a particular signature"""

    def __init__(self, owner: str, data: str):
        """owner is SignatureOwner, data is SignatureData"""
        super().__init__(FieldTest("SignatureOwner", StringEqual(owner)), FieldTest("SignatureData", StringEqual(data)))


class SignatureSetMember(Or):
    """Tests for membership in the given list of signatures"""

    def __init__(self, sigs: typing.Iterable[Signature]):
        tests = [SignatureTest(sig["SignatureOwner"], sig["SignatureData"]) for sig in sigs]
        super().__init__(*tests)


class KeySubset(IterateTest):
    def __init__(self, sig_type: str, keys: typing.Iterable[typing.Mapping[str, str]]):
        super().__init__(
            And(
                FieldTest("SignatureType", StringEqual(sig_type)),
                FieldTest("Keys", IterateTest(SignatureSetMember(keys))),
            )
        )


class FieldsMismatchError(Exception):
    """Represents a mismatch between expected and actual sets of field names."""

    def __init__(self, expected: typing.Set[str], actual: typing.Set[str]) -> None:
        """Constructor."""
        super().__init__(expected, actual)
        type_test(set)(expected)
        type_test(set)(actual)
        list(map(type_test(str), expected))
        list(map(type_test(str), actual))
        self.expected = expected
        self.actual = actual

    def __str__(self) -> str:
        return f"expected fields {self.expected} but got {self.actual}"


class SupersetOfDicts(Test):
    """Tests that the subject is a list of dicts with at least certain members

    All dicts must have the same field names"""

    @staticmethod
    def dict_to_tuple(it: typing.Mapping[str, Data], field_names: typing.Tuple[str, ...]) -> typing.Tuple[Data, ...]:
        actual_keys = set(it.keys())
        expected_keys = set(field_names)
        if actual_keys != expected_keys:
            raise FieldsMismatchError(expected_keys, actual_keys)
        return tuple(it.get(field_name) for field_name in field_names)

    def __init__(self, reqs: typing.Iterable[typing.Mapping[str, Data]], field_names: typing.Tuple[str, ...]):
        list(map(type_test(dict), reqs))
        type_test(tuple)(field_names)
        list(map(type_test(str), field_names))
        self.field_names = field_names
        self.reqs = {SupersetOfDicts.dict_to_tuple(req, field_names) for req in reqs}

    def why_not(self, globs: Globals, subject: Data) -> str:
        if not isinstance(subject, list):
            return "is not a list"
        actual = set()
        for elt in subject:
            if not isinstance(elt, dict):
                return f"member {elt} is not a dict"
            try:
                tup = SupersetOfDicts.dict_to_tuple(elt, self.field_names)
            except FieldsMismatchError:
                return f"member {elt!r} does not have the right set of field names {self.field_names}"
            actual.add(tup)
        missing = self.reqs - actual
        if not missing:
            return ""
        return f"lacks {self.field_names} combinations {missing}"


class KeySuperset(TupleTest):
    """Tests that there is one Keys dict containing at least certain members"""

    def __init__(self, sig_type: str, keys: typing.Iterable[Signature]):
        super().__init__(
            And(
                FieldTest("SignatureType", StringEqual(sig_type)),
                FieldTest("Keys", SupersetOfDicts(keys, ("SignatureOwner", "SignatureData"))),
            )
        )


class OnceTest(Test):
    """Tests that only works once"""

    def __init__(self, test: Test):
        self.executed = False
        self.test = test

    def why_not(self, globs: Globals, subject: Data) -> str:
        if self.executed:
            return "test was already run once"

        self.executed = True
        return self.test.why_not(globs, subject)


# Following tests are TCG PC Client Platform specific, but are common and reduce the use of AcceptAll


class EvSeperatorTest(Or):
    """Test for valid EV_SEPARATOR entry values"""

    def __init__(self) -> None:
        # See TCG PC Client Platform Firmware Profile (Table 9 Events)
        valid_hex_values = ["00000000", "FFFFFFFF"]
        tests = []
        for value in valid_hex_values:
            val_bytes = codecs.decode(value.encode(), "hex")
            event_test = FieldTest("Event", StringEqual(value))
            digests = {}
            for hash_alg in Hash:
                digests[str(hash_alg)] = codecs.encode(hash_alg.hash(val_bytes), "hex").decode("utf-8")
            tests.append(And(event_test, DigestTest(digests)))
        super().__init__(*tests)


class EvEfiActionTest(Test):
    """Test for valid EV_EFI_ACTION entry values"""

    _expected_strings = {
        4: ["Calling EFI Application from Boot Option", "Returning from EFI Application from Boot Option"],
        5: [
            "Exit Boot Services Invocation",
            "Exit Boot Services Returned with Failure",
            "Exit Boot Services Returned with Success",
        ],
        6: ["UEFI Debug Mode"],
    }

    def __init__(self, pcr: int):
        self.pcr = pcr
        if pcr not in self._expected_strings:
            self.test = None
            return

        tests = []
        for value in self._expected_strings[pcr]:
            event_test = FieldTest("Event", StringEqual(value))
            digests = {}
            for hash_alg in Hash:
                digests[str(hash_alg)] = codecs.encode(hash_alg.hash(value.encode()), "hex").decode("utf-8")
            tests.append(And(event_test, DigestTest(digests)))
        self.test = Or(*tests)

    def why_not(self, globs: Globals, subject: Data) -> str:
        if self.test is None:
            return f"No EV_EFI_ACTION event for {self.pcr} is expected in the spec"

        return self.test.why_not(globs, subject)
