import abc
import importlib
import json
import typing

from keylime import config

from . import tests

# This module defines Policy for testing measured boot logs.
# This module also implements a registry of policies and a few trivial
# policies.

# RefState is a succinct description of what is expected to be found
# in a measured boot log.  A Policy maps one of these to the
# corresponding Test.
RefState = typing.Mapping[str, tests.Data]


# Policy maps RefState expressed in some convenient form into the
# corresponding Test to apply to the log.  The log is Python data
# corresponding to JSON, and is the result of parsing and enriching.
class Policy(metaclass=abc.ABCMeta):
    """Policy can compile RefState into a Test"""

    @abc.abstractmethod
    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        """Reveal the set of relevant PCR indices"""
        raise NotImplementedError

    @abc.abstractmethod
    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        """Convert the given RefState into a precise Test"""
        raise NotImplementedError

    def evaluate(self, refstate: RefState, eventlog: tests.Data) -> str:
        """Evaluate and return the reason for rejection or empty string for accept"""
        tester = self.refstate_to_test(refstate)
        return tester.why_not({}, eventlog)


class AcceptAll(Policy):
    """Policy that accepts all eventlogs"""

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return set()

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        return tests.AcceptAll()


class Simple(Policy):
    """Simple policy that is a direct transation of tests combinators."""

    @staticmethod
    def from_json(policy_file):
        """Construct the policy from a JSON file."""
        with open(policy_file, "r", encoding="utf-8") as fp:
            return Simple._refstate_to_test(json.load(fp))

    @staticmethod
    def from_json_str(policy_str):
        """Construct the policy from a JSON string."""
        return Simple._refstate_to_test(json.loads(policy_str))

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return set(range(0, 24))

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        """Construct the policy from a RefState."""
        return Simple._refstate_to_test(refstate)

    @staticmethod
    def _refstate_to_test(refstate: RefState) -> tests.Test:
        for test in refstate:
            if hasattr(Simple, f"_{test}"):
                return getattr(Simple, f"_{test}")(refstate)
            raise Exception(f"Test {test} not found")
        return tests.AcceptAll()

    @staticmethod
    def _acceptall(_: RefState) -> tests.Test:
        # Example: {"acceptall": {}}
        return tests.AcceptAll()

    @staticmethod
    def _rejectall(refstate: RefState) -> tests.Test:
        # Example: {"rejectall": "RejectAll"}
        return tests.RejectAll(refstate["rejectall"])

    @staticmethod
    def _and(refstate: RefState) -> tests.Test:
        # Example: {"and": [{"acceptall": {}}, {"acceptall": {}}]}
        return tests.And(*[Simple._refstate_to_test(t) for t in refstate["and"]])

    @staticmethod
    def _or(refstate: RefState) -> tests.Test:
        # Example: {"or": [{"acceptall": {}}, {"acceptall": {}}]}
        return tests.Or(*[Simple._refstate_to_test(t) for t in refstate["or"]])

    @staticmethod
    def _dispatcher(refstate: RefState) -> tests.Test:
        # Example:
        #   {"dispatcher": {"keys": ["key1"],
        #                   "tests": [{"values": ["val1"], "test": {"acceptall": {}}}]}
        dispatcher = tests.Dispatcher(tuple(refstate["dispatcher"]["keys"]))
        for test in refstate["dispatcher"]["tests"]:
            dispatcher.set(
                tuple(test["values"]), Simple._refstate_to_test(test["test"])
            )
        return dispatcher

    @staticmethod
    def _fieldtest(refstate: RefState) -> tests.Test:
        # Example: {"fieldtest": {"field": "field1", "test": {"acceptall": {}}}}
        return tests.FieldTest(
            refstate["fieldtest"]["field"],
            Simple._refstate_to_test(refstate["fieldtest"]["test"]),
        )

    @staticmethod
    def _fieldstest(refstate: RefState) -> tests.Test:
        # Example: {"fieldstest": [{"field": "field1", "test": {"acceptall": {}}}]}
        return tests.FieldsTest(
            **{
                t["field"]: Simple._refstate_to_test(t["test"])
                for t in refstate["fieldstest"]
            }
        )

    @staticmethod
    def _iteratetest(refstate: RefState) -> tests.Test:
        # Example: {"iteratetest": {"acceptall": {}}}
        return tests.IterateTest(Simple._refstate_to_test(refstate["iteratetest"]))

    @staticmethod
    def _tupletest(refstate: RefState) -> tests.Test:
        # Example: {"tupletest": [{"acceptall": {}}]}
        return tests.TupleTest(
            *[Simple._refstate_to_test(t) for t in refstate["tupletest"]]
        )

    @staticmethod
    def _delayedfield(refstate: RefState) -> tests.Test:
        # Example: {"delayedfield": {"delayer": {...}, "field": "field1"}}
        return tests.DelayedField(
            Simple._refstate_to_test(refstate["delayedfield"]["delayer"]),
            refstate["delayedfield"]["field"],
        )

    @staticmethod
    def _delayinitializer(refstate: RefState) -> tests.Test:
        # Example: {"delayinitializer": {...}}
        return tests.DelayInitializer(
            Simple._refstate_to_test(refstate["delayinitializer"])
        )

    @staticmethod
    def _delaytofields(refstate: RefState) -> tests.Test:
        # Example:
        #  {"delaytofields": {"test": {"acceptall": {}}, "fields": ["field1", "field2"]}}
        return tests.DelayToFields(
            Simple._refstate_to_test(refstate["delaytofields"]["test"]),
            *refstate["delaytofields"]["fields"],
        )

    @staticmethod
    def _intequal(refstate: RefState) -> tests.Test:
        # Example: {"intequal": 42}
        return tests.IntEqual(int(refstate["intequal"]))

    @staticmethod
    def _stringequal(refstate: RefState) -> tests.Test:
        # Example: {"stringequal": "hi"}
        return tests.StringEqual(str(refstate["stringequal"]))

    @staticmethod
    def _regexp(refstate: RefState) -> tests.Test:
        # Example: {"regexp": "a.*"}
        return tests.RegExp(str(refstate["regexp"]))

    @staticmethod
    def _digeststest(refstate: RefState) -> tests.Test:
        # Example: {"digeststest": [{"md5": "5bb0...", "sha1": "5ce3..."}]}
        return tests.DigestsTest(refstate["digeststest"])

    @staticmethod
    def _digesttest(refstate: RefState) -> tests.Test:
        # Example: {"digesttest": {"md5": "5bb0...", "sha1": "5ce3..."}}
        return tests.DigestTest(refstate["digesttest"])

    @staticmethod
    def _variabletest(refstate: RefState) -> tests.Test:
        # Example: {"variabletest": {"variable": "...", "unicode": "...", "test": {}}}
        return tests.VariableTest(
            refstate["variabletest"]["variable"],
            refstate["variabletest"]["unicode"],
            Simple._refstate_to_test(refstate["variabletest"]["test"]),
        )

    @staticmethod
    def _variabledispatch(refstate: RefState) -> tests.Test:
        # Example: {"variabledispatch": [{"variable": "...", "unicode": "...", "test": {}}]}
        variabledispatch = tests.VariableDispatch()
        for variabletest in refstate["variabledispatch"]:
            variabledispatch.set(
                variabletest["variable"],
                variabletest["unicode"],
                Simple._refstate_to_test(variabletest["test"]),
            )
        return variabledispatch

    @staticmethod
    def _signaturetest(refstate: RefState) -> tests.Test:
        # Example: {"signaturetest": {"owner": "5bb0...", "data": "5ce3..."}}
        return tests.SignatureTest(
            refstate["signaturetest"]["owner"], refstate["signaturetest"]["data"]
        )

    @staticmethod
    def _signaturesetmember(refstate: RefState) -> tests.Test:
        # Example: {"signaturesetmember": [{"owner": "5bb0...", "data": "5ce3..."}]}
        return tests.SignatureSetMember(
            [
                {"SignatureOwner": s["owner"], "SignatureData": s["data"]}
                for s in refstate["signaturesetmember"]
            ]
        )

    @staticmethod
    def _keysubset(refstate: RefState) -> tests.Test:
        # Example: {"keysubset": {"type": "uuid",
        #                         "keys": [{"owner": "5bb0...", "data": "5ce3..."}]}}
        return tests.KeySubset(
            refstate["keysubset"]["type"],
            [
                {"SignatureOwner": k["owner"], "SignatureData": k["data"]}
                for k in refstate["keysubset"]["keys"]
            ],
        )

    @staticmethod
    def _supersetofdicts(refstate: RefState) -> tests.Test:
        # Example: {"supersetofdicts": {"dicts": [{"f1": "", "f2": ""}, {...}],
        #                               "fields": ["f1", "f2"]}}
        return tests.SupersetOfDicts(
            refstate["supersetofdicts"]["dicts"],
            tuple(refstate["supersetofdicts"]["fields"]),
        )

    @staticmethod
    def _keysuperset(refstate: RefState) -> tests.Test:
        # Example: {"keysuperset": {"type": "uuid",
        #                           "keys": [{"owner": "5bb0...", "data": "5ce3..."}]}}
        return tests.KeySuperset(
            refstate["keysuperset"]["type"],
            [
                {"SignatureOwner": k["owner"], "SignatureData": k["data"]}
                for k in refstate["keysuperset"]["keys"]
            ],
        )


def _mkreg() -> typing.Mapping[str, Policy]:
    return {}


_registry = _mkreg()


def register(name: str, policy: Policy):
    """Remember the given policy under the given name"""
    _registry[name] = policy


register("accept-all", AcceptAll())


def get_policy_names() -> typing.Tuple[str, ...]:
    """Return the list of policy names"""
    return list(_registry.keys())


def get_policy(name: str) -> Policy:
    """Returns the Policy with the given name, None if there is none"""
    return _registry.get(name)


def refstate_to_test(policy_name: str, refstate: RefState) -> tests.Test:
    """Compiles the given RefState into the Test prescribed by the named policy"""
    policy = get_policy(policy_name)
    if policy is None:
        raise Exception(f"there is no policy named {policy_name!a}")
    return policy.refstate_to_test(refstate)


def evaluate(policy_name: str, refstate: RefState, eventlog: tests.Data) -> str:
    """Evaluate the given eventlog using given refstate and policy

    Returns either:
    (a) an empty string to signal a good result or
    (b) a non-empty string identifying something wrong.
    """
    tester = refstate_to_test(policy_name, refstate)
    return tester.why_not({}, eventlog)


imports = config.MEASUREDBOOT_IMPORTS
# print(f'importing {imports!r}, __package__={__package__!r}')
for imp in imports:
    if imp:
        importlib.import_module(imp, __package__)
