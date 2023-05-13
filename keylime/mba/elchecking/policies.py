import abc
import importlib
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
        return frozenset()

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        return tests.AcceptAll()


class RejectAll(Policy):
    """Policy that rejects all eventlogs"""

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return frozenset()

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        return tests.RejectAll("reject all")


def _mkreg() -> typing.Dict[str, Policy]:
    return {}


_registry = _mkreg()


def register(name: str, policy: Policy) -> None:
    """Remember the given policy under the given name"""
    _registry[name] = policy


register("accept-all", AcceptAll())
register("reject-all", RejectAll())


def get_policy_names() -> typing.List[str]:
    """Return the list of policy names"""
    return list(_registry.keys())


def get_policy(name: str) -> typing.Optional[Policy]:
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


def load_policies() -> None:
    imports = config.getlist("verifier", "measured_boot_imports")
    imports.append(".example")
    if imports:
        for imp in imports:
            if imp:
                importlib.import_module(imp, __package__)
