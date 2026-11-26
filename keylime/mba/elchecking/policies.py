import abc
import typing

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

    def get_relevant_pcrs_from_refstate(self, refstate: RefState) -> typing.FrozenSet[int]:
        """Reveal relevant PCR indices after reading the reference state."""
        _ = refstate
        return self.get_relevant_pcrs()

    def accepts_empty_refstate(self) -> bool:
        """Whether an empty or missing reference state is a valid configuration.

        ``accept-all`` tolerates an empty reference state; policies that must
        check content (``ordered-replay``, ``reject-all``) override this so an
        empty reference state is not silently treated as accept-all.
        """
        return True

    def requires_evaluation_every_quote(self) -> bool:
        """Whether the policy must run on every quote, not just the first one.

        ``measured_boot_evaluate = once`` skips evaluation after the first
        attestation. A policy that pins the reference state against each quote
        (``ordered-replay``, ``reject-all``) overrides this so a later quote
        presenting a different boot state is still compared.
        """
        return False

    def requires_log_bound_pcrs(self) -> bool:
        """Whether the policy needs the set of PCRs the quote bound to the log.

        ``ordered-replay`` compares reference values against PCRs the quote
        already matched to the event log, so it overrides this. When a caller
        omits that set, the evaluator rejects instead of falling back to the
        broad quote-PCR set, which would drop the value-matched requirement.
        """
        return False

    def validate_quote_bank(self, refstate: RefState, quote_hash_alg: typing.Optional[str]) -> str:
        """Return a reason if the quoted PCR bank does not satisfy the policy."""
        _ = (refstate, quote_hash_alg)
        return ""

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

    def accepts_empty_refstate(self) -> bool:
        return False

    def requires_evaluation_every_quote(self) -> bool:
        return True

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        return tests.RejectAll("reject all")


class OrderedReplay(Policy):
    """Match reference PCR values against the quote-bound, parser-calculated map."""

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return frozenset()

    def accepts_empty_refstate(self) -> bool:
        return False

    def requires_evaluation_every_quote(self) -> bool:
        return True

    def requires_log_bound_pcrs(self) -> bool:
        return True

    @staticmethod
    def _refstate_to_replay(refstate: RefState) -> tests.OrderedReplay:
        if not isinstance(refstate, dict):
            raise Exception(f"expected refstate to be a dict, got {refstate!r}")
        if "pcrs" not in refstate:
            raise Exception("refstate lacks pcrs")
        return tests.OrderedReplay(refstate["pcrs"])

    def get_relevant_pcrs_from_refstate(self, refstate: RefState) -> typing.FrozenSet[int]:
        replay = self._refstate_to_replay(refstate)
        return frozenset(pcr for bank in replay.expected.values() for pcr in bank)

    def validate_quote_bank(self, refstate: RefState, quote_hash_alg: typing.Optional[str]) -> str:
        replay = self._refstate_to_replay(refstate)
        reference_banks = set(replay.expected)
        if quote_hash_alg is None:
            return "the quote hash algorithm is unavailable"
        if reference_banks != {quote_hash_alg}:
            return f"reference PCR banks {sorted(reference_banks)} do not match quoted bank {quote_hash_alg}"
        return ""

    def refstate_to_test(self, refstate: RefState) -> tests.Test:
        return self._refstate_to_replay(refstate)


def _mkreg() -> typing.Dict[str, Policy]:
    return {}


_registry = _mkreg()


def register(name: str, policy: Policy) -> None:
    """Remember the given policy under the given name"""
    _registry[name] = policy


def unregister(name: str) -> None:
    """Remove the policy registered under the given name, if present"""
    _registry.pop(name, None)


register("accept-all", AcceptAll())
register("reject-all", RejectAll())
register("ordered-replay", OrderedReplay())


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
