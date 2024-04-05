#!/usr/bin/env python

from abc import ABC, abstractmethod
from enum import Enum
from typing import Callable, Dict, List, Optional, Pattern, Tuple, Type

from keylime import keylime_logging
from keylime.common import validators
from keylime.failure import Component, Failure
from keylime.ima import ast, file_signatures
from keylime.ima.file_signatures import ImaKeyrings
from keylime.ima.types import RuntimePolicyType

logger = keylime_logging.init_logging("ima-policy")


class EvalResult(Enum):
    ACCEPT = 1
    REJECT = 2
    SKIP = 3  # move to next rules


TARGET_TO_EVAL_RESULT: Dict[str, EvalResult] = {
    "ACCEPT": EvalResult.ACCEPT,
    "REJECT": EvalResult.REJECT,
}


class IMAPolicyError(Exception):
    pass


def kvps_to_dict(
    kvps: str,
    allowed_keys: List[str],
    single_use_keys: List[str],
    required_keys_list: Optional[List[List[str]]],
    rulename: str,
) -> Dict[str, List[str]]:
    """Convert key-value pairs to a Dict"""
    result: Dict[str, List[str]] = {}

    for kvp in kvps.split(" "):
        kvp = kvp.strip()
        if "=" in kvp:
            key, value = kvp.split("=", 1)
            if key not in allowed_keys:
                raise IMAPolicyError(f"Unsupported parameter '{key}' for {rulename}")

            values = result.get(key, [])
            if len(values) == 1 and key in single_use_keys:
                raise IMAPolicyError(f"{key} is only allowed to be passed once in {rulename}")
            values.append(value.strip())
            result[key] = values
        else:
            if kvp:
                raise IMAPolicyError(f"{kvp} is not a valid key=value pair")

    if required_keys_list:
        found = False
        for required_keys in required_keys_list:
            required_keys = required_keys.copy()
            for key in result:
                if key in required_keys:
                    required_keys.remove(key)
            if len(required_keys) == 0:
                found = True
                break
        if not found:
            raise IMAPolicyError(
                f"Missing required attribute for {rulename}: {' or '.join([', '.join(rk) for rk in required_keys_list])}"
            )
    return result


def target_to_eval_result(target: str) -> EvalResult:
    try:
        return TARGET_TO_EVAL_RESULT[target]
    except KeyError as exc:
        raise IMAPolicyError(f"Unsupported target {target}") from exc


class CompiledRegexList:
    """A list of regular expressions"""

    compiled_regexs: List[Tuple[Pattern[str], EvalResult]]

    def __init__(self, compiled_regexs: List[Tuple[Pattern[str], EvalResult]]):
        self.compiled_regexs = compiled_regexs

    def __len__(self) -> int:
        return len(self.compiled_regexs)

    @staticmethod
    def __compile_rules(regex_list: List[str], eval_result: str) -> Tuple[Pattern[str], EvalResult]:
        compiled_regex, err_msg = validators.valid_exclude_list(regex_list)
        if err_msg:
            raise IMAPolicyError(err_msg)
        if not compiled_regex:
            raise IMAPolicyError(f"Could not get a compiled regex from regex list '{regex_list}'")
        er = {
            "ACCEPT": EvalResult.ACCEPT,
            "REJECT": EvalResult.REJECT,
        }[eval_result]
        return (compiled_regex, er)

    @staticmethod
    def from_excludelist(exclude_list: Optional[List[str]]) -> "CompiledRegexList":
        """
        Create a CompilleRegexList from an exclude list where none of the
        list items has the prefix 'ACCEPT'
        """
        if exclude_list and len(exclude_list) > 0:
            return CompiledRegexList([CompiledRegexList.__compile_rules(exclude_list, "ACCEPT")])
        return CompiledRegexList([])

    @staticmethod
    def from_list(rule_list: List[str]) -> "CompiledRegexList":
        """
        Create a CompiledRegexList from a list where each regex must be prefixed
        with either ACCEPT: or REJECT:. For more efficient processing bunch
        consecutive ACCEPT or REJECT regexs.
        """
        eval_result = "ACCEPT"
        rules: List[str] = []
        comp_rules: List[Tuple[Pattern[str], EvalResult]] = []

        for rule in rule_list:
            elems = rule.split(":", 1)
            if len(elems) != 2 or elems[0] not in ["ACCEPT", "REJECT"]:
                raise IMAPolicyError("List element must start with 'ACCEPT:' or 'REJECT:'")

            if elems[0] != eval_result:
                if rules:
                    comp_rules.append(CompiledRegexList.__compile_rules(rules, eval_result))

                eval_result = elems[0]
                rules = []

            rules.append(elems[1])

        if rules:
            comp_rules.append(CompiledRegexList.__compile_rules(rules, eval_result))

        return CompiledRegexList(comp_rules)

    def eval(self, pathname: str) -> EvalResult:
        for regex, eval_result in self.compiled_regexs:
            if regex.match(pathname):
                return eval_result
        return EvalResult.SKIP


class ABCPolicy(ABC):
    @abstractmethod
    def get_regex_list(self, listname: str) -> Optional[CompiledRegexList]:
        pass

    @abstractmethod
    def get_map(self, mapname: str) -> Optional[Dict[str, List[str]]]:
        pass


class ABCRule(ABC):
    rulename: str
    rawparams: str
    parameters: Dict[str, List[str]]

    def __init__(self, rulename: str, rawparams: str):
        self.rulename = rulename
        self.rawparams = rawparams
        self.parameters = {}

    def __str__(self) -> str:
        if self.rawparams:
            return f"{self.rulename}: {self.rawparams}"
        return f"{self.rulename}:"

    @staticmethod
    @abstractmethod
    def from_string(rawparams: str) -> "ABCRule":
        pass

    @abstractmethod
    def setup(self, policy: ABCPolicy) -> None:
        pass


class Evaluator:
    functions: Dict[Type["ABCRule"], Callable[..., Tuple[EvalResult, Optional[Failure]]]]

    def __init__(self, functions: Dict[Type["ABCRule"], Callable[..., Tuple[EvalResult, Optional[Failure]]]]):
        self.functions = functions

    def get_evaluator(self, class_type: Type["ABCRule"]) -> Callable[..., Tuple[EvalResult, Optional[Failure]]]:
        evaluator = self.functions.get(class_type, None)
        if evaluator is None:
            logger.warning("No evaluator was implemented for: %s. Using always false evaluator!", class_type)
            failure = Failure(Component.IMA, ["validation"])
            failure.add_event(
                "no_evaluator", f"No evaluator was implemented for: {class_type} . Using always false evaluator!", True
            )
            return lambda *_: (EvalResult.SKIP, failure)
        return evaluator


class FileNames(ABCRule):
    """
    FileNames represents a 'FILE-NAMES: regex-ref=<listname>' rule. The listname refers to a list
    where each entry is a regex prefixed by eiter ACCEPT: or REJECT:
    """

    comp_regex_list: Optional[CompiledRegexList]

    def __init__(self, rawparams: str, parameters: Dict[str, List[str]]):
        super().__init__("FILE-NAMES", rawparams)
        self.parameters = parameters
        self.comp_regex_list = None

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        parameters = kvps_to_dict(rawparams, ["regex-ref"], ["regex-ref"], [["regex-ref"]], "FILE-NAMES")
        return FileNames(rawparams, parameters)

    def setup(self, policy: ABCPolicy) -> None:
        self.comp_regex_list = policy.get_regex_list(self.parameters["regex-ref"][0])

    def eval(self, path: ast.Name) -> Tuple[EvalResult, Optional[Failure]]:
        if not self.comp_regex_list:
            return EvalResult.SKIP, None

        failure = Failure(Component.IMA)
        ret = self.comp_regex_list.eval(path.name)
        if ret in [EvalResult.REJECT]:
            failure.add_event("rejected_by_file_names_rule", f"{path.name} was rejected by FILE-NAMES rule", True)
        return ret, failure


def filenamefilter_eval(
    _digest: ast.Digest,
    path: ast.Name,
    _signature: Optional[ast.Signature],
    _data: Optional[ast.Buffer],
    rule: FileNames,
) -> Tuple[EvalResult, Optional[Failure]]:
    return rule.eval(path)


class FileHashes(ABCRule):
    """
    FileHashes represents a 'FILE-HASHES: map-ref=<mapname> target=<ACCEPT|REJECT>' rule.
    """

    parameters: Dict[str, List[str]]
    target: EvalResult
    filehashesmap: Optional[Dict[str, List[str]]]

    def __init__(self, rawparams: str, parameters: Dict[str, List[str]], target: EvalResult):
        super().__init__("FILE-HASHES", rawparams)
        self.parameters = parameters
        self.target = target
        self.filehashesmap = {}

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        parameters = kvps_to_dict(rawparams, ["map-ref", "target"], ["map-ref", "target"], [["map-ref", "target"]], "FILE-HASHES")
        target = target_to_eval_result(parameters["target"][0])
        return FileHashes(rawparams, parameters, target)

    def setup(self, policy: ABCPolicy) -> None:
        self.filehashesmap = policy.get_map(self.parameters["map-ref"][0])

    def eval(self, digest: ast.Digest, path: ast.Name) -> Tuple[EvalResult, Optional[Failure]]:
        if not self.filehashesmap:
            return EvalResult.SKIP, None

        hashes_list = self.filehashesmap.get(path.name, None)
        if not hashes_list:
            return EvalResult.SKIP, None

        hex_hash = digest.hash.hex()
        if hex_hash in hashes_list:
            if self.target in [EvalResult.REJECT]:
                failure = Failure(Component.IMA)
                failure.add_event("rejected_by_file_hashes_rule", f"{path.name} was rejected by FILE-HASHES rule", True)
                return self.target, failure
            return self.target, None

        return EvalResult.SKIP, None


def filehashesfilter_eval(
    digest: ast.Digest,
    path: ast.Name,
    _signature: Optional[ast.Signature],
    _data: Optional[ast.Buffer],
    rule: FileHashes,
) -> Tuple[EvalResult, Optional[Failure]]:
    return rule.eval(digest, path)


class ImaSignatureCheck(ABCRule):
    """ImaSignatureCheck represents an IMA-SIGNATURE-CHECK rule"""

    def __init__(self) -> None:
        super().__init__("IMA-SIGNATURE-CHECK", "")

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        if len(rawparams) > 0:
            raise IMAPolicyError("IMA-SIGNATURE-CHECK does not support any parameters")
        return ImaSignatureCheck()

    def setup(self, policy: ABCPolicy) -> None:
        pass

    @staticmethod
    def eval(
        ima_keyrings: Optional[file_signatures.ImaKeyrings],
        digest: ast.Digest,
        path: ast.Name,
        signature: Optional[ast.Signature],
    ) -> EvalResult:
        if ima_keyrings and signature:
            if ima_keyrings.integrity_digsig_verify(signature.data, digest.hash, digest.algorithm):
                logger.debug("signature for file %s is good", path)
                return EvalResult.ACCEPT

        return EvalResult.SKIP


def ima_signature_check_eval(
    ima_keyrings: Optional[file_signatures.ImaKeyrings],
    digest: ast.Digest,
    path: ast.Name,
    signature: Optional[ast.Signature],
    _data: Optional[ast.Buffer],
    _rule: ImaSignatureCheck,
) -> Tuple[EvalResult, Optional[Failure]]:
    return ImaSignatureCheck.eval(ima_keyrings, digest, path, signature), None


class IMAPolicy(ABCPolicy):
    MAPPINGS: Dict[str, Type[ABCRule]] = {
        "IMA-SIGNATURE-CHECK": ImaSignatureCheck,
        "FILE-HASHES": FileHashes,
        "FILE-NAMES": FileNames,
    }
    DEFAULT_POLICY_STR: str = (
        "FILE-NAMES: regex-ref=excludes\n"
        "IMA-SIGNATURE-CHECK\n"
        "FILE-HASHES: map-ref=digests target=ACCEPT\n"
    )

    rules: List[ABCRule]
    runtime_policy: Optional[RuntimePolicyType]
    regex_list: Dict[str, CompiledRegexList]

    def __init__(self, rules: List[ABCRule], runtime_policy: Optional[RuntimePolicyType]):
        self.rules = rules
        self.runtime_policy = runtime_policy
        self.regex_list = {}
        self.__setup_rules()

    def __setup_rules(self) -> None:
        """Call setup on all rules to detect errors early on"""
        for rule in self.rules:
            rule.setup(self)

    @staticmethod
    def from_string(policy: str, runtime_policy: Optional[RuntimePolicyType]) -> "IMAPolicy":
        rules: List[ABCRule] = []

        for rule in policy.split("\n"):
            rule = rule.strip()
            if not rule or rule.startswith("#"):
                continue

            rule_parts = rule.split(":")

            rule_type = rule_parts[0]
            rule_params = ""

            if len(rule_parts) > 1:
                _, rule_params = rule.split(":", 1)
                rule_params = rule_params.strip()

            rule_class = IMAPolicy.MAPPINGS.get(rule_type)
            if not rule_class:
                raise IMAPolicyError(f"IMAPolicy does not support '{rule_type}' rule")
            rules.append(rule_class.from_string(rule_params))
        return IMAPolicy(rules, runtime_policy)

    @staticmethod
    def from_runtime_policy(runtime_policy: Optional[RuntimePolicyType]) -> "IMAPolicy":
        # Currently RuntimePolicyType does not carry a policy with rules
        # so use the default built-in policy
        return IMAPolicy.from_string(IMAPolicy.DEFAULT_POLICY_STR, runtime_policy)

    def eval(
        self,
        evaluator: Evaluator,
        digest: ast.Digest,
        path: ast.Name,
        signature: Optional[ast.Signature],
        data: Optional[ast.Buffer],
        ima_keyrings: Optional[ImaKeyrings],
    ) -> Failure:
        """Evaluate the policy against an IMA log entry"""
        failure = Failure(Component.IMA, ["ima-policy"])

        for rule in self.rules:
            res, rule_failure = evaluator.get_evaluator(type(rule))(digest, path, signature, data, rule)
            logger.debug("%s -> %s", rule, res)
            if rule_failure:
                failure.merge(rule_failure)

            if res in [EvalResult.ACCEPT, EvalResult.REJECT]:
                return failure

        # None of the rules ACCEPT'ed or REJECT'ed the log entry, so if either
        # a runtime_policy or ima_keyrings is given leave an error message.
        # Without both the log entry would 'pass'.
        if self.runtime_policy:
            failure.add_event("not_in_policy", f"File not accepted by policy: {path.name}", True)
        if ima_keyrings:
            failure.add_event("invalid_signature", f"signature for file {path.name} could not be validated", True)

        return failure

    def get_regex_list(self, listname: str) -> Optional[CompiledRegexList]:
        """Get a regex list from the runtimepolicy using its name"""
        if not self.regex_list.get(listname):
            regexlist: List[str] = []

            if self.runtime_policy:
                rlist = self.runtime_policy.get("excludes", None)
                if rlist is None:
                    raise IMAPolicyError(f"A regular expression list with name '{listname}' is not available")
                if not isinstance(rlist, list):
                    raise IMAPolicyError(f"Referenced regular expression list '{listname}' is not a list")
                regexlist = rlist

            self.regex_list[listname] = CompiledRegexList.from_excludelist(regexlist)
        return self.regex_list.get(listname)

    def get_map(self, mapname: str) -> Optional[Dict[str, List[str]]]:
        if not self.runtime_policy:
            return {}
        rmap = self.runtime_policy.get(mapname, None)
        if rmap is None:
            raise IMAPolicyError(f"A map with name '{mapname}' is not available")
        if not isinstance(rmap, dict):
            raise IMAPolicyError(f"Referenced map '{mapname}' is not a map")
        return rmap
