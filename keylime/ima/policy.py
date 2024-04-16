#!/usr/bin/env python

from abc import ABC, abstractmethod
from enum import Enum
from typing import Callable, Dict, List, Optional, Pattern, Tuple, Type

from keylime import keylime_logging
from keylime.common import validators
from keylime.failure import Component, Failure
from keylime.ima import ast, file_signatures, ima_dm
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


def check_mutually_exclusive(keys: List[str], exclusions_list: List[List[str]], rulename: str) -> None:
    """
    Check for mutually excluse keys by checking all list of mutually exclusive
    keys in the exclusions_list.
    """
    for exclusion_list in exclusions_list:
        ctr = 0
        for exclusion in exclusion_list:
            if exclusion in keys:
                ctr += 1
                if ctr == 2:
                    raise IMAPolicyError(
                        f"{rulename} contains mutually exclusive paramers {', '.join(exclusion_list)}."
                    )


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

    @abstractmethod
    def get_runtime_policy(self) -> Optional[RuntimePolicyType]:
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


class DeviceMapperCheck(ABCRule):
    """
    DeviceMapperCheck represents a 'DEVICE-MAPPER-CHECK' rule.
    """

    def __init__(self) -> None:
        super().__init__("DEVICE-MAPPER-CHECK", "")

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        if len(rawparams) > 0:
            raise IMAPolicyError("DEVICE-MAPPER-CHECK does not support any parameters")
        return ImaSignatureCheck()

    def setup(self, policy: ABCPolicy) -> None:
        pass

    @staticmethod
    def eval(
        dm_validator: Optional[ima_dm.DmIMAValidator],
        digest: ast.Digest,
        path: ast.Name,
        data: Optional[ast.Buffer],
    ) -> Tuple[EvalResult, Optional[Failure]]:
        if not data:
            return EvalResult.SKIP, None

        if dm_validator and path.name in dm_validator.valid_names:
            failure = dm_validator.validate(digest, path, data)
            if failure:
                return EvalResult.REJECT, failure
            return EvalResult.ACCEPT, None

        return EvalResult.SKIP, None


def device_mapper_check_eval(
    dm_validator: Optional[ima_dm.DmIMAValidator],
    digest: ast.Digest,
    path: ast.Name,
    _signature: Optional[ast.Signature],
    data: Optional[ast.Buffer],
    _rule: DeviceMapperCheck,
) -> Tuple[EvalResult, Optional[Failure]]:
    return DeviceMapperCheck.eval(dm_validator, digest, path, data)


class FileNames(ABCRule):
    """
    FileNames represents a
    'FILE-NAMES: regex-ref=<listname>|[regex=<regex> [regex=<regex> ...]]'
    rule. The listname refers to a list
    where each entry is a regex prefixed by eiter ACCEPT: or REJECT:
    """

    comp_regex_list: Optional[CompiledRegexList]

    def __init__(self, rawparams: str, parameters: Dict[str, List[str]]):
        super().__init__("FILE-NAMES", rawparams)
        self.parameters = parameters
        self.comp_regex_list = None

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        parameters = kvps_to_dict(
            rawparams, ["regex-ref", "regex"], ["regex-ref"], [["regex-ref"], ["regex"]], "FILE-NAMES"
        )
        return FileNames(rawparams, parameters)

    def setup(self, policy: ABCPolicy) -> None:
        check_mutually_exclusive(list(self.parameters.keys()), [["regex-ref", "regex"]], "FILE-NAMES")
        if "regex-ref" in self.parameters:
            self.comp_regex_list = policy.get_regex_list(self.parameters["regex-ref"][0])
        elif "regex" in self.parameters:
            self.comp_regex_list = CompiledRegexList.from_list(self.parameters["regex"])

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
    FileHashes represents a
    'FILE-HASHES: map-ref=<mapname>|[filename=<filename> hash=<hash> [hash=<hash> ...]] target=<ACCEPT|REJECT>'
    rule.
    """

    parameters: Dict[str, List[str]]
    target: EvalResult
    filehashesmap: Optional[Dict[str, List[str]]]
    filedigestsmap: Optional[Dict[str, List[ast.Digest]]]

    def __init__(self, rawparams: str, parameters: Dict[str, List[str]], target: EvalResult):
        super().__init__("FILE-HASHES", rawparams)
        self.parameters = parameters
        self.target = target
        self.filehashesmap = {}
        self.filedigestsmap = {}

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        parameters = kvps_to_dict(
            rawparams,
            ["map-ref", "target", "filename", "hash"],
            ["map-ref", "target", "filename"],
            [["map-ref", "target"], ["filename", "hash", "target"]],
            "FILE-HASHES",
        )
        target = target_to_eval_result(parameters["target"][0])
        return FileHashes(rawparams, parameters, target)

    def setup(self, policy: ABCPolicy) -> None:
        check_mutually_exclusive(
            list(self.parameters.keys()), [["map-ref", "filename"], ["map-ref", "hash"]], "FILE-HASHES"
        )
        if "map-ref" in self.parameters:
            self.filehashesmap = policy.get_map(self.parameters["map-ref"][0])
        elif "filename" in self.parameters and "hash" in self.parameters:
            digests = [ast.Digest(digest) for digest in self.parameters["hash"]]
            self.filedigestsmap = {self.parameters["filename"][0]: digests}

    def eval(self, digest: ast.Digest, path: ast.Name) -> Tuple[EvalResult, Optional[Failure]]:
        ret = EvalResult.SKIP

        if self.filehashesmap:
            hashes_list = self.filehashesmap.get(path.name, None)
            if not hashes_list:
                return EvalResult.SKIP, None

            if digest.hash.hex() in hashes_list:
                ret = self.target
        elif self.filedigestsmap:
            digests_list = self.filedigestsmap.get(path.name, None)
            if not digests_list:
                return EvalResult.SKIP, None

            if digest in digests_list:
                ret = self.target

        if ret in [EvalResult.REJECT]:
            failure = Failure(Component.IMA)
            failure.add_event("rejected_by_file_hashes_rule", f"{path.name} was rejected by FILE-HASHES rule", True)
            return self.target, failure

        return ret, None


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


class LearnKeys(ABCRule):
    """LearnKeys represents a 'LEARN-KEYS [ignored-list-ref=<ignore-list>] [allowed-hashes-ref=<hashes-list>]' rule"""

    parameters: Dict[str, List[str]]
    ignored_keyrings: List[str]
    allowed_hashes: Dict[str, List[str]]  # a key's hash must be in this dict (key = keyring name)

    def __init__(self, rawparams: str, parameters: Dict[str, List[str]]) -> None:
        super().__init__("LEARN-KEYS", rawparams)
        self.parameters = parameters
        self.ignored_keyrings = []
        self.allowed_hashes = {}

    @staticmethod
    def from_string(rawparams: str) -> ABCRule:
        parameters = kvps_to_dict(
            rawparams,
            ["ignored-keyrings-ref", "allowed-hashes-ref"],
            ["ignored-keyrings-ref", "allowed-hashes-ref"],
            None,
            "LEARN-KEYS",
        )
        return LearnKeys(rawparams, parameters)

    def setup(self, policy: ABCPolicy) -> None:
        runtime_policy = policy.get_runtime_policy()
        if runtime_policy:
            ignore_keyrings = self.parameters.get("ignored-keyrings-ref", [""])[0]
            if ignore_keyrings:
                ik = runtime_policy.get("ima", {}).get(ignore_keyrings, [])
                if not isinstance(ik, list):
                    raise IMAPolicyError("Referenced ignored-keyrings-ref {ignore_list} is not a list")
                self.ignored_keyrings = ik

            allowed_hashes = self.parameters.get("allowed-hashes-ref", [""])[0]
            if allowed_hashes:
                ah = runtime_policy.get(allowed_hashes, [])
                if not isinstance(ah, dict):
                    raise IMAPolicyError("Referenced allowed-hashes-ref {allowed_hashes} is not a dictionary")
                self.allowed_hashes = ah

    def eval(
        self,
        ima_keyrings: Optional[file_signatures.ImaKeyrings],
        digest: ast.Digest,
        path: ast.Name,
        data: Optional[ast.Buffer],
    ) -> Tuple[EvalResult, Optional[Failure]]:
        if not data:
            return EvalResult.SKIP, None
        failure = Failure(Component.IMA)

        # Is data.data a key?
        try:
            pubkey, keyidv2 = file_signatures.get_pubkey(data.data)
        except ValueError as ve:
            failure.add_event("invalid_key", f"key from {path.name} does not have a supported key: {ve}", True)
            return EvalResult.SKIP, failure

        if pubkey:
            if "*" not in self.ignored_keyrings and path.name not in self.ignored_keyrings:
                accept_list = self.allowed_hashes.get(path.name, None)
                if not accept_list:
                    allowed_hashes = self.parameters.get("allowed-hashes", "<allowed-hashes not given in rule>")
                    failure.add_event("not_in_allowlist", f"Keyring not found in {allowed_hashes}: {path.name}", True)
                    return EvalResult.REJECT, failure
                hex_hash = digest.hash.hex()
                if hex_hash not in accept_list:
                    failure.add_event(
                        "runtime_policy_hash",
                        {
                            "message": "Hash for key not found in runtime policy",
                            "got": hex_hash,
                            "expected": accept_list,
                        },
                        True,
                    )
                    return EvalResult.REJECT, failure
                if ima_keyrings is not None:
                    ima_keyrings.add_pubkey_to_keyring(pubkey, path.name, keyidv2=keyidv2)
                    return EvalResult.ACCEPT, None

        return EvalResult.SKIP, failure


def learn_keys_eval(
    ima_keyrings: Optional[file_signatures.ImaKeyrings],
    digest: ast.Digest,
    path: ast.Name,
    _signature: Optional[ast.Signature],
    data: Optional[ast.Buffer],
    rule: LearnKeys,
) -> Tuple[EvalResult, Optional[Failure]]:
    return rule.eval(ima_keyrings, digest, path, data)


class IMAPolicy(ABCPolicy):
    MAPPINGS: Dict[str, Type[ABCRule]] = {
        "DEVICE-MAPPER-CHECK": DeviceMapperCheck,
        "IMA-SIGNATURE-CHECK": ImaSignatureCheck,
        "FILE-HASHES": FileHashes,
        "FILE-NAMES": FileNames,
        "LEARN-KEYS": LearnKeys,
    }
    DEFAULT_POLICY_STR: str = (
        "LEARN-KEYS: ignored-keyrings-ref=ignored_keyrings allowed-hashes-ref=keyrings\n"
        "DEVICE-MAPPER-CHECK\n"
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
        if runtime_policy and "rules" in runtime_policy:
            return IMAPolicy.from_string(runtime_policy["rules"], runtime_policy)
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
            # FIXME: historical error message ...
            logger.warning("File not found in allowlist: %s", path.name)
            failure.add_event("not_in_allowlist", f"File not found in allowlist: {path.name}", True)
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

    def get_runtime_policy(self) -> Optional[RuntimePolicyType]:
        return self.runtime_policy
