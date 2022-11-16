"""Parser and validator for device mapper IMA events

  - https://www.kernel.org/doc/html/v5.15/admin-guide/device-mapper/dm-ima.html

"""

import pickle
import re
import sys
from collections import ChainMap
from itertools import chain
from typing import Any, Callable, Dict, List, Optional, Union

import lark
from lark.exceptions import LarkError
from lark.lark import Lark
from lark.visitors import Transformer, v_args
from packaging import version

from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.ima import ast
from keylime.ima.dm_grammar import DM_GRAMMAR

if sys.version_info >= (3, 7):
    from dataclasses import dataclass
else:
    from keylime.backport_dataclasses import dataclass

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict


class DeepChainMap(ChainMap):  # type: ignore[type-arg]
    """
    Variant of ChainMap that handles updates for nested ChainMaps
    Based on the example in https://docs.python.org/3/library/collections.html#collections.ChainMap
    """

    def __setitem__(self, key: Any, value: Any) -> None:
        for mapping in self.maps:
            if key in mapping:
                mapping[key] = value
                return
        super().__setitem__(key, value)

    def __delitem__(self, key: Any) -> None:
        for mapping in self.maps:
            if key in mapping:
                del mapping[key]
                return
        raise KeyError(key)


RuleAttributeType = Optional[Union[int, str, bool]]

# Special Type for the match key.
# Note that mypy currently does not detect that the variable is a literal,
# so we still need to add a type ignore
MatchKeyType = Literal["name", "uuid"]


class DeviceRenameRule(TypedDict):
    valid_name: RuleAttributeType
    valid_uuid: RuleAttributeType


class DeviceRemoveRule(TypedDict):
    allow_removal: bool


class TableLoadRule(TypedDict):
    allow_multiple_loads: bool
    name: str
    uuid: str
    major: int
    minor: int
    minor_count: int
    num_targets: int
    targets: List[Dict[str, RuleAttributeType]]


class Rule(TypedDict):
    required: bool
    device_resume_required: bool
    device_rename: DeviceRenameRule
    device_remove: DeviceRemoveRule
    allow_clear: bool
    table_load: TableLoadRule


class Policies(TypedDict):
    match_on: MatchKeyType
    rules: Dict[str, Rule]


@dataclass
class DeviceState:
    policy_name: str
    active: bool
    valid_state: bool
    active_table_hash: ast.Digest
    inactive_table_hash: Optional[ast.Digest]
    num_targets: int
    allow_multiple_loads: bool


class DmIMAValidator:
    valid_names = [
        "dm_table_load",
        "dm_device_resume",
        "dm_device_remove",
        "dm_table_clear",
        "dm_device_rename",
        "dm_target_update",
    ]
    policies: Policies
    devices: Dict[str, DeviceState]

    def __init__(self, policies: Policies) -> None:
        self.policies = policies
        self.devices = {}

    def state_load(self, state: Optional[bytes]) -> None:
        if state:
            self.devices = pickle.loads(state)

    def state_dump(self) -> bytes:
        """
        Export the state of the validator.
        Note: the validator assumes that this data is always trustworthy and might not compatible between versions
        """
        return pickle.dumps(self.devices)

    def validate(self, digest: ast.Digest, path: ast.Name, data: ast.Buffer) -> Failure:
        """Validate a single entry."""
        failure = Failure(Component.IMA, ["validation", "dm"])
        try:
            event = parse(data.data.decode("utf-8"), path.name)
            hash_alg = Hash(digest.algorithm)
            if digest.hash != hash_alg.hash(data.data):
                failure.add_event("invalid_data", "hash in IMA log and of the actual data mismatch", True)

            match_key = self.policies["match_on"]

            if path.name == "dm_table_load":
                assert isinstance(event, LoadEvent)
                failure.merge(self.validate_table_load(event, match_key, digest))
            elif path.name == "dm_device_resume":
                assert isinstance(event, ResumeEvent)
                failure.merge(self.validate_device_resume(event, match_key))
            elif path.name == "dm_device_remove":
                assert isinstance(event, RemoveEvent)
                failure.merge(self.validate_device_remove(event, match_key))
            elif path.name == "dm_device_rename":
                assert isinstance(event, RenameEvent)
                failure.merge(self.validate_device_rename(event, match_key))
            elif path.name == "dm_table_clear":
                assert isinstance(event, ClearEvent)
                failure.merge(self.validate_table_clear(event, match_key))
            elif path.name == "dm_target_update":
                assert isinstance(event, UpdateEvent)
                failure.merge(self.validate_target_update(event, match_key))
            else:
                failure.add_event("invalid_event_type", {"got": path.name}, True)

        except (LarkError, TypeError) as e:
            failure.add_event("parsing_failed", f"Could not construct valid entry: {e}", True)

        return failure

    def validate_table_clear(self, event: "ClearEvent", match_key: MatchKeyType) -> Failure:
        failure = Failure(Component.IMA, ["validation", "dm", "dm_table_clear"])

        device_key = getattr(event.device_metadata, match_key)
        device_state = self.devices.get(device_key, None)
        if device_state is None:
            failure.add_event("clear_before_table_load", "Clear event before table was loaded", True)
            return failure

        policy = self.policies["rules"][device_state.policy_name]
        if not policy["allow_clear"]:
            failure.add_event(
                "table_cleared", f"Table for device {device_key} was cleared, but that is not allowed", True
            )
            device_state.valid_state = False
            return failure

        return failure

    def validate_target_update(self, event: "UpdateEvent", match_key: MatchKeyType) -> Failure:
        failure = Failure(Component.IMA, ["validation", "dm", "dm_target_update"])

        device_key = getattr(event.device_metadata, match_key)
        device_state = self.devices.get(device_key, None)
        if device_state is None:
            failure.add_event("update_before_table_load", "Update event before table was loaded", True)
            return failure

        policy = self.policies["rules"][device_state.policy_name]
        target_data = policy["table_load"]["targets"][event.target.target_index]

        # Validate the target data again
        self.validate_target_table(event.target, target_data, failure)

        return failure

    def validate_device_remove(self, event: "RemoveEvent", match_key: MatchKeyType) -> Failure:
        failure = Failure(Component.IMA, ["validation", "dm", "dm_device_remove"])

        # TODO: check if we can always use the active table
        device_key = getattr(event.device_active_metadata, match_key)
        device_state = self.devices.get(device_key, None)
        if device_state is None:
            failure.add_event("remove_before_table_load", "Remove event before table was loaded", True)
            return failure

        policy = self.policies["rules"][device_state.policy_name]
        if not policy["device_remove"]["allow_removal"]:
            failure.add_event("device_removed", f"Device {device_key} was remove, but that is not allowed", True)
            device_state.valid_state = False
            return failure

        # Remove device completely
        del self.devices[device_key]
        return failure

    def validate_device_resume(self, event: "ResumeEvent", match_key: MatchKeyType) -> Failure:
        failure = Failure(Component.IMA, ["validation", "dm", "dm_device_resume"])

        device_key = getattr(event.device_metadata, match_key)
        if device_key not in self.devices:
            failure.add_event("resume_before_table_load", "Resume event before table was loaded", True)
            return failure

        device_state = self.devices[device_key]

        # We only expect one resume event
        if device_state.active:
            failure.add_event("already_active", "table is already active", True)
            device_state.valid_state = False
            return failure

        # Check if the table hash is consistent
        if device_state.active_table_hash != event.active_table_hash:
            failure.add_event(
                "active_table_mismatch",
                {
                    "got": event.active_table_hash.hash.decode(),
                    "expected": device_state.active_table_hash.hash.decode(),
                    "context": "resume does not match the table",
                },
                True,
            )
            device_state.valid_state = False
            return failure

        # TODO: Check also current capacity.

        # Mark now device as active and in a valid state
        device_state.active = True
        device_state.valid_state = True
        return failure

    def validate_device_rename(self, event: "RenameEvent", match_key: MatchKeyType) -> Failure:
        failure = Failure(Component.IMA, ["validation", "dm", "dm_device_rename"])

        device_key = getattr(event.device_metadata, match_key)
        device_state = self.devices.get(device_key, None)
        if device_state is None:
            failure.add_event("rename_before_table_load", "Rename event before table was loaded", True)
            return failure

        policy = self.policies["rules"][device_state.policy_name]

        # Only check if the name changed
        if event.device_metadata.name != event.new_name:
            if not _check_attr(event.new_name, policy["device_rename"]["valid_name"]):
                failure.add_event(
                    "new_name_invalid",
                    {
                        "message": "New name is invalid",
                        "got": event.new_name,
                        "expected": policy["device_rename"]["valid_name"],
                    },
                    True,
                )
                device_state.valid_state = False
            elif match_key == "name":
                self.devices[event.new_name] = self.devices.pop(device_key)

        # Only check if uuid changed
        if event.device_metadata.uuid != event.new_uuid:
            if not _check_attr(event.new_uuid, policy["device_rename"]["valid_uuid"]):
                failure.add_event(
                    "new_uuid_invalid",
                    {
                        "message": "New name is invalid",
                        "got": event.new_uuid,
                        "expected": policy["device_rename"]["valid_uuid"],
                    },
                    True,
                )
                device_state.valid_state = False
            elif match_key == "uuid":
                self.devices[event.new_name] = self.devices.pop(device_key)

        return failure

    def validate_table_load(self, event: "LoadEvent", match_key: MatchKeyType, digest: ast.Digest) -> Failure:
        failure = Failure(Component.IMA, ["validation", "dm", "dm_table_load"])

        device_key = getattr(event.device_metadata, match_key)

        if device_key in self.devices and not self.devices[device_key].allow_multiple_loads:
            failure.add_event("multiple_table_loads", f"Multiple table load entries for device: {device_key}", True)
            return failure

        # Find matching policy
        used_policy_name = None
        used_policy = None
        for policy_name, policy in self.policies["rules"].items():
            if re.fullmatch(policy["table_load"][match_key], device_key):
                used_policy = policy
                used_policy_name = policy_name
                break

        if used_policy is None or used_policy_name is None:
            failure.add_event("no_matching_policy", "No policy found", True)
            return failure

        # Validate device metadata
        for entry in ["name", "uuid", "major", "minor", "minor_count", "num_targets"]:
            if not _check_attr(getattr(event.device_metadata, entry), used_policy["table_load"][entry]):  # type:ignore
                failure.add_event(
                    "invalid_entry",
                    {
                        "got": getattr(event.device_metadata, entry),
                        "expected": used_policy["table_load"][entry],  # type:ignore
                        "context": entry,
                    },
                    True,
                )
                return failure

        # Check "num_targets"
        # Note that we get actually could get multiple lines, but this does not happen for our use cases so we
        # treat it as a failure.
        if event.device_metadata.num_targets != len(event.targets) or used_policy["table_load"]["num_targets"] != len(
            event.targets
        ):
            failure.add_event("num_targets_mismatch", "lengths are not consistent", True)
            return failure

        # Validate targets
        for actual_target, should_values in zip(event.targets, used_policy["table_load"]["targets"]):
            self.validate_target_table(actual_target, should_values, failure)

        # Add device to validator
        self.devices[device_key] = DeviceState(
            active=False,
            valid_state=not used_policy["device_resume_required"],
            # Device normally has a resume to be in a fully validated state
            active_table_hash=digest,
            inactive_table_hash=None,
            policy_name=used_policy_name,
            allow_multiple_loads=used_policy["table_load"]["allow_multiple_loads"],
            num_targets=event.device_metadata.num_targets,
        )
        return failure

    @staticmethod
    def validate_target_table(
        target: "Target", reference_values: Dict[str, RuleAttributeType], failure: Failure
    ) -> None:
        """
        Validates a target table entry against reference_values in a policy.
        If a failure occurs it is added to the failure object.
        """
        valid = True
        for key in reference_values.keys():
            data: Union["Target", "TargetAttributes"] = target
            # Non default target arguments are stored in target_attributes
            if key not in ["target_index", "target_begin", "target_len", "target_name", "target_version"]:
                data = target.target_attributes
            try:
                if not _check_attr(getattr(data, key), reference_values[key]):
                    failure.add_event(
                        "target_data_mismatch",
                        {"got": getattr(data, key), "expected": reference_values[key], "context": key},
                        True,
                    )
                    valid = False
            except AttributeError as e:
                failure.add_event(
                    "target_attribute_not_found", {"context": f"Key {key} not found on target: {e}"}, True
                )

        if not valid:
            failure.add_event("target_data_invalid", "target data was not valid", True)

    def invalid(self) -> Failure:
        """
        Check if the devices are in a consistent state
        """
        failure = Failure(Component.IMA, ["validation", "dm"])
        used_policies = set()
        # Check if the devices are in a valid state
        for device_name, device in self.devices.items():
            if not device.valid_state:
                failure.add_event("device_invalid_state", {"context": device_name}, True)
            else:
                # Only add polices that are on valid states
                used_policies.add(device.policy_name)

        # Check for required active policies
        for policy_name, policy in self.policies["rules"].items():
            if policy["required"] and policy_name not in used_policies:
                failure.add_event("required_policy_not_in_use", f"policy {policy_name} required but not used", True)
        return failure


def _strtobool(val: str) -> bool:
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    if val in ("n", "no", "f", "false", "off", "0"):
        return False

    raise ValueError(f"invalid truth value {val}")


def _check_attr(attr: RuleAttributeType, reference_value: RuleAttributeType) -> bool:
    """
    Validate an attribute against the reference value
    - If the reference value is a str we assume that is a regex
    - If the reference value it is a bool or int it is checked for equality after converting attr to the type
    - If the reference value is None we always return True
    - If the reference value is not None and the attr is or type conversion fails it returns False
    """
    if reference_value is None:
        return True

    if attr is None:
        return False

    if isinstance(reference_value, bool):

        if isinstance(attr, str):
            try:
                return reference_value == _strtobool(attr)
            except ValueError:
                return False
        else:
            return reference_value == attr

    # This has to be done after the bool check because bool is also an instance of int
    if isinstance(reference_value, int):
        try:
            return reference_value == int(attr)
        except ValueError:
            return False

    if isinstance(reference_value, str):
        return bool(re.fullmatch(reference_value, str(attr)))

    return False


class TargetAttributes:
    pass


@dataclass
class VerityAttributes(TargetAttributes):
    hash_failed: str
    verity_version: int
    data_device_name: str
    hash_device_name: str
    verity_algorithm: str
    root_digest: str
    salt: str
    ignore_zero_blocks: str
    check_at_most_once: str
    root_hash_sig_key_desc: Optional[str] = None
    verity_mode: Optional[str] = None


@dataclass
class CacheAttributes(TargetAttributes):
    metadata_mode: str
    cache_metadata_device: str
    cache_device: str
    cache_origin_device: str
    writethrough: str
    writeback: str
    passthrough: str
    metadata2: str
    no_discard_passdown: str


@dataclass
class CryptAttributes(TargetAttributes):
    allow_discards: str
    same_cpu_crypt: str
    submit_from_crypt_cpus: str
    no_read_workqueue: str
    no_write_workqueue: str
    iv_large_sectors: str
    key_size: int
    key_parts: int
    key_extra_size: int
    key_mac_size: int
    integrity_tag_size: Optional[int] = None
    cipher_auth: Optional[str] = None
    sector_size: Optional[int] = None
    cipher_string: Optional[str] = None


@dataclass
class IntegrityAttributes(TargetAttributes):
    dev_name: str
    start: int
    tag_size: int
    mode: str
    recalculate: str
    allow_discards: str
    fix_padding: str
    fix_hmac: str
    legacy_recalculate: str
    journal_sectors: int
    interleave_sectors: int
    buffer_sectors: int
    meta_device: Optional[str] = None
    block_size: Optional[int] = None


@dataclass
class LinearAttributes(TargetAttributes):
    device_name: str
    start: str


@dataclass
class SnapshotAttributes(TargetAttributes):
    snap_origin_name: str
    snap_cow_name: str
    snap_valid: str
    snap_merge_failed: str
    snapshot_overflowed: str


@dataclass
class MirrorDevice:
    """
    Device information used by the mirror target attributes
    """

    mirror_device_name: str  # In raw data this is "mirror_device_X"
    mirror_device_status: str  # In raw data this is "mirror_device_X_status"


@dataclass
class MirrorAttributes(TargetAttributes):
    nr_mirrors: str
    mirror_device_data: List[MirrorDevice]
    handle_errors: str
    keep_log: str
    log_type_status: str


@dataclass
class Target:
    target_index: int
    target_begin: int
    target_len: int
    target_name: str
    target_version: str
    target_attributes: TargetAttributes


@dataclass
class DeviceMetaData:
    """
    Generic device metadata.
    """

    name: str
    uuid: str
    major: int
    minor: int
    minor_count: int
    num_targets: int


@dataclass
class DeviceMetaDataMinimal:
    """
    Device metadata that is measured when no_data happens
    """

    name: str
    uuid: str


@dataclass
class LoadEvent:
    dm_version: str
    device_metadata: DeviceMetaData
    targets: List[Target]


@dataclass
class ResumeEvent:
    dm_version: str
    device_metadata: DeviceMetaData
    current_device_capacity: int
    active_table_hash: ast.Digest

    def __post_init__(self) -> None:
        if isinstance(self.active_table_hash, str):
            self.active_table_hash = ast.Digest(self.active_table_hash)


@dataclass
class RemoveEvent:
    dm_version: str
    remove_all: str
    current_device_capacity: int
    device_active_metadata: Optional[DeviceMetaData] = None
    device_inactive_metadata: Optional[DeviceMetaData] = None
    active_table_hash: Optional[str] = None
    inactive_table_hash: Optional[str] = None


@dataclass
class ClearEvent:
    dm_version: str
    current_device_capacity: int
    no_data: bool
    device_metadata: Optional[Union[DeviceMetaData, DeviceMetaDataMinimal]] = None
    inactive_table_hash: Optional[str] = None


@dataclass
class RenameEvent:
    dm_version: str
    device_metadata: DeviceMetaData  # This is the device metadata of the active one
    new_name: str
    new_uuid: str
    current_device_capacity: int


@dataclass
class UpdateEvent:
    dm_version: str
    device_metadata: DeviceMetaData
    target: Target


def _token_to_dict(name: str, prefix: Optional[str] = None) -> Callable[[List[Any]], Dict[str, Any]]:
    """
    Generates function that converts a token to a dict containing the token name as key.
    The length of prefix is stripped from the key.
    """
    if prefix is not None:
        prefix_len = len(prefix)
        return lambda x: {name[prefix_len:]: x[0]}
    return lambda x: {name: x[0]}


class DeviceMapperTransformer(Transformer):  # type: ignore
    """
    Converts the Lark AST into the data structures for validation.
    """

    # All the tokens specified here just need to converted to a dict and in some cases their prefix stripped
    verity_tokens = [
        "verity_hash_failed",
        "verity_verity_version",
        "verity_data_device_name",
        "verity_hash_device_name",
        "verity_verity_algorithm",
        "verity_root_digest",
        "verity_salt",
        "verity_ignore_zero_blocks",
        "verity_check_at_most_once",
        "verity_root_hash_sig_key_desc",
        "verity_verity_mode",
    ]
    cache_tokens = [
        "cache_metadata_mode",
        "cache_cache_metadata_device",
        "cache_cache_device",
        "cache_cache_origin_device",
        "cache_writethrough",
        "cache_writeback",
        "cache_passthrough",
        "cache_metadata2",
        "cache_no_discard_passdown",
    ]
    crypt_tokens = [
        "crypt_allow_discards",
        "crypt_same_cpu_crypt",
        "crypt_submit_from_crypt_cpus",
        "crypt_no_read_workqueue",
        "crypt_no_write_workqueue",
        "crypt_iv_large_sectors",
        "crypt_integrity_tag_size",
        "crypt_cipher_auth",
        "crypt_sector_size",
        "crypt_cipher_string",
        "crypt_key_size",
        "crypt_key_parts",
        "crypt_key_extra_size",
        "crypt_key_mac_size",
    ]
    integrity_tokens = [
        "integrity_dev_name",
        "integrity_start",
        "integrity_tag_size",
        "integrity_mode",
        "integrity_meta_device",
        "integrity_block_size",
        "integrity_recalculate",
        "integrity_allow_discards",
        "integrity_fix_padding",
        "integrity_fix_hmac",
        "integrity_legacy_recalculate",
        "integrity_journal_sectors",
        "integrity_interleave_sectors",
        "integrity_buffer_sectors",
    ]
    mirror_tokens = ["mirror_nr_mirrors", "mirror_handle_errors", "mirror_keep_log", "mirror_log_type_status"]
    linear_tokens = ["linear_device_name", "linear_start"]
    snapshot_tokens = [
        "snapshot_snap_origin_name",
        "snapshot_snap_cow_name",
        "snapshot_snap_valid",
        "snapshot_snap_merge_failed",
        "snapshot_snapshot_overflowed",
    ]
    target_tokens = ["target_index", "target_begin", "target_len", "target_name", "target_version", "target_attributes"]
    device_tokens = [
        "device_name",
        "device_uuid",
        "device_major",
        "device_minor",
        "device_minor_count",
        "device_num_targets",
    ]
    other_tokens = ["dm_version", "remove_all", "current_device_capacity", "active_table_hash", "inactive_table_hash"]
    rename_tokens = ["rename_new_name", "rename_new_uuid"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        for token in chain(self.target_tokens, self.other_tokens):
            setattr(self, token, _token_to_dict(token))

        for token in self.device_tokens:
            setattr(self, token, _token_to_dict(token, "device_"))

        for token in self.rename_tokens:
            setattr(self, token, _token_to_dict(token, "rename_"))

        # Target specific tokens
        for token in self.verity_tokens:
            setattr(self, token, _token_to_dict(token, "verity_"))
        for token in self.cache_tokens:
            setattr(self, token, _token_to_dict(token, "cache_"))
        for token in self.crypt_tokens:
            setattr(self, token, _token_to_dict(token, "crypt_"))
        for token in self.integrity_tokens:
            setattr(self, token, _token_to_dict(token, "integrity_"))
        for token in self.mirror_tokens:
            setattr(self, token, _token_to_dict(token, "mirror_"))
        for token in self.linear_tokens:
            setattr(self, token, _token_to_dict(token, "linear_"))
        for token in self.snapshot_tokens:
            setattr(self, token, _token_to_dict(token, "snapshot_"))

        super().__init__(*args, **kwargs)

    @staticmethod
    def INT(tok: Any) -> int:
        return int(tok.value)

    @staticmethod
    def NUMBER(tok: Any) -> int:
        return int(tok.value)

    @staticmethod
    def STRING(tok: Any) -> str:
        return str(tok.value)

    @staticmethod
    def optional_string(children: List[str]) -> str:
        """Special handling for options that can have an empty string"""
        if not children:
            return ""
        return children[0]

    @staticmethod
    @v_args(inline=True)
    def version_nb(a: int, b: int, c: int) -> str:
        return f"{a}.{b}.{c}"

    @staticmethod
    def yes(x: List[Any]) -> str:
        assert x == []
        return "y"

    @staticmethod
    def no(x: List[Any]) -> str:
        assert x == []
        return "n"

    @staticmethod
    def verity_attributes(children: Any) -> VerityAttributes:
        return VerityAttributes(**DeepChainMap(*children))

    @staticmethod
    def cache_attributes(children: Any) -> CacheAttributes:
        return CacheAttributes(**DeepChainMap(*children))

    @staticmethod
    def crypt_attributes(children: Any) -> CryptAttributes:
        return CryptAttributes(**DeepChainMap(*children))

    @staticmethod
    def integrity_attributes(children: Any) -> IntegrityAttributes:
        return IntegrityAttributes(**DeepChainMap(*children))

    @staticmethod
    def linear_attributes(children: Any) -> LinearAttributes:
        return LinearAttributes(**DeepChainMap(*children))

    @staticmethod
    def mirror_attributes(children: Any) -> MirrorAttributes:
        return MirrorAttributes(**DeepChainMap(*children))

    @staticmethod
    def snapshot_attributes(children: Any) -> SnapshotAttributes:
        return SnapshotAttributes(**DeepChainMap(*children))

    @staticmethod
    def target(children: Any) -> Dict[str, Target]:
        return {"target": Target(**DeepChainMap(*children))}

    @staticmethod
    def targets(children: List[Dict[str, Target]]) -> Dict[str, List[Target]]:
        targets = []
        for child in children:
            targets.append(child["target"])
        return {"targets": targets}

    @staticmethod
    def device_metadata(children: Any) -> Dict[str, DeviceMetaData]:
        return {"device_metadata": DeviceMetaData(**DeepChainMap(*children))}

    @staticmethod
    def load_event(children: Any) -> LoadEvent:
        return LoadEvent(**DeepChainMap(*children))

    def resume_event(self, children: Any) -> ResumeEvent:
        data = DeepChainMap(*children)
        self._handle_no_data(data)
        return ResumeEvent(**data)

    def remove_event(self, children: Any) -> RemoveEvent:
        data = DeepChainMap(*children)
        self._handle_no_data(data)
        return RemoveEvent(**data)

    @staticmethod
    def rename_event(children: Any) -> RenameEvent:
        return RenameEvent(**DeepChainMap(*children))

    def clear_event(self, children: Any) -> ClearEvent:
        data = DeepChainMap(*children)
        self._handle_no_data(data)
        return ClearEvent(**data)

    @staticmethod
    def update_event(children: Any) -> UpdateEvent:
        return UpdateEvent(**DeepChainMap(*children))

    @staticmethod
    def remove_optional(children: Any) -> DeepChainMap:
        return DeepChainMap(*children)

    @staticmethod
    def resume_optional(children: Any) -> DeepChainMap:
        return DeepChainMap(*children)

    @staticmethod
    def clear_optional(children: Any) -> DeepChainMap:
        return DeepChainMap(*children)

    @staticmethod
    def no_data(_: Any) -> Dict[str, bool]:
        return {"no_data": True}

    @staticmethod
    @v_args(inline=True)
    def device_active_metadata(device_metadata: Any) -> Dict[str, Union[DeviceMetaData, DeviceMetaDataMinimal]]:
        return {"device_active_metadata": device_metadata["device_metadata"]}

    @staticmethod
    @v_args(inline=True)
    def device_inactive_metadata(device_metadata: Any) -> Dict[str, Union[DeviceMetaData, DeviceMetaDataMinimal]]:
        return {"device_inactive_metadata": device_metadata["device_metadata"]}

    @staticmethod
    def _handle_no_data(data: Union[Dict[Any, Any], DeepChainMap]) -> None:
        """
        If a no_data event happens (no information of the device is available) the event is still measured,
        but only with the devices name and uuid. This handles that special case.
        """
        if "no_data" in data:
            data["device_metadata"] = DeviceMetaDataMinimal(name=data["name"], uuid=data["uuid"])
            del data["name"]
            del data["uuid"]

    # Because mirror targets contains multiple devices it needs special parsing for that
    @staticmethod
    @v_args(inline=True)
    def mirror_mirror_device_name(_: Any, name: str) -> Dict[str, str]:
        return {"mirror_device_name": name}

    @staticmethod
    @v_args(inline=True)
    def mirror_mirror_device_status(_: Any, status: str) -> Dict[str, str]:
        return {"mirror_device_status": status}

    @staticmethod
    def mirror_mirror_device_row(children: Any) -> Dict[str, MirrorDevice]:
        return {"mirror_device_row": MirrorDevice(**DeepChainMap(*children))}

    @staticmethod
    def mirror_mirror_device_data(children: Any) -> Dict[str, List[MirrorDevice]]:
        devices = []
        for child in children:
            # We might get mirror_device_data because of the manual left recursion
            if "mirror_device_row" in child:
                devices.append(child["mirror_device_row"])
            if "mirror_device_data" in child:
                devices.append(child["mirror_device_data"])
        return {"mirror_device_data": devices}


parser = Lark(DM_GRAMMAR)
transformer = DeviceMapperTransformer()

# The parser_fast only works on newer lark versions
parser_fast = Lark(DM_GRAMMAR, parser="lalr", transformer=transformer)

EventTypes = Union[LoadEvent, ClearEvent, RemoveEvent, ResumeEvent, RenameEvent, UpdateEvent]


def parse(data: str, event: str) -> EventTypes:
    if version.Version(lark.__version__) >= version.Version("1.0.0"):
        out = parser_fast.parse(event + data)
    else:
        out = transformer.transform(parser.parse(event + data))

    if (event, type(out)) not in [
        ("dm_table_load", LoadEvent),
        ("dm_device_resume", ResumeEvent),
        ("dm_device_remove", RemoveEvent),
        ("dm_table_clear", ClearEvent),
        ("dm_device_rename", RenameEvent),
        ("dm_target_update", UpdateEvent),
    ]:
        raise TypeError(f"{event} was parsed as: {type(out)}")

    assert isinstance(out, (LoadEvent, ResumeEvent, RemoveEvent, ClearEvent, RenameEvent, UpdateEvent))
    return out
