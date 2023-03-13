import sys
from typing import Dict, List, Optional, Union

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict
else:
    from typing_extensions import Literal, TypedDict

### Types for tpm_dm.py

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
