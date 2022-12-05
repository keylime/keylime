"""Tagging of failure events that might cause revocation in Keylime.

"""

import enum
import functools
import re
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple, Union

from keylime import json, keylime_logging

logger = keylime_logging.init_logging("failure")


@functools.total_ordering
class SeverityLabel:
    """
    Severity label that can be attached to an event.

    The severity level is assigned dynamically based on the configuration,
    so only use the name for use outside use of the tagging module.
    """

    name: str
    severity: int

    def __init__(self, name: str, severity: int):
        self.name = name
        self.severity = severity

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SeverityLabel):
            return NotImplemented
        return self.severity < other.severity

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SeverityLabel):
            return NotImplemented
        return self.severity == other.severity


class Component(enum.Enum):
    """
    Main components of Keylime that can generate revocations.
    """

    QUOTE_VALIDATION = "qoute_validation"
    PCR_VALIDATION = "pcr_validation"
    MEASURED_BOOT = "measured_boot"
    IMA = "ima"
    INTERNAL = "internal"
    DEFAULT = "default"


class Event:
    """
    Event that might be the reason for revocation.

    The context is string
    """

    event_id: str
    severity_label: SeverityLabel
    context: str
    recoverable: bool

    def __init__(
        self,
        component: Component,
        sub_components: Optional[List[str]],
        event_id: str,
        context: Union[str, Dict[str, json.JSONType]],
        recoverable: bool,
    ):

        # Build full event id with the format "component.[sub_component].event_id"
        self.event_id = component.value
        if sub_components is not None:
            self.event_id += "." + ".".join(sub_components)
        self.event_id += f".{event_id}"

        # Convert message
        if isinstance(context, str):
            context = {"message": context}
        self.context = json.dumps(context)

        self.severity_label = _severity_match(self.event_id)
        self.recoverable = recoverable


class Failure:
    """
    Failure Object that collects all events that might cause a revocation.

    If recoverable is set to False the validation process returned early and might skipped other validation steps.
    """

    events: List[Event]
    recoverable: bool
    highest_severity: Optional[SeverityLabel]
    _component: Component
    _sub_components: Optional[List[str]]

    def __init__(self, component: Component, sub_components: Optional[List[str]] = None):
        self._component = component
        self._sub_components = sub_components
        self.events = []
        self.recoverable = True
        self.highest_severity_event: Optional[
            Event
        ] = None  # This only holds the first event that has the highest severity
        self.highest_severity: Optional[SeverityLabel] = None

    def _add(self, event: Event) -> None:
        if not event.recoverable:
            self.recoverable = False
            if event.severity_label != MAX_SEVERITY_LABEL:
                logger.warning(
                    "Irrecoverable Event with id: %s has not the highest severity level.\n "
                    "Setting it the the highest severity level.",
                    event.event_id,
                )
                event.severity_label = MAX_SEVERITY_LABEL

        if self.highest_severity is None or event.severity_label > self.highest_severity:
            self.highest_severity = event.severity_label
            self.highest_severity_event = event

        self.events.append(event)

    def add_event(
        self,
        event_id: str,
        context: Union[str, Dict[str, json.JSONType]],
        recoverable: bool,
        sub_components: Optional[List[str]] = None,
    ) -> None:
        """
        Add event to Failure object. Uses the component and subcomponents specified in the Failure object.

        As context specify either a string that contains a message or a dict that contains useful information about that
        event.
        Set recoverable to False if the code skips other not directly related checks. Those events should always have
        the highest severity label assigned and if not we manually do that.

        Example usage:
            failure.add_event("ima_hash",
                              {"message": "IMA hash does not match the calculated hash.",
                               "expected": self.template_hash, "got": self.mode.hash()}, True)
        """
        if sub_components is not None and self._sub_components is not None:
            sub_components = self._sub_components + sub_components
        elif self._sub_components is not None:
            sub_components = self._sub_components
        event = Event(self._component, sub_components, event_id, context, recoverable)
        self._add(event)

    def merge(self, other: "Failure") -> None:
        if self.recoverable:
            self.recoverable = other.recoverable
        if self.highest_severity is None:
            self.highest_severity = other.highest_severity
            self.highest_severity_event = other.highest_severity_event
        elif other.highest_severity is not None and self.highest_severity < other.highest_severity:
            self.highest_severity = other.highest_severity
            self.highest_severity_event = other.highest_severity_event

        self.events.extend(other.events)

    def get_event_ids(self) -> List[str]:
        """
        Returns a list of the event ids currently collected
        """
        return list(map(lambda x: x.event_id, self.events))

    def __bool__(self) -> bool:
        return not self.recoverable or len(self.events) > 0


def _eval_severity_config(
    severity_labels: Optional[List[str]] = None, severity_policy: Optional[List[Dict[str, str]]] = None
) -> Tuple[List[Callable[[str], Optional[SeverityLabel]]], SeverityLabel]:
    """
    Generates the list of rules to match a event_id against.
    """

    if severity_labels:
        labels_list = severity_labels
    else:
        # Default labels from lowest to highest severity
        labels_list = ["info", "notice", "warning", "error", "critical", "alert", "emergency"]

    if severity_policy:
        policies = severity_policy
    else:
        # The default policy assigns the highest severity to all events
        policies = [{"event_id": ".*", "severity_label": labels_list[-1]}]

    labels = {}
    for label, level in zip(labels_list, range(0, len(labels_list))):
        labels[label] = SeverityLabel(label, level)

    label_max = labels[labels_list[-1]]

    rules = []
    for policy in policies:
        # TODO validate regex
        regex = re.compile(policy["event_id"])

        def rule(policy_regex: Pattern[Any], label_str: str, event_id: str) -> Optional[SeverityLabel]:
            if policy_regex.fullmatch(event_id):
                policy_label = labels.get(label_str)
                if policy_label is None:
                    logger.error("Label %s is not a valid label. Defaulting to maximal severity label!", label_str)
                    return label_max
                return policy_label
            return None

        new_rule: Callable[[str], Optional[SeverityLabel]] = functools.partial(rule, regex, policy["severity_label"])
        rules.append(new_rule)
    return rules, label_max


# Only evaluate the policy once on module load
SEVERITY_RULES, MAX_SEVERITY_LABEL = _eval_severity_config()


def set_severity_config(severity_labels: Optional[List[str]], severity_policy: Optional[List[Dict[str, str]]]) -> None:
    """
    Set a custom severity configuration
    """

    if not severity_labels:
        raise Exception("Empty severity_labels provided to set_severity_config()")

    if not severity_policy:
        raise Exception("Empty severity_policy provided to set_severity_config()")

    global SEVERITY_RULES, MAX_SEVERITY_LABEL

    SEVERITY_RULES, MAX_SEVERITY_LABEL = _eval_severity_config(
        severity_labels=severity_labels, severity_policy=severity_policy
    )

    logger.info("Severity configuration set")


def _severity_match(event_id: str) -> SeverityLabel:
    """
    Match the event_id to a severity label.
    """
    for rule in SEVERITY_RULES:
        match = rule(event_id)
        if match is not None:
            return match
    logger.warning("No rule matched for event_id: %s. Defaulting to max severity label", event_id)
    return MAX_SEVERITY_LABEL
