from keylime.common import exception

######################
# Keylime Agent States
######################

REGISTERED = 0
"""The agent is registered with registrar but not added to verifier yet"""

START = 1
"""The agent is added to verifier and will be moved to next state"""

SAVED = 2
"""The agent was added in verifier and wait for requests"""

GET_QUOTE = 3
"""The agent is under periodic integrity checking"""

GET_QUOTE_RETRY = 4
"""The agent is under periodic integrity checking but in a retry
state due to connection issues"""

PROVIDE_V = 5
"""The agent is receiving V key from the verifier"""

PROVIDE_V_RETRY = 6
"""The agent is recieving V key from the verifier but in a retry state due to
connection issues"""

FAILED = 7
"""The agent host failed to prove the integrity"""

TERMINATED = 8
"""The agent was terminated and will be removed from verifier"""

INVALID_QUOTE = 9
"""The integrity report from agent is not trusted against whitelist"""

TENANT_FAILED = 10
"""The agent was terminated but failed to be removed form verifier"""


VALID_STATES = (
    REGISTERED,
    START,
    SAVED,
    GET_QUOTE,
    GET_QUOTE_RETRY,
    PROVIDE_V,
    PROVIDE_V_RETRY,
    FAILED,
    TERMINATED,
    INVALID_QUOTE,
    TENANT_FAILED,
)

APPROVED_REACTIVATE_STATES = [START, GET_QUOTE, GET_QUOTE_RETRY, PROVIDE_V, PROVIDE_V_RETRY]

STATE_REPRESENTATIONS = {
    REGISTERED: "Registered",
    START: "Start",
    SAVED: "Saved",
    GET_QUOTE: "Get Quote",
    GET_QUOTE_RETRY: "Get Quote (retry)",
    PROVIDE_V: "Provide V",
    PROVIDE_V_RETRY: "Provide V (retry)",
    FAILED: "Failed",
    TERMINATED: "Terminated",
    INVALID_QUOTE: "Invalid Quote",
    TENANT_FAILED: "Tenant Quote Failed",
}


def state_to_str(state: int) -> str:
    if state not in VALID_STATES:
        raise exception.InvalidAgentState()
    return STATE_REPRESENTATIONS[state]
