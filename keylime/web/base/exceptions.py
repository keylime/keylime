class ActionError(Exception):
    pass


class ActionUndefined(ActionError):
    pass


class InvalidActionDefinition(ActionError):
    pass


class ActionDispatchError(ActionError):
    pass


class ActionIncompleteError(ActionError):
    pass


class StopAction(Exception):
    pass


class RouteError(Exception):
    pass


class InvalidMethod(RouteError):
    pass


class InvalidPathOrPattern(RouteError):
    pass


class PatternMismatch(RouteError):
    pass


class ControllerError(Exception):
    pass


class ParamDecodeError(ControllerError):
    pass


class RequiredContentMissing(ControllerError):
    pass


class APIMessageError(Exception):
    pass


class InvalidMessage(APIMessageError):
    pass


class MissingMember(InvalidMessage):
    pass


class UnexpectedMember(InvalidMessage):
    pass


class InvalidMember(InvalidMessage):
    pass
