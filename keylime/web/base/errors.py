class ActionError(Exception):
    pass


class ActionDispatchError(ActionError):
    pass


class ActionIncompleteError(ActionError):
    pass


class RouteError(Exception):
    pass


class InvalidMethod(RouteError):
    pass


class InvalidPathOrPattern(RouteError):
    pass


class ActionUndefined(RouteError):
    pass


class PatternMismatch(RouteError):
    pass
