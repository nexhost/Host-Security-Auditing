class NexhostError(Exception):
    """Base expected application error."""


class ConfigurationError(NexhostError):
    pass


class ValidationError(NexhostError):
    pass


class AuthorizationRequired(ValidationError):
    pass


class ScopeViolation(ValidationError):
    pass


class ScannerError(NexhostError):
    pass


class ScannerUnavailable(ScannerError):
    pass


class ScannerTimeout(ScannerError):
    pass


class ParseError(NexhostError):
    pass

