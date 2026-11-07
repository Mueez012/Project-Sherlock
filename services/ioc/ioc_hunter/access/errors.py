"""Public access failures whose messages never contain credentials."""


class AccessError(RuntimeError):
    """An identity or authorization failure with a transport-neutral status."""

    status_code = 403


class AccessDenied(AccessError):
    status_code = 403

    def __init__(self):
        super().__init__("Access denied")


class AuthenticationRequired(AccessError):
    status_code = 401

    def __init__(self):
        super().__init__("An authenticated identity is required")


class AuthenticationNotConfigured(AccessError):
    status_code = 503

    def __init__(self):
        super().__init__("HTTP authentication is not configured correctly")
