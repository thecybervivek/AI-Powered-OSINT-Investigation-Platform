class IntegrationError(Exception):
    """Base class for all integration-layer errors."""


class IntegrationTimeoutError(IntegrationError):
    """The upstream source did not respond within the configured timeout."""


class IntegrationAuthError(IntegrationError):
    """The configured API key/credential was rejected by the upstream source."""


class IntegrationRateLimitError(IntegrationError):
    """The upstream source rate-limited this request."""


class IntegrationNotConfiguredError(IntegrationError):
    """Required API key/config for this source is missing from settings/.env."""
