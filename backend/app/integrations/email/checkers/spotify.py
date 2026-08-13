"""
Spotify email account-presence: BLOCKED by design.

Spotify's sign-up flow validates email client-side but the endpoint is
protected by bot-detection (device/fingerprint challenges) that this
project does not attempt to defeat.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

SPOTIFY = make_blocked_platform(
    "spotify", "spotify.com", "entertainment",
    "Spotify's sign-up email check is protected by bot-detection "
    "(device/fingerprint challenges); no legitimate unauthenticated "
    "signal is available without attempting to defeat those controls.",
)
