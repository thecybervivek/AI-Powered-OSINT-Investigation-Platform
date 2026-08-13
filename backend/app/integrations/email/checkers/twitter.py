"""
X / Twitter email account-presence: BLOCKED by design.

X's email-availability endpoint requires a guest token and is
aggressively anti-bot walled (rate limiting, challenge responses)
specifically to prevent this kind of automated check.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

X_TWITTER = make_blocked_platform(
    "x_twitter", "x.com", "social",
    "X's email-availability endpoint requires a guest token and is "
    "aggressively anti-bot walled; no reliable unauthenticated signal "
    "is available without attempting to defeat those controls.",
)
