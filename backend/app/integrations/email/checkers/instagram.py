"""
Instagram email account-presence: BLOCKED by design.

Instagram's sign-up/password-reset flows sit behind anti-bot
challenges (rate limiting and CAPTCHA) specifically to prevent this
kind of automated account-existence check.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

INSTAGRAM = make_blocked_platform(
    "instagram", "instagram.com", "social",
    "Instagram's password-reset/signup flows sit behind anti-bot "
    "challenges (rate limiting and CAPTCHA) specifically to prevent "
    "this kind of automated account-existence check; no reliable "
    "unauthenticated signal is available without attempting to "
    "defeat those controls, which this platform does not do.",
)
