"""
Pinterest email account-presence: BLOCKED by design.

Pinterest's sign-up email-availability check sits behind reCAPTCHA/
anti-bot controls; this project does not defeat CAPTCHAs, so no
legitimate unauthenticated signal is available.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

PINTEREST = make_blocked_platform(
    "pinterest", "pinterest.com", "social",
    "Pinterest's sign-up email-availability check sits behind "
    "reCAPTCHA/anti-bot controls; this project does not attempt to "
    "defeat those controls.",
)
