"""
TikTok email account-presence: BLOCKED by design.

TikTok's sign-up email-availability check is protected by CAPTCHA/
anti-bot controls that this project does not attempt to defeat.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

TIKTOK = make_blocked_platform(
    "tiktok", "tiktok.com", "entertainment",
    "TikTok's sign-up email-availability check is protected by "
    "CAPTCHA/anti-bot controls; no legitimate unauthenticated signal "
    "is available without attempting to defeat those controls.",
)
