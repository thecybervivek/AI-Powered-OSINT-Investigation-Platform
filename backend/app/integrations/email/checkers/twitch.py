"""
Twitch email account-presence: BLOCKED by design.

Twitch's sign-up flow validates email but the endpoint sits behind
bot-protection (challenge/CAPTCHA) that this project does not attempt
to defeat.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

TWITCH = make_blocked_platform(
    "twitch", "twitch.tv", "entertainment",
    "Twitch's sign-up email check sits behind bot-protection "
    "(challenge/CAPTCHA); no legitimate unauthenticated signal is "
    "available without attempting to defeat those controls.",
)
