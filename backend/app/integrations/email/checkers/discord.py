"""
Discord email account-presence: BLOCKED by design.

Discord's registration endpoint requires solving an hCaptcha challenge
for the email-availability check to run at all; this project does not
attempt to defeat CAPTCHAs.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

DISCORD = make_blocked_platform(
    "discord", "discord.com", "social",
    "Discord's registration endpoint requires solving an hCaptcha "
    "challenge before an email-availability check can run; this "
    "project does not attempt to defeat CAPTCHAs.",
)
