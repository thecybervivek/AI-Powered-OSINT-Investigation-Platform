"""
Telegram email account-presence: BLOCKED - not applicable.

Telegram accounts are tied to a phone number, not an email address;
there is no email-based account-existence signal to check at all, so
this reports BLOCKED with that explanation rather than a fabricated
result (distinct from the other BLOCKED platforms here, which do have
an email flow that anti-bot controls prevent us from using).
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

TELEGRAM = make_blocked_platform(
    "telegram", "telegram.org", "social",
    "Telegram accounts are tied to a phone number, not an email "
    "address; there is no email-based account-existence signal to "
    "check for this platform.",
)
