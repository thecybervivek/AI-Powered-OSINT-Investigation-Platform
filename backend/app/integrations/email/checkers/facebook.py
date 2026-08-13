"""
Facebook email account-presence: BLOCKED by design.

Facebook's account-recovery "identify" flow deliberately returns a
generic, non-committal response regardless of whether the address is
registered, specifically to prevent enumeration.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

FACEBOOK = make_blocked_platform(
    "facebook", "facebook.com", "social",
    "Facebook's account-recovery flow returns a non-committal response "
    "regardless of whether the address is registered, by design, to "
    "prevent account enumeration; no reliable unauthenticated signal "
    "is available.",
)
