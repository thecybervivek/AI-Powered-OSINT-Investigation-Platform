"""
Reddit email account-presence: BLOCKED by design.

Reddit's account-recovery flow deliberately returns the same generic
response regardless of whether the address is registered, specifically
to prevent this kind of enumeration - there is no unauthenticated
endpoint that positively confirms or denies an email is in use.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

REDDIT = make_blocked_platform(
    "reddit", "reddit.com", "social",
    "Reddit's account-recovery flow returns a non-committal response "
    "regardless of whether the address is registered, by design, to "
    "prevent account enumeration; no reliable unauthenticated signal "
    "is available.",
)
