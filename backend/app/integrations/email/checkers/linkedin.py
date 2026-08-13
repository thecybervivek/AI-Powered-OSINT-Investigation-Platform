"""
LinkedIn email account-presence: BLOCKED by design.

LinkedIn requires authentication for account-existence-adjacent
endpoints and its terms explicitly prohibit unauthenticated automated
querying; no legitimate unauthenticated signal is available.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

LINKEDIN = make_blocked_platform(
    "linkedin", "linkedin.com", "professional",
    "LinkedIn requires authentication for account-existence-adjacent "
    "endpoints and its terms explicitly prohibit unauthenticated "
    "automated querying; no legitimate unauthenticated signal is "
    "available.",
)
