"""
YouTube / Google account email presence: BLOCKED by design.

YouTube accounts are Google accounts. Establishing whether a Google
account exists for an address requires either defeating Google's
anti-bot controls or replaying an authenticated Google session -
the same trust-model problem already documented in
ghunt_integration.py (GHuntIntegration/google_intelligence), which
this project intentionally does not do. Google account intelligence
belongs to that dedicated slot, not to a fabricated presence check
here.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

YOUTUBE = make_blocked_platform(
    "youtube", "youtube.com", "entertainment",
    "YouTube accounts are Google accounts; a real signal would require "
    "either defeating anti-bot controls or session-replay against "
    "Google, the same trust-model problem documented for Google "
    "Intelligence (see GHuntIntegration) - this project does not do "
    "either.",
)
