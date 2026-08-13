"""
GitLab email account-presence: BLOCKED by design.

GitLab does not expose a verified, currently-reliable unauthenticated
endpoint for checking whether an email address is already registered
(its sign-up form's client-side validation targets username
availability, not email). Rather than guess at an undocumented
internal API and risk a wrong CONFIRMED/NOT_FOUND, this reports
BLOCKED with an honest reason and makes no network request.
"""

from backend.app.integrations.email.base_checker import make_blocked_platform

GITLAB = make_blocked_platform(
    "gitlab", "gitlab.com", "development",
    "No verified, reliable unauthenticated email-existence signal is "
    "available for GitLab today; its public sign-up form validates "
    "username availability, not email.",
)
