"""
Registry of every Email Intelligence account-presence checker, one per
platform, mirroring the priority order given for this module. Two
platforms (GitHub, SoundCloud) have a verified, legitimate,
unauthenticated signal and actually make a request. The rest report
BLOCKED with a specific, honest reason (see each module) rather than
pretending support that doesn't exist.

Gravatar is intentionally NOT in this list even though it's in the
priority order: it already has a mature, independent
GravatarIntegration (see ../gravatar_integration.py) that's also used
for the Email Overview section. base_checker/normalization.py folds
that existing result into Account & Social Presence too, instead of
duplicating a second Gravatar implementation here.
"""

from backend.app.integrations.email.base_checker import PresencePlatform
from backend.app.integrations.email.checkers.discord import DISCORD
from backend.app.integrations.email.checkers.facebook import FACEBOOK
from backend.app.integrations.email.checkers.github import GITHUB
from backend.app.integrations.email.checkers.gitlab import GITLAB
from backend.app.integrations.email.checkers.instagram import INSTAGRAM
from backend.app.integrations.email.checkers.linkedin import LINKEDIN
from backend.app.integrations.email.checkers.pinterest import PINTEREST
from backend.app.integrations.email.checkers.reddit import REDDIT
from backend.app.integrations.email.checkers.soundcloud import SOUNDCLOUD
from backend.app.integrations.email.checkers.spotify import SPOTIFY
from backend.app.integrations.email.checkers.telegram import TELEGRAM
from backend.app.integrations.email.checkers.tiktok import TIKTOK
from backend.app.integrations.email.checkers.twitch import TWITCH
from backend.app.integrations.email.checkers.twitter import X_TWITTER
from backend.app.integrations.email.checkers.youtube import YOUTUBE

ALL_CHECKERS: list[PresencePlatform] = [
    GITHUB,
    GITLAB,
    REDDIT,
    PINTEREST,
    SPOTIFY,
    SOUNDCLOUD,
    X_TWITTER,
    INSTAGRAM,
    FACEBOOK,
    LINKEDIN,
    TIKTOK,
    TWITCH,
    YOUTUBE,
    DISCORD,
    TELEGRAM,
]

__all__ = ["ALL_CHECKERS"]
