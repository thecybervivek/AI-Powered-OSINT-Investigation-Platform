from dataclasses import dataclass
from enum import Enum


class DetectionMethod(str, Enum):
    """
    How we decide a profile exists once the HTTP response comes back.
    Mirrors the detection strategies used by public username-enumeration
    tools: some sites 404 cleanly, others always return 200 and instead
    render an error string in the body, or redirect away entirely.
    """

    STATUS_CODE = "status_code"
    ERROR_STRING_IN_BODY = "error_string_in_body"
    REDIRECT_ON_MISSING = "redirect_on_missing"


@dataclass(frozen=True)
class PlatformDefinition:

    name: str
    category: str
    url_template: str
    detection_method: DetectionMethod
    # Present only for ERROR_STRING_IN_BODY: substring found on the page
    # when the profile does NOT exist.
    missing_marker: str | None = None
    # HTTP status that indicates "exists" for STATUS_CODE detection.
    existing_status: int = 200


# ==========================================================
# Platform Catalogue
# ==========================================================
# A single shared catalogue keeps URL patterns consistent across the
# three engines below; each engine simply selects a different slice
# (and, for Maigret, layers on lightweight bio/metadata extraction).

PLATFORM_CATALOGUE: list[PlatformDefinition] = [
    PlatformDefinition("GitHub", "development", "https://github.com/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("GitLab", "development", "https://gitlab.com/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Bitbucket", "development", "https://bitbucket.org/{}/", DetectionMethod.STATUS_CODE),
    PlatformDefinition("StackOverflow", "development", "https://stackoverflow.com/users/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Dev.to", "development", "https://dev.to/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Replit", "development", "https://replit.com/@{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Docker Hub", "development", "https://hub.docker.com/u/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("npm", "development", "https://www.npmjs.com/~{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("PyPI", "development", "https://pypi.org/user/{}/", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Kaggle", "development", "https://www.kaggle.com/{}", DetectionMethod.STATUS_CODE),

    PlatformDefinition("X (Twitter)", "social", "https://x.com/{}", DetectionMethod.ERROR_STRING_IN_BODY, "This account doesn\u2019t exist"),
    PlatformDefinition("Instagram", "social", "https://www.instagram.com/{}/", DetectionMethod.ERROR_STRING_IN_BODY, "Sorry, this page"),
    PlatformDefinition("Reddit", "social", "https://www.reddit.com/user/{}/about.json", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Facebook", "social", "https://www.facebook.com/{}", DetectionMethod.ERROR_STRING_IN_BODY, "content isn't available"),
    PlatformDefinition("Pinterest", "social", "https://www.pinterest.com/{}/", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Tumblr", "social", "https://{}.tumblr.com/", DetectionMethod.STATUS_CODE),
    PlatformDefinition("LinkedIn", "social", "https://www.linkedin.com/in/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Snapchat", "social", "https://www.snapchat.com/add/{}", DetectionMethod.ERROR_STRING_IN_BODY, "not found"),
    PlatformDefinition("VKontakte", "social", "https://vk.com/{}", DetectionMethod.ERROR_STRING_IN_BODY, "not been found"),
    PlatformDefinition("Threads", "social", "https://www.threads.net/@{}", DetectionMethod.ERROR_STRING_IN_BODY, "Sorry, this page"),

    PlatformDefinition("YouTube", "media", "https://www.youtube.com/@{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Twitch", "media", "https://www.twitch.tv/{}", DetectionMethod.ERROR_STRING_IN_BODY, "sorry_train"),
    PlatformDefinition("TikTok", "media", "https://www.tiktok.com/@{}", DetectionMethod.ERROR_STRING_IN_BODY, "Couldn't find this account"),
    PlatformDefinition("Vimeo", "media", "https://vimeo.com/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("SoundCloud", "media", "https://soundcloud.com/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Spotify", "media", "https://open.spotify.com/user/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Flickr", "media", "https://www.flickr.com/people/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Medium", "media", "https://medium.com/@{}", DetectionMethod.STATUS_CODE),

    PlatformDefinition("Keybase", "identity", "https://keybase.io/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("About.me", "identity", "https://about.me/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Gravatar", "identity", "https://en.gravatar.com/{}", DetectionMethod.ERROR_STRING_IN_BODY, "Profile not found"),
    PlatformDefinition("Patreon", "identity", "https://www.patreon.com/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Ko-fi", "identity", "https://ko-fi.com/{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Telegram", "messaging", "https://t.me/{}", DetectionMethod.ERROR_STRING_IN_BODY, "If you have Telegram"),
    PlatformDefinition("HackerNews", "forums", "https://news.ycombinator.com/user?id={}", DetectionMethod.ERROR_STRING_IN_BODY, "No such user"),
    PlatformDefinition("Product Hunt", "forums", "https://www.producthunt.com/@{}", DetectionMethod.STATUS_CODE),
    PlatformDefinition("Steam", "gaming", "https://steamcommunity.com/id/{}", DetectionMethod.ERROR_STRING_IN_BODY, "The specified profile could not be found"),
    PlatformDefinition("Chess.com", "gaming", "https://www.chess.com/member/{}", DetectionMethod.STATUS_CODE),
]


# Engine-specific slices. Real Sherlock/Maigret/WhatsMyName ship
# hundreds of sites each pulled from independently maintained JSON
# data files; here each engine draws a distinct, deterministic slice
# of the shared catalogue by category so the three sources return
# genuinely different (but overlapping, as in real life) coverage.

def sherlock_platforms() -> list[PlatformDefinition]:
    return [
        p for p in PLATFORM_CATALOGUE
        if p.category in {"social", "development", "media"}
    ]


def maigret_platforms() -> list[PlatformDefinition]:
    return [
        p for p in PLATFORM_CATALOGUE
        if p.category in {"social", "identity", "forums", "messaging"}
    ]


def whatsmyname_platforms() -> list[PlatformDefinition]:
    return [
        p for p in PLATFORM_CATALOGUE
        if p.category in {"development", "gaming", "identity", "media"}
    ]
