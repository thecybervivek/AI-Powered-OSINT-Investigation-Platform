from functools import lru_cache

from pydantic import Field
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "AI Powered OSINT Investigation Platform"
    APP_VERSION: str = "1.0.0-rc.2"
    APP_DESCRIPTION: str = "AI Powered OSINT Investigation Platform release candidate"

    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Production hardening (Milestone 10)
    TRUSTED_HOSTS: list[str] = ["localhost", "127.0.0.1"]
    ENABLE_API_DOCS: bool = True
    ENABLE_HSTS: bool = True
    HSTS_MAX_AGE_SECONDS: int = 63072000

    # Security
    SECRET_KEY: str = Field(
        default="CHANGE_ME_BEFORE_PRODUCTION"
    )

    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "ai-osint-platform"
    JWT_AUDIENCE: str = "ai-osint-api"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_COOKIE_NAME: str = "osint_refresh"
    REFRESH_COOKIE_SECURE: bool = False
    REFRESH_COOKIE_SAMESITE: str = "lax"
    REFRESH_COOKIE_PATH: str = "/api/v1"

    # Database
    DATABASE_URL: str = "sqlite:///./osint.db"
    DATABASE_ECHO: bool = False

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""

    # API
    API_PREFIX: str = "/api/v1"
    API_TITLE: str = "OSINT API"
    API_VERSION: str = "v1"

    # CORS
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # ------------------------------------------------------
    # OSINT Module Configuration (Milestones 2-4)
    # ------------------------------------------------------

    # Outbound HTTP behaviour shared by every integration.
    OSINT_HTTP_USER_AGENT: str = (
        "AI-OSINT-Investigation-Platform/1.0 (+compliance-scan)"
    )
    OSINT_REQUEST_TIMEOUT_SECONDS: float = 8.0
    OSINT_MAX_RETRIES: int = 2
    OSINT_RETRY_BACKOFF_SECONDS: float = 0.5

    # Milestone 2 - Username Intelligence
    USERNAME_CHECK_TIMEOUT_SECONDS: float = 6.0
    USERNAME_MAX_CONCURRENCY: int = 20

    # Milestone 3 - Email Intelligence
    EMAILREP_API_KEY: str = ""
    EMAILREP_BASE_URL: str = "https://emailrep.io"
    HIBP_API_KEY: str = ""
    HIBP_BASE_URL: str = "https://haveibeenpwned.com/api/v3"
    GRAVATAR_BASE_URL: str = "https://www.gravatar.com"

    # Milestone 4 - Domain / IP / DNS Intelligence
    DNS_RESOLVER_TIMEOUT_SECONDS: float = 5.0
    WHOIS_TIMEOUT_SECONDS: float = 8.0
    SSL_CHECK_TIMEOUT_SECONDS: float = 6.0
    IP_GEOLOCATION_BASE_URL: str = "http://ip-api.com/json"
    IPINFO_API_TOKEN: str = ""

    # ------------------------------------------------------
    # Milestone 5 - IP / URL Intelligence & IOC Analysis
    # ------------------------------------------------------

    # AbuseIPDB - community-reported IP abuse confidence scoring.
    # Optional: with no key configured, the integration reports
    # status=skipped rather than failing the investigation.
    ABUSEIPDB_API_KEY: str = ""
    ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"
    ABUSEIPDB_MAX_AGE_DAYS: int = 90

    # VirusTotal - multi-vendor verdict aggregation, used for both the
    # IP module and the URL module. Same optional-skip behaviour.
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # URLScan.io - live sandboxed page analysis for URL targets.
    # Unauthenticated submissions work at a lower rate/visibility, so
    # this one is "degraded, not skipped" when no key is present -
    # the integration still runs, just without the higher API tier.
    URLSCAN_API_KEY: str = ""
    URLSCAN_BASE_URL: str = "https://urlscan.io/api/v1"
    URLSCAN_VISIBILITY: str = "private"
    URLSCAN_ACTIVE_SCANNING_ENABLED: bool = False
    URLSCAN_POLL_TIMEOUT_SECONDS: float = 20.0
    URLSCAN_POLL_INTERVAL_SECONDS: float = 2.0

    # ------------------------------------------------------
    # Inbound API Rate Limiting (protects OUR endpoints, not to be
    # confused with the outbound OSINT_* retry/backoff settings above)
    # ------------------------------------------------------
    #
    # RATE_LIMIT_BACKEND selects the slowapi storage_uri scheme:
    #   "memory" -> "memory://"                         (this milestone)
    #   "redis"  -> built from the existing REDIS_* settings above
    #               (a future milestone; no endpoint code changes then)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_BACKEND: str = "memory"
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_INVESTIGATION: str = "10/minute"
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"
    RATE_LIMIT_REFRESH: str = "10/minute"

    # ------------------------------------------------------
    # Milestone 6 - File Intelligence
    # ------------------------------------------------------

    # Upload handling
    FILE_STORAGE_DIR: str = "storage/uploads"
    FILE_UPLOAD_MAX_SIZE_MB: int = 50
    FILE_HASH_CHUNK_SIZE_BYTES: int = 1024 * 1024  # 1 MB streaming reads

    # Extensions that are outright rejected regardless of MIME sniffing -
    # executables/scripts have no legitimate reason to be "investigated"
    # via upload in an OSINT metadata pipeline and are far higher risk
    # to even write to disk.
    FILE_BLOCKED_EXTENSIONS: list[str] = [
        ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".msi",
        ".ps1", ".vbs", ".js", ".jar", ".sh", ".apk",
    ]

    # Reputation sources (all optional; skipped gracefully without a key)
    VIRUSTOTAL_FILE_LOOKUP_ENABLED: bool = True
    MALWAREBAZAAR_API_KEY: str = ""
    MALWAREBAZAAR_BASE_URL: str = "https://mb-api.abuse.ch/api/v1/"
    HYBRIDANALYSIS_API_KEY: str = ""
    HYBRIDANALYSIS_BASE_URL: str = "https://www.hybrid-analysis.com/api/v2"

    # YARA
    YARA_RULES_DIR: str = "backend/app/integrations/file/yara_rules"
    YARA_SCAN_TIMEOUT_SECONDS: float = 15.0

    # ------------------------------------------------------
    # Milestone 7 - AI Investigation & Report Engine
    # ------------------------------------------------------

    # OpenAI is fully optional. Without OPENAI_API_KEY, the AI Analysis
    # Engine automatically and silently falls back to the deterministic
    # local analyzer - report generation never fails for lack of a key.
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_REQUEST_TIMEOUT_SECONDS: float = 30.0
    EXTERNAL_AI_PROCESSING_ENABLED: bool = False
    AI_REDACT_SENSITIVE_DATA: bool = True

    REPORT_PDF_STORAGE_DIR: str = "storage/reports"


    # ------------------------------------------------------
    # Milestone 9 Part 1 - Phone Intelligence
    # ------------------------------------------------------
    # PhoneValidationIntegration needs no settings at all (fully offline,
    # bundled libphonenumber data). NumVerify is the one optional,
    # network-backed cross-verification source in this module.
    NUMVERIFY_API_KEY: str = ""
    NUMVERIFY_BASE_URL: str = "http://apilayer.net/api/validate"

    # ------------------------------------------------------
    # Milestone 9 Part 2 - Reverse Image Intelligence
    # ------------------------------------------------------
    # Reuses FILE_UPLOAD_MAX_SIZE_MB / FILE_BLOCKED_EXTENSIONS above for
    # size/extension validation (same validate_upload() call as File
    # Intelligence) - only the storage location is dedicated, so images
    # analyzed for reverse-image lookups stay organized separately from
    # generic file uploads on disk.
    IMAGE_STORAGE_DIR: str = "storage/images"

    # ------------------------------------------------------
    # Milestone 9 Part 4 - Breach Intelligence
    # ------------------------------------------------------
    # HIBP_API_KEY/HIBP_BASE_URL above (Milestone 3) are reused as-is for
    # the per-email breach lookup here - not duplicated. DeHashed is the
    # new, optional second source, adding domain-wide exposure search
    # (which HIBP's public API tier doesn't offer) and plaintext/hashed
    # password visibility where DeHashed's dataset has it. Local
    # fallback (no key required at all) reuses the already-integrated
    # EmailRepIntegration's own breach/credential-leak flags.
    DEHASHED_EMAIL: str = ""
    DEHASHED_API_KEY: str = ""
    DEHASHED_BASE_URL: str = "https://api.dehashed.com"

    # ------------------------------------------------------
    # Milestone 9 Part 5 - Threat Intelligence
    # ------------------------------------------------------
    # All five providers are optional and independently key-gated -
    # each reports status=skipped on its own when unconfigured, so any
    # subset (including none) still leaves the module functional.

    # Shodan - internet-wide host scan data: open ports, banners,
    # detected services, org/ASN, hostnames.
    SHODAN_API_KEY: str = ""
    SHODAN_BASE_URL: str = "https://api.shodan.io"

    # Censys - internet-wide host scan data (v2 API, HTTP Basic Auth
    # with an API ID + Secret rather than a single key).
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    CENSYS_BASE_URL: str = "https://search.censys.io/api/v2"

    # GreyNoise Community API - classifies whether an IP is mass
    # internet background-noise scanning activity vs targeted, and
    # flags common legitimate business services (RIOT).
    GREYNOISE_API_KEY: str = ""
    GREYNOISE_BASE_URL: str = "https://api.greynoise.io/v3/community"

    # AlienVault OTX - community threat-pulse reputation (how many
    # threat-intel "pulses" reference this indicator, and from whom).
    OTX_API_KEY: str = ""
    OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1"

    # SecurityTrails - historical/passive DNS intelligence: past IP
    # resolutions for a domain, complementing Milestone 4's live-only
    # DNS lookups with a historical view.
    SECURITYTRAILS_API_KEY: str = ""
    SECURITYTRAILS_BASE_URL: str = "https://api.securitytrails.com/v1"

    # ------------------------------------------------------
    # Milestone 9 Part 6 - DNS Intelligence
    # ------------------------------------------------------
    # Certificate Transparency search (crt.sh) is a free public service
    # requiring no API key - it powers subdomain enumeration here.
    CRT_SH_BASE_URL: str = "https://crt.sh"
    CRT_SH_TIMEOUT_SECONDS: float = 15.0


    @model_validator(mode="after")
    def validate_production_security(self):
        """Fail fast when an unsafe development configuration reaches production."""
        if self.ENVIRONMENT.lower() == "production":
            if self.SECRET_KEY == "CHANGE_ME_BEFORE_PRODUCTION" or len(self.SECRET_KEY) < 32:
                raise ValueError("Production SECRET_KEY must be changed and contain at least 32 characters.")
            if self.DEBUG:
                raise ValueError("DEBUG must be false in production.")
            if "*" in self.ALLOWED_ORIGINS:
                raise ValueError("Wildcard CORS origins are not allowed in production.")
            if not self.REFRESH_COOKIE_SECURE:
                raise ValueError("REFRESH_COOKIE_SECURE must be true in production.")
            if self.RATE_LIMIT_BACKEND == "memory":
                raise ValueError("Production rate limiting must use a shared backend such as Redis.")
        return self


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()