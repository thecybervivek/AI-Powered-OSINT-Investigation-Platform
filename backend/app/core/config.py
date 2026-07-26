from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "AI Powered OSINT Investigation Platform"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "Production Ready AI Powered OSINT Investigation Platform"

    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Security
    SECRET_KEY: str = Field(
        default="CHANGE_ME_BEFORE_PRODUCTION"
    )

    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

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
    URLSCAN_VISIBILITY: str = "public"
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

    REPORT_PDF_STORAGE_DIR: str = "storage/reports"


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()