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

    # ------------------------------------------------------
    # Milestone 4 - Domain / IP / DNS Intelligence
    # ------------------------------------------------------
    DNS_RESOLVER_TIMEOUT_SECONDS: float = 5.0
    WHOIS_TIMEOUT_SECONDS: float = 8.0
    SSL_CHECK_TIMEOUT_SECONDS: float = 6.0
    IP_GEOLOCATION_BASE_URL: str = "http://ip-api.com/json"
    IPINFO_API_TOKEN: str = ""

    # ------------------------------------------------------
    # Milestone 5 - IP / URL Intelligence & IOC Analysis
    # ------------------------------------------------------

    # AbuseIPDB
    ABUSEIPDB_API_KEY: str = ""
    ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"
    ABUSEIPDB_MAX_AGE_DAYS: int = 90

    # VirusTotal
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"

    # URLScan.io
    URLSCAN_API_KEY: str = ""
    URLSCAN_BASE_URL: str = "https://urlscan.io/api/v1"
    URLSCAN_VISIBILITY: str = "public"
    URLSCAN_POLL_TIMEOUT_SECONDS: float = 20.0
    URLSCAN_POLL_INTERVAL_SECONDS: float = 2.0

    # ------------------------------------------------------
    # Inbound API Rate Limiting
    # ------------------------------------------------------
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_BACKEND: str = "memory"
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_INVESTIGATION: str = "10/minute"


@lru_cache
def get_settings():
    return Settings()


settings = get_settings()