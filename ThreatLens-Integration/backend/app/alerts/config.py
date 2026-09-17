"""
Configuration for the Alert & Notification Module.

Settings that belong to the whole platform - the database URL and the JWT
signing key/algorithm - are taken from `app.config.settings` rather than being
read from the environment a second time. They used to be declared here with
their own defaults, which is how login came to sign tokens with one key while
this module verified them with another.

What remains below is genuinely alerts-specific: the SMTP channel, the
service-to-service ingest key, and the deduplication window.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import settings as shared_settings


class AlertSettings(BaseSettings):
    # --- Database (shared with the rest of the platform) ---
    database_url: str = Field(default_factory=lambda: shared_settings.DATABASE_URL)

    # --- SMTP / Email notification channel ---
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_name: str = "ThreatLens AI"
    smtp_use_tls: bool = True

    # --- Auth (the same key /auth/login signs with; see app/config/settings.py) ---
    jwt_secret_key: str = Field(default_factory=lambda: shared_settings.JWT_SECRET_KEY)
    jwt_algorithm: str = Field(default_factory=lambda: shared_settings.JWT_ALGORITHM)

    # --- Internal service-to-service auth for Member 5 -> Member 6 calls ---
    # Used only by the POST /api/v1/alerts/ingest endpoint so the Threat
    # Monitoring module (a backend service, not a logged-in user) can raise
    # alerts without needing a user JWT. Replace with a real service-auth
    # mechanism (mTLS, signed internal JWT, etc.) if the team adopts one.
    alert_ingest_api_key: str = "change-me-internal-key"

    # --- Deduplication window (see service.py for strategy) ---
    alert_dedup_window_minutes: int = 15

    environment: str = "development"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = AlertSettings()
