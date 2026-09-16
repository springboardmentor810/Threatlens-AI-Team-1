"""
Project-wide configuration.

Single source of truth for the settings that more than one module needs, and
the one place `.env` is loaded.

Why this module exists
----------------------
`python-dotenv` was already a declared dependency but `load_dotenv()` was never
called anywhere, so copying `.env.example` to `.env` had no effect: every
`os.getenv(...)` fell through to its hardcoded default. Two of those defaults
were a committed PostgreSQL password and a JWT signing key that disagreed with
the one the alerts module verifies against.

Import order matters: modules that read configuration at import time (such as
`app.database.database`, which builds the engine once) must import from here,
not from `os.environ` directly, so that `.env` is guaranteed to be loaded first.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# backend/app/config/settings.py -> parents[3] is the repository root
REPO_ROOT = Path(__file__).resolve().parents[3]

# `override=False`: a real environment variable always beats the .env file,
# which is what CI and container deployments expect.
load_dotenv(REPO_ROOT / ".env", override=False)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

# No credentials in source. Set DATABASE_URL in .env for PostgreSQL; the
# SQLite default keeps a fresh clone runnable with no external service.
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./threatlens.db")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

# Must match what app/alerts/config.py reads (JWT_SECRET_KEY / JWT_ALGORITHM),
# or tokens minted by /auth/login are rejected by /api/v1/alerts. The default
# below is deliberately the same placeholder that AlertSettings uses so the two
# agree even when no .env is present.
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")


# ---------------------------------------------------------------------------
# AI / ML
# ---------------------------------------------------------------------------

# Where the trained estimators live. ml_model/inference/ai_predictor.py
# addresses them relative to the current working directory, which only works
# when the process starts at the repository root - the API starts in backend/.
# Resolving from the repo root here makes the location independent of it.
ML_MODEL_DIR: str = os.getenv("ML_MODEL_DIR", str(REPO_ROOT / "ml_model" / "saved_model"))

# Load the models during startup rather than on the first upload. Set false in
# environments that never score files (or to keep test start-up cheap); the
# upload endpoint then reports the AI stage as unavailable and still returns
# its static analysis.
ML_ENABLED: bool = os.getenv("ML_ENABLED", "true").lower() not in {"0", "false", "no"}

_INSECURE_DEFAULT_SECRET = "change-me"


def warn_on_insecure_defaults() -> list[str]:
    """
    Return a list of human-readable warnings about settings that are still at
    their development defaults. Called from the app lifespan so a misconfigured
    deployment is loud at startup instead of silently insecure.
    """
    problems: list[str] = []

    if ENVIRONMENT.lower() in {"development", "dev", "test", "testing"}:
        return problems

    if JWT_SECRET_KEY == _INSECURE_DEFAULT_SECRET:
        problems.append(
            "JWT_SECRET_KEY is still the development placeholder. Set a strong "
            "value in .env before serving real traffic."
        )

    if DATABASE_URL.startswith("sqlite"):
        problems.append(
            f"DATABASE_URL is SQLite ({DATABASE_URL}) outside development. "
            "Set a PostgreSQL URL in .env."
        )

    return problems
