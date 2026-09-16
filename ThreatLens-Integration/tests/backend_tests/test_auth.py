"""
Tests for User Management & Authentication (Member 1).

This module had no test coverage at all before Phase 1 of the integration,
despite every other module depending on the tokens it issues. The
cross-module cases at the bottom are the important ones: they pin down the
contract that broke when the modules were developed on separate branches.

Environment (DATABASE_URL / ALERT_INGEST_API_KEY) comes from conftest.py,
which pytest loads before this module is imported.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.main import app
from app.config import settings
from app.database.database import Base, engine
from app.models import user as _user_model  # noqa: F401  register table
from app.alerts import models as _alert_models  # noqa: F401  register table

client = TestClient(app)

PASSWORD = "Str0ngPass!23"
ALL_ROLES = ["security_analyst", "soc_team_member", "administrator", "researcher"]


@pytest.fixture(autouse=True)
def _clean_db():
    """Reset tables before every test for isolation."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def _email(role: str) -> str:
    return f"{role}-{uuid.uuid4().hex[:8]}@example.com"


def _register(role: str = "security_analyst", email: str | None = None, **overrides):
    payload = {
        "full_name": role.replace("_", " ").title(),
        "email": email or _email(role),
        "password": PASSWORD,
        "role": role,
    }
    payload.update(overrides)
    return client.post("/api/v1/auth/register", json=payload), payload


def _login(email: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/login", data={"username": email, "password": password})


def _auth_header(role: str = "security_analyst") -> dict:
    _, payload = _register(role)
    token = _login(payload["email"]).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# =====================================================================
# REGISTRATION
# =====================================================================

@pytest.mark.parametrize("role", ALL_ROLES)
def test_register_accepts_every_platform_role(role):
    resp, payload = _register(role)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == payload["email"]
    assert body["role"] == role
    assert body["is_active"] is True
    assert "password" not in body


def test_register_rejects_unknown_role():
    resp, _ = _register(role="wizard")
    assert resp.status_code == 422


def test_register_rejects_duplicate_email():
    resp, payload = _register()
    assert resp.status_code == 201
    again, _ = _register(email=payload["email"])
    assert again.status_code == 400


def test_register_rejects_malformed_email():
    resp, _ = _register(email="not-an-email")
    assert resp.status_code == 422


def test_password_is_hashed_not_stored_plaintext():
    _, payload = _register()
    from app.database.database import SessionLocal
    from app.models.user import User

    db = SessionLocal()
    try:
        stored = db.query(User).filter(User.email == payload["email"]).first()
        assert stored is not None
        assert stored.password != PASSWORD
        assert stored.password.startswith("$2b$")
    finally:
        db.close()


# =====================================================================
# LOGIN
# =====================================================================

def test_login_returns_bearer_token():
    _, payload = _register()
    resp = _login(payload["email"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_rejects_wrong_password():
    _, payload = _register()
    assert _login(payload["email"], "WrongPassword!1").status_code == 401


def test_login_rejects_unknown_email():
    assert _login("nobody@example.com").status_code == 401


def test_token_carries_sub_and_role_claims():
    """Every downstream module reads these two claims off the token."""
    _, payload = _register("administrator")
    token = _login(payload["email"]).json()["access_token"]
    claims = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    assert claims["sub"] == payload["email"]
    assert claims["role"] == "administrator"
    assert "exp" in claims


# =====================================================================
# PROFILE
# =====================================================================

def test_profile_requires_authentication():
    assert client.get("/api/v1/auth/profile").status_code == 401


def test_profile_rejects_garbage_token():
    resp = client.get("/api/v1/auth/profile", headers={"Authorization": "Bearer not.a.token"})
    assert resp.status_code == 401


def test_profile_returns_current_user():
    _, payload = _register("researcher")
    token = _login(payload["email"]).json()["access_token"]
    resp = client.get("/api/v1/auth/profile", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == payload["email"]
    assert resp.json()["role"] == "researcher"


def test_profile_update_changes_full_name():
    _, payload = _register()
    token = _login(payload["email"]).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.put("/api/v1/auth/profile", json={"full_name": "Renamed Analyst"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["full_name"] == "Renamed Analyst"


# =====================================================================
# RBAC
# =====================================================================

def test_admin_dashboard_allows_administrator():
    resp = client.get("/api/v1/auth/admin/dashboard", headers=_auth_header("administrator"))
    assert resp.status_code == 200


@pytest.mark.parametrize("role", ["security_analyst", "soc_team_member", "researcher"])
def test_admin_dashboard_denies_non_administrators(role):
    resp = client.get("/api/v1/auth/admin/dashboard", headers=_auth_header(role))
    assert resp.status_code == 403


# =====================================================================
# CROSS-MODULE CONTRACT
#
# These are the regressions Phase 1 fixed. Before it, /auth/login signed
# tokens with a hardcoded key that app/alerts/config.py did not share, and
# UserRole used a two-value title-case vocabulary ("Admin", "Security
# Analyst") that no RBAC check in the alerts module recognised.
# =====================================================================

def test_login_and_alerts_module_share_one_signing_key():
    assert settings.JWT_SECRET_KEY, "JWT_SECRET_KEY must be configured"
    from app.alerts.config import settings as alert_settings

    assert alert_settings.jwt_secret_key == settings.JWT_SECRET_KEY
    assert alert_settings.jwt_algorithm == settings.JWT_ALGORITHM


@pytest.mark.parametrize("role", ALL_ROLES)
def test_login_token_is_accepted_by_the_alerts_api(role):
    """A token straight from /auth/login must authenticate against /api/v1/alerts."""
    resp = client.get("/api/v1/alerts", headers=_auth_header(role))
    assert resp.status_code == 200, resp.text


def test_token_signed_with_a_foreign_key_is_rejected():
    token = jwt.encode(
        {"sub": "attacker@example.com", "role": "administrator"},
        "some-other-key",
        algorithm="HS256",
    )
    resp = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_user_role_vocabulary_matches_the_alerts_rbac_sets():
    """
    Guards against the two vocabularies drifting apart again. Every role the
    alerts router enforces must be a role this service can actually issue.
    """
    from app.schemas.user_schema import UserRole
    from app.alerts import router as alerts_router

    issuable = {r.value for r in UserRole}
    enforced = (
        alerts_router._ALL_VIEW_ROLES
        | alerts_router._UPDATE_ROLES
        | alerts_router._DELETE_ROLES
        | alerts_router._CREATE_ROLES
    )
    assert enforced <= issuable, f"alerts enforces roles auth cannot issue: {enforced - issuable}"
    assert issuable == set(ALL_ROLES)


def test_only_administrator_may_delete_an_alert():
    """End-to-end RBAC across the auth and alerts modules."""
    from app.alerts.config import settings as alert_settings

    ingest = client.post(
        "/api/v1/alerts/ingest",
        headers={"X-Internal-Api-Key": alert_settings.alert_ingest_api_key},
        json={
            "source_reference_id": f"detection-{uuid.uuid4().hex[:8]}",
            "file_name": "evil.exe",
            "file_hash_sha256": "b" * 64,
            "malware_family": "Trojan",
            "risk_score": 90.0,
            "severity": "critical",
            "alert_type": "malware_detected",
            "title": "Malware detected",
            "message": "raised by test",
            "source": "test",
        },
    )
    assert ingest.status_code == 201, ingest.text
    alert_id = ingest.json()["id"]

    denied = client.delete(f"/api/v1/alerts/{alert_id}", headers=_auth_header("security_analyst"))
    assert denied.status_code == 403

    allowed = client.delete(f"/api/v1/alerts/{alert_id}", headers=_auth_header("administrator"))
    assert allowed.status_code == 204
