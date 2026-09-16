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


def _admin_token() -> str:
    from app.database.database import SessionLocal
    from app.models.user import User
    from app.auth.security import hash_password

    admin_email = "bootstrap-admin@example.com"
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == admin_email).first()
        if not user:
            user = User(
                full_name="Bootstrap Admin",
                email=admin_email,
                password=hash_password(PASSWORD),
                role="administrator",
                is_active=True,
            )
            db.add(user)
            db.commit()
    finally:
        db.close()

    return jwt.encode(
        {"sub": admin_email, "role": "administrator"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def _signup(email: str | None = None, full_name: str = "Test Analyst", **overrides):
    payload = {
        "full_name": full_name,
        "email": email or _email("security_analyst"),
        "password": PASSWORD,
    }
    payload.update(overrides)
    return client.post("/api/v1/auth/signup", json=payload), payload


def _register(role: str = "security_analyst", email: str | None = None, auth: bool = True, **overrides):
    payload = {
        "full_name": role.replace("_", " ").title(),
        "email": email or _email(role),
        "password": PASSWORD,
        "role": role,
    }
    payload.update(overrides)
    headers = {"Authorization": f"Bearer {_admin_token()}"} if auth else {}
    return client.post("/api/v1/auth/register", json=payload, headers=headers), payload


def _login(email: str, password: str = PASSWORD):
    return client.post("/api/v1/auth/login", data={"username": email, "password": password})


def _auth_header(role: str = "security_analyst") -> dict:
    _, payload = _register(role)
    token = _login(payload["email"]).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# =====================================================================
# SIGNUP & REGISTRATION
# =====================================================================

def test_signup_creates_security_analyst_user():
    resp, payload = _signup()
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == payload["email"]
    assert body["role"] == "security_analyst"
    assert body["is_active"] is True
    assert "password" not in body


def test_register_requires_admin_token():
    """Unauthenticated call to /register must return 401."""
    resp, _ = _register(role="administrator", auth=False)
    assert resp.status_code == 401


def test_register_forbidden_for_non_admin():
    """Security analyst cannot create arbitrary users via /register."""
    _, analyst_payload = _signup()
    token = _login(analyst_payload["email"]).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "New Admin",
            "email": "newadmin@example.com",
            "password": PASSWORD,
            "role": "administrator",
        },
        headers=headers,
    )
    assert resp.status_code == 403


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


# =====================================================================
# FORGOT & RESET PASSWORD
# =====================================================================

def test_forgot_password_unknown_email_returns_generic_200():
    resp = client.post("/api/v1/auth/forgot-password", json={"email": "unknown@example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "If that address exists" in data["message"]
    assert "dev_reset_link" not in data


def test_forgot_password_known_email_in_dev_returns_link():
    _, payload = _signup()
    resp = client.post("/api/v1/auth/forgot-password", json={"email": payload["email"]})
    assert resp.status_code == 200
    data = resp.json()
    assert "If that address exists" in data["message"]
    assert "dev_reset_link" in data
    assert "/reset-password?token=" in data["dev_reset_link"]


def test_reset_password_changes_password():
    _, payload = _signup()
    forgot_resp = client.post("/api/v1/auth/forgot-password", json={"email": payload["email"]})
    reset_link = forgot_resp.json()["dev_reset_link"]
    token = reset_link.split("token=")[-1]

    new_pass = "BrandNewSecret!99"
    reset_resp = client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": new_pass},
    )
    assert reset_resp.status_code == 200

    # Old password no longer works
    assert _login(payload["email"], PASSWORD).status_code == 401

    # New password works
    login_resp = _login(payload["email"], new_pass)
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()


def test_reset_password_rejects_login_token():
    _, payload = _signup()
    login_token = _login(payload["email"]).json()["access_token"]

    resp = client.post(
        "/api/v1/auth/reset-password",
        json={"token": login_token, "new_password": "NewPassword!123"},
    )
    assert resp.status_code == 400
    assert "Invalid or expired reset token" in resp.json()["detail"]


def test_reset_password_rejects_expired_token():
    from datetime import datetime, timedelta

    expired_token = jwt.encode(
        {
            "sub": "someuser@example.com",
            "purpose": "password_reset",
            "exp": datetime.utcnow() - timedelta(minutes=5),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    resp = client.post(
        "/api/v1/auth/reset-password",
        json={"token": expired_token, "new_password": "NewPassword!123"},
    )
    assert resp.status_code == 400
    assert "Invalid or expired reset token" in resp.json()["detail"]
