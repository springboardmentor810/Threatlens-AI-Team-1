"""
Test suite for the Alert & Notification Module (Member 6).

Run from the `backend/` directory so the `app` package resolves:
    cd backend
    pip install -r ../requirements.txt pytest httpx python-multipart
    DATABASE_URL=sqlite:///./test.db ALERT_INGEST_API_KEY=test-key \
        pytest ../tests/backend_tests/test_alerts.py -v

Uses a throwaway SQLite file DB via the DATABASE_URL env var so tests
don't require a running PostgreSQL instance. CI/Member 8 can point this
at a real Postgres instance by setting DATABASE_URL instead.
"""

import os
import sys
import uuid

# Defaults only — conftest.py sets these before any test module is imported,
# which is the only ordering-independent place to do it. Assigning here would
# be too late whenever another module imports app.database.database first.
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_threatlens.db")
os.environ.setdefault("ALERT_INGEST_API_KEY", "test-key")


BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.main import app
from app.config import settings
from app.alerts.database import Base, engine, SessionLocal
from app.alerts.adapters import build_alert_from_threat_event, is_benign
from app.models.user import User



client = TestClient(app)

INTERNAL_HEADERS = {"X-Internal-Api-Key": "test-key"}


def _token(role: str, user_id: str = "user-1") -> dict:
    """
    Mint a token the way /auth/login does: `sub` carries the identifier and
    `role` the RBAC role, signed with the project-wide key.
    """
    t = jwt.encode(
        {"sub": user_id, "role": role},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return {"Authorization": f"Bearer {t}"}


# `sub` doubles as the account identifier: app/alerts/dependencies.py projects
# the authenticated user's email onto CurrentUser.user_id, and
# Alert.recipient_user_id is matched against it when scoping a researcher.
USERS = {
    "analyst-1": "security_analyst",
    "soc-1": "soc_team_member",
    "admin-1": "administrator",
    "researcher-1": "researcher",
}

ANALYST = _token("security_analyst", "analyst-1")
SOC = _token("soc_team_member", "soc-1")
ADMIN = _token("administrator", "admin-1")
RESEARCHER = _token("researcher", "researcher-1")


@pytest.fixture(autouse=True)
def _clean_db():
    """
    Reset the tables before every test for isolation, then seed the accounts
    the tokens above refer to.

    The seeding is needed because the alerts module no longer decodes tokens
    itself: it authenticates through Member 1's dependency, which loads the
    user from the database and rejects inactive accounts. A correctly signed
    token for an account that does not exist is now a 401, which is the point.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        for identifier, role in USERS.items():
            db.add(
                User(
                    full_name=identifier,
                    email=identifier,
                    password="not-used-these-tests-mint-tokens-directly",
                    role=role,
                    is_active=True,
                )
            )
        db.commit()
    finally:
        db.close()

    yield


def _sample_detection(**overrides) -> dict:
    detection = {
        "filename": "invoice.exe",
        "prediction": "Trojan",
        "confidence": 92,
        "risk_score": 95,
        "risk_level": "High Risk",
        "file_hash": "sha256-abc123",
    }
    detection.update(overrides)
    return detection


def _ingest(detection=None) -> dict:
    detection = detection or _sample_detection()
    payload = build_alert_from_threat_event(detection)
    r = client.post("/api/v1/alerts/ingest", json=payload.model_dump(mode="json"), headers=INTERNAL_HEADERS)
    assert r.status_code == 201, r.text
    return r.json()


# 1. Alert creation
def test_create_alert_via_ingest():
    alert = _ingest()
    assert alert["title"].startswith("Trojan detected")
    assert alert["severity"] == "critical"
    assert alert["status"] == "detected"
    assert alert["isRead"] is False


# 2. Alert retrieval (list)
def test_list_alerts():
    _ingest()
    r = client.get("/api/v1/alerts", headers=ANALYST)
    assert r.status_code == 200
    assert len(r.json()) == 1


# 3. Alert retrieval by ID
def test_get_alert_by_id():
    created = _ingest()
    r = client.get(f"/api/v1/alerts/{created['id']}", headers=ANALYST)
    assert r.status_code == 200
    assert r.json()["id"] == created["id"]


# 4. Mark as read
def test_mark_as_read():
    created = _ingest()
    r = client.patch(f"/api/v1/alerts/{created['id']}/read", headers=SOC)
    assert r.status_code == 200
    assert r.json()["isRead"] is True


# 5. Status update
def test_update_status():
    created = _ingest()
    r = client.patch(
        f"/api/v1/alerts/{created['id']}/status",
        json={"status": "under_investigation"},
        headers=ANALYST,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "under_investigation"


# 6. Alert resolution
def test_resolve_alert():
    created = _ingest()
    r = client.patch(f"/api/v1/alerts/{created['id']}/resolve", headers=ANALYST)
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    assert r.json()["resolvedAt"] is not None


# 7. Unauthorized access
def test_list_requires_auth():
    r = client.get("/api/v1/alerts")
    assert r.status_code == 401


def test_soc_cannot_resolve():
    created = _ingest()
    r = client.patch(f"/api/v1/alerts/{created['id']}/resolve", headers=SOC)
    assert r.status_code == 403


def test_ingest_requires_valid_internal_key():
    payload = build_alert_from_threat_event(_sample_detection())
    r = client.post(
        "/api/v1/alerts/ingest",
        json=payload.model_dump(mode="json"),
        headers={"X-Internal-Api-Key": "wrong-key"},
    )
    assert r.status_code == 401


# 8. Invalid alert ID
def test_get_nonexistent_alert_returns_404():
    r = client.get(f"/api/v1/alerts/{uuid.uuid4()}", headers=ANALYST)
    assert r.status_code == 404


def test_update_status_nonexistent_alert_returns_404():
    r = client.patch(
        f"/api/v1/alerts/{uuid.uuid4()}/status",
        json={"status": "resolved"},
        headers=ANALYST,
    )
    assert r.status_code == 404


# 9. Invalid severity/status
def test_invalid_status_value_rejected():
    created = _ingest()
    r = client.patch(
        f"/api/v1/alerts/{created['id']}/status",
        json={"status": "not_a_real_status"},
        headers=ANALYST,
    )
    assert r.status_code == 422


def test_invalid_severity_filter_rejected():
    r = client.get("/api/v1/alerts?severity=not_a_real_severity", headers=ANALYST)
    assert r.status_code == 422


# 10. Duplicate alert prevention
def test_duplicate_detection_does_not_create_second_alert():
    first = _ingest()
    second = _ingest()  # identical detection payload
    assert first["id"] == second["id"]
    r = client.get("/api/v1/alerts", headers=ANALYST)
    assert len(r.json()) == 1


def test_different_file_hash_creates_new_alert():
    _ingest(_sample_detection(file_hash="sha256-aaa"))
    _ingest(_sample_detection(file_hash="sha256-bbb"))
    r = client.get("/api/v1/alerts", headers=ANALYST)
    assert len(r.json()) == 2


# 11. Threat event -> alert generation (adapter)
def test_benign_detection_is_not_alertable():
    assert is_benign("Benign") is True
    with pytest.raises(ValueError):
        build_alert_from_threat_event(_sample_detection(prediction="Benign"))


@pytest.mark.parametrize(
    "risk_level,expected_severity",
    [
        ("High Risk", "critical"),
        ("Medium Risk", "high"),
        ("Low Risk", "medium"),
        ("Minimal Risk", "low"),
    ],
)
def test_risk_level_severity_mapping(risk_level, expected_severity):
    payload = build_alert_from_threat_event(_sample_detection(risk_level=risk_level))
    assert payload.severity.value == expected_severity


# 12. Role-based access
def test_researcher_only_sees_own_alerts():
    payload = build_alert_from_threat_event(_sample_detection(), recipient_user_id="researcher-1")
    client.post("/api/v1/alerts/ingest", json=payload.model_dump(mode="json"), headers=INTERNAL_HEADERS)
    payload2 = build_alert_from_threat_event(_sample_detection(file_hash="sha256-other"))  # no recipient
    client.post("/api/v1/alerts/ingest", json=payload2.model_dump(mode="json"), headers=INTERNAL_HEADERS)

    r = client.get("/api/v1/alerts", headers=RESEARCHER)
    assert len(r.json()) == 1  # only the one addressed to them


def test_admin_can_delete_analyst_cannot():
    created = _ingest()
    r = client.delete(f"/api/v1/alerts/{created['id']}", headers=ANALYST)
    assert r.status_code == 403

    r2 = client.delete(f"/api/v1/alerts/{created['id']}", headers=ADMIN)
    assert r2.status_code == 204


def test_stats_summary():
    _ingest()
    r = client.get("/api/v1/alerts/stats/summary", headers=SOC)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["critical"] == 1


# =====================================================================
# Authentication is now database-backed (Phase 5)
#
# The module used to decode the JWT itself in auth_stub.py, so any correctly
# signed token was accepted. It now authenticates through Member 1's
# dependency, which loads the account and checks it is active.
# =====================================================================

def test_signed_token_for_an_unknown_account_is_rejected():
    """The old stub accepted this; it only ever checked the signature."""
    headers = _token("administrator", "ghost@example.com")
    assert client.get("/api/v1/alerts", headers=headers).status_code == 401


def test_token_for_a_deactivated_account_is_rejected():
    """Deactivating a user now takes effect immediately, not at token expiry."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "analyst-1").first()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    assert client.get("/api/v1/alerts", headers=ANALYST).status_code == 403


def test_token_signed_with_a_foreign_key_is_rejected():
    forged = jwt.encode(
        {"sub": "admin-1", "role": "administrator"}, "not-the-key", algorithm="HS256"
    )
    r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


# =====================================================================
# List filters
#
# Coverage carried over from the fix-alert-module branch's suite, rewritten
# against this module's adapter API. That branch's tests could not be used as
# they stand: they import build_alert_from_classification_event / is_alertable,
# a numeric variant of the adapter that does not exist here.
# =====================================================================

def test_list_filters_by_severity():
    _ingest()  # critical
    _ingest(_sample_detection(risk_level="Low Risk", file_hash="sha256-low"))

    critical = client.get("/api/v1/alerts?severity=critical", headers=ANALYST).json()
    assert [a["severity"] for a in critical] == ["critical"]

    medium = client.get("/api/v1/alerts?severity=medium", headers=ANALYST).json()
    assert [a["severity"] for a in medium] == ["medium"]


def test_list_unread_only_filter():
    first = _ingest()
    _ingest(_sample_detection(file_hash="sha256-second"))

    client.patch(f"/api/v1/alerts/{first['id']}/read", headers=SOC)

    unread = client.get("/api/v1/alerts?unread_only=true", headers=ANALYST).json()
    assert len(unread) == 1
    assert unread[0]["id"] != first["id"]

    everything = client.get("/api/v1/alerts", headers=ANALYST).json()
    assert len(everything) == 2


def test_list_filters_by_status():
    created = _ingest()
    _ingest(_sample_detection(file_hash="sha256-other"))

    client.patch(
        f"/api/v1/alerts/{created['id']}/status",
        json={"status": "under_investigation"},
        headers=ANALYST,
    )

    investigating = client.get("/api/v1/alerts?status=under_investigation", headers=ANALYST).json()
    assert [a["id"] for a in investigating] == [created["id"]]


def test_list_respects_the_limit_parameter():
    for i in range(3):
        _ingest(_sample_detection(file_hash=f"sha256-{i}"))

    assert len(client.get("/api/v1/alerts?limit=2", headers=ANALYST).json()) == 2


def test_risk_score_outside_zero_to_hundred_is_rejected():
    payload = build_alert_from_threat_event(_sample_detection()).model_dump(mode="json")
    payload["risk_score"] = 150.0
    r = client.post("/api/v1/alerts/ingest", json=payload, headers=INTERNAL_HEADERS)
    assert r.status_code == 422
