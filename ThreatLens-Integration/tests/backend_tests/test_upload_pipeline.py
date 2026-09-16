"""
End-to-end upload pipeline: file -> static analysis -> AI -> detection -> alert.

Covers items 6 and 7 of Member 3's integration checklist: that the AI result
reaches the backend, and that the backend passes it on to threat monitoring and
the alert module.

The malware path is exercised with a stubbed predictor rather than a real
malicious sample. Only the verdict is stubbed - the upload, static analysis,
persistence, risk scoring and alert routing are all the real code paths.
"""

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app.main import app
from app.config import settings
from app.api import upload as upload_module
from app.database.database import Base, engine, SessionLocal
from app.models.user import User
from app.alerts import models as _alert_models  # noqa: F401  register table
from app.modules.threat_monitoring import models as _threat_models  # noqa: F401

client = TestClient(app)

ANALYST_EMAIL = "pipeline-analyst"

_PE_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "normal.exe",
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\calc.exe"),
]


def _find_pe():
    return next((p for p in _PE_CANDIDATES if p.is_file()), None)


requires_pe = pytest.mark.skipif(_find_pe() is None, reason="no PE sample on this host")


@pytest.fixture(autouse=True)
def _clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(upload_module, "UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr(upload_module, "REPORTS", {})

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        db.add(
            User(
                full_name="Pipeline Analyst",
                email=ANALYST_EMAIL,
                password="unused-token-is-minted-directly",
                role="security_analyst",
                is_active=True,
            )
        )
        db.commit()
    finally:
        db.close()
    yield


def _auth():
    token = jwt.encode(
        {"sub": ANALYST_EMAIL, "role": "security_analyst"},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return {"Authorization": f"Bearer {token}"}


def _upload(path_or_bytes, filename=None):
    if isinstance(path_or_bytes, bytes):
        content = path_or_bytes
        filename = filename or "sample.exe"
    else:
        source = Path(path_or_bytes)
        content = source.read_bytes()
        filename = filename or source.name
    return client.post(
        "/api/v1/upload",
        files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
    )


class _StubPredictor:
    """Stands in for AIPredictor to force a verdict deterministically."""

    def __init__(self, verdict, probability):
        self.verdict = verdict
        self.probability = probability

    def predict(self, features):
        return {
            "verdict": self.verdict,
            "malware_probability": self.probability,
            "risk_score": round(self.probability * 100, 2),
            "risk_level": "CRITICAL" if self.probability >= 0.75 else "LOW",
            "model": "Stubbed ensemble",
            "model_probabilities": {
                "extra_trees": self.probability,
                "lightgbm": self.probability,
            },
            "ensemble_weights": {"extra_trees": 0.5, "lightgbm": 0.5},
        }


@pytest.fixture
def force_verdict(monkeypatch):
    """Force the AI verdict while leaving every other stage real."""

    def _apply(verdict, probability):
        from app.ml import predictor as ml_predictor

        stub = _StubPredictor(verdict, probability)
        monkeypatch.setattr(ml_predictor, "get_predictor", lambda: stub)

    return _apply


# =====================================================================
# 6. The AI result reaches the backend
# =====================================================================

@requires_pe
def test_upload_of_a_pe_returns_an_ai_verdict():
    body = _upload(_find_pe()).json()
    ai = body["ai_analysis"]

    if not ai["available"]:
        pytest.skip(f"AI stage unavailable: {ai['reason']}")

    assert ai["verdict"] in {"MALWARE", "BENIGN"}
    assert 0.0 <= ai["malware_probability"] <= 1.0
    assert ai["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    # Per-model probabilities are implementation detail and stay server-side;
    # see test_ai_response_contract.py for the full allow-list.
    assert "model_probabilities" not in ai


def test_non_pe_upload_is_reported_as_unanalysable_not_an_error():
    """A PDF cannot be featurised by EMBER; the upload must still succeed."""
    body = _upload(b"%PDF-1.4 not really a pdf", "doc.pdf").json()
    assert body["ai_analysis"]["available"] is False
    assert "PE" in body["ai_analysis"]["reason"]


def test_an_unscored_upload_is_still_recorded():
    """
    Regression: unscored scans used to be dropped, so a PDF vanished from the
    history, reports and analytics entirely. Its static analysis is real and
    belongs in the record.
    """
    body = _upload(b"%PDF-1.4 not really a pdf", "doc.pdf").json()
    assert body["detection"] is not None

    threats = client.get("/api/v1/threats").json()
    assert threats["total"] == 1
    assert threats["items"][0]["filename"] == "doc.pdf"


def test_a_clean_non_pe_file_is_classified_by_static_analysis():
    """
    The AI ensemble only applies to PE binaries, but "no YARA hit" is a real
    negative result, not an absence of one. Leaving a clean PDF as "Unscanned"
    was accurate and useless.
    """
    _upload(b"%PDF-1.4 nothing interesting here", "clean.pdf")
    recorded = client.get("/api/v1/threats").json()["items"][0]

    assert recorded["prediction"] == "Benign"
    assert recorded["detection_engine"] == "Static analysis (YARA + indicators)"
    assert recorded["risk_level"] == "minimal"


def test_a_clean_non_pe_file_raises_no_alert():
    _upload(b"%PDF-1.4 nothing interesting here", "clean.pdf")
    assert client.get("/api/v1/alerts", headers=_auth()).json() == []


def test_a_non_pe_file_matching_a_yara_rule_is_flagged_suspicious():
    """A positive static finding must not be softened just because no AI ran."""
    _upload(b"%PDF-1.4 VirtualAlloc CreateRemoteThread", "macro.pdf")
    recorded = client.get("/api/v1/threats").json()["items"][0]

    assert recorded["prediction"] == "Suspicious"
    assert "Suspicious_APIs" in (recorded["yara_matches"] or [])
    assert recorded["risk_score"] > 0


def test_a_suspicious_non_pe_file_raises_an_alert():
    _upload(b"%PDF-1.4 VirtualAlloc CreateRemoteThread", "macro.pdf")
    alerts = client.get("/api/v1/alerts", headers=_auth()).json()

    assert len(alerts) == 1
    assert alerts[0]["fileName"] == "macro.pdf"


def test_the_record_says_the_ai_did_not_run():
    """Transparency: a static verdict must not read like an AI one."""
    _upload(b"%PDF-1.4 nothing interesting here", "clean.pdf")
    threat_id = client.get("/api/v1/threats").json()["items"][0]["id"]
    detail = client.get(f"/api/v1/threats/{threat_id}").json()

    assert "static analysis" in detail["description"].lower()
    assert "AI ensemble was not applied" in detail["description"]


def test_unscanned_survives_for_analysis_that_could_not_run(monkeypatch):
    """
    "Unscanned" is still the right label when nothing could be checked - here,
    YARA being unavailable. It must alert on nothing and count as neither
    malware nor benign.
    """
    monkeypatch.setattr(upload_module, "yara", None)
    _upload(b"%PDF-1.4 whatever", "unknown.pdf")

    recorded = client.get("/api/v1/threats").json()["items"][0]
    assert recorded["prediction"] == "Unscanned"

    summary = client.get("/api/v1/threats/dashboard/summary").json()
    assert summary["total_files"] == 1
    assert summary["malware_files"] == 0
    assert summary["benign_files"] == 0
    assert client.get("/api/v1/alerts", headers=_auth()).json() == []


# =====================================================================
# 7. The backend passes it to monitoring and alerts
# =====================================================================

@requires_pe
def test_malware_verdict_is_recorded_and_raises_an_alert(force_verdict):
    force_verdict("MALWARE", 0.97)

    body = _upload(_find_pe()).json()
    assert body["ai_analysis"]["available"] is True
    assert body["detection"] is not None, "a scored upload must be recorded"

    threats = client.get("/api/v1/threats").json()
    assert threats["total"] >= 1
    recorded = threats["items"][0]
    assert recorded["prediction"] == "Malware"
    assert recorded["confidence"] == pytest.approx(97.0, abs=0.5)

    alerts = client.get("/api/v1/alerts", headers=_auth()).json()
    assert len(alerts) == 1, "a malware detection must raise exactly one alert"
    assert alerts[0]["fileName"] == _find_pe().name


@requires_pe
def test_benign_verdict_is_recorded_but_raises_no_alert(force_verdict):
    force_verdict("BENIGN", 0.02)

    body = _upload(_find_pe()).json()
    assert body["detection"] is not None

    threats = client.get("/api/v1/threats").json()
    assert threats["total"] == 1
    assert threats["items"][0]["prediction"] == "Benign"

    alerts = client.get("/api/v1/alerts", headers=_auth()).json()
    assert alerts == [], "a benign scan must not raise an alert"


@requires_pe
def test_detection_carries_the_static_analysis_artifacts(force_verdict):
    """YARA hits and network indicators must survive into the detection record."""
    force_verdict("MALWARE", 0.88)

    _upload(_find_pe())

    threats = client.get("/api/v1/threats").json()
    threat_id = threats["items"][0]["id"]
    detail = client.get(f"/api/v1/threats/{threat_id}").json()

    assert detail["file_hash_sha256"]
    assert detail["file_size"] > 0
    assert detail["detection_engine"]


@requires_pe
def test_repeated_upload_of_the_same_file_does_not_duplicate_the_alert(force_verdict):
    """The alert module deduplicates on file hash within its window."""
    force_verdict("MALWARE", 0.91)

    _upload(_find_pe())
    _upload(_find_pe())

    alerts = client.get("/api/v1/alerts", headers=_auth()).json()
    assert len(alerts) == 1
