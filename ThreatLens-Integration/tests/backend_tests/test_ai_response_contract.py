"""
The AI module is consumed as a prediction service.

These pin the shape of `ai_analysis` in the upload response: the five fields
the frontend is allowed to map, and nothing that describes how the prediction
was produced. Without a test, per-model probabilities creep back in the next
time someone debugs the ensemble.
"""

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import upload as upload_module
from app.database.database import Base, engine

client = TestClient(app)

# Fields the UI maps: verdict, malware_probability, risk_score, risk_level,
# model - plus the availability flags it needs to choose a state.
ALLOWED_KEYS = {
    "available",
    "status",
    "reason",
    "verdict",
    "malware_probability",
    "risk_score",
    "risk_level",
    "model",
}

# Implementation detail that must never reach the client.
FORBIDDEN_KEYS = {
    "model_probabilities",
    "ensemble_weights",
    "features",
    "feature_vector",
    # Class confidence, inverted for benign verdicts. Removed because a UI
    # labelling it "malware probability" would have shown 94% for a file the
    # model scored at 0.06.
    "confidence_percentage",
}

_PE = next(
    (p for p in (Path(r"C:\Windows\System32\notepad.exe"),
                 Path(r"C:\Windows\System32\calc.exe")) if p.is_file()),
    None,
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(upload_module, "UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr(upload_module, "REPORTS", {})
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def _upload(content: bytes, name: str):
    return client.post(
        "/api/v1/upload",
        files={"file": (name, io.BytesIO(content), "application/octet-stream")},
    ).json()["ai_analysis"]


def test_unavailable_response_exposes_only_allowed_keys():
    ai = _upload(b"%PDF-1.4 not a PE", "doc.pdf")
    assert ai["available"] is False
    assert set(ai) <= ALLOWED_KEYS, set(ai) - ALLOWED_KEYS
    assert ai["reason"]


@pytest.mark.skipif(_PE is None, reason="no PE sample on this host")
def test_scored_response_exposes_only_allowed_keys():
    ai = _upload(_PE.read_bytes(), _PE.name)
    if not ai["available"]:
        pytest.skip(f"AI stage unavailable: {ai['reason']}")
    assert set(ai) <= ALLOWED_KEYS, set(ai) - ALLOWED_KEYS


@pytest.mark.skipif(_PE is None, reason="no PE sample on this host")
def test_scored_response_carries_every_field_the_ui_maps():
    ai = _upload(_PE.read_bytes(), _PE.name)
    if not ai["available"]:
        pytest.skip(f"AI stage unavailable: {ai['reason']}")

    assert ai["verdict"] in {"MALWARE", "BENIGN"}
    assert 0.0 <= ai["malware_probability"] <= 1.0
    assert 0 <= ai["risk_score"] <= 100
    assert ai["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert ai["model"], "Detection Model is rendered from this, never hardcoded"


@pytest.mark.skipif(_PE is None, reason="no PE sample on this host")
def test_no_model_internals_reach_the_client():
    ai = _upload(_PE.read_bytes(), _PE.name)
    leaked = FORBIDDEN_KEYS & set(ai)
    assert not leaked, f"implementation detail exposed: {leaked}"


@pytest.mark.skipif(_PE is None, reason="no PE sample on this host")
def test_malware_probability_is_not_inverted_for_a_benign_verdict():
    """
    The regression that prompted the rename: a benign file scored at 0.06 was
    reported as 94% "confidence". Whatever the verdict, this field is the
    probability of malware, so a benign result must sit at the low end.
    """
    ai = _upload(_PE.read_bytes(), _PE.name)
    if not ai["available"]:
        pytest.skip(f"AI stage unavailable: {ai['reason']}")
    if ai["verdict"] != "BENIGN":
        pytest.skip("host binary was not scored benign")

    assert ai["malware_probability"] < 0.5


# =====================================================================
# Alert wording
# =====================================================================

def test_ai_alerts_say_malware_probability_not_confidence():
    from app.alerts.adapters import build_alert_from_threat_event

    alert = build_alert_from_threat_event({
        "filename": "evil.exe",
        "prediction": "Malware",
        "confidence": 90.0,
        "risk_score": 88,
        "risk_level": "High Risk",
        "detection_engine": "Extra Trees + Tuned LightGBM",
    })
    assert "90.0% malware probability" in alert.message
    assert "confidence" not in alert.message.lower()


def test_static_alerts_do_not_claim_a_probability_they_never_measured():
    """
    A static rule verdict's score is derived from which rules fired, not from a
    model. Calling it a malware probability would be as wrong as calling it
    confidence.
    """
    from app.alerts.adapters import build_alert_from_threat_event

    alert = build_alert_from_threat_event({
        "filename": "macro.pdf",
        "prediction": "Ransomware",
        "confidence": 90.0,
        "risk_score": 92,
        "risk_level": "High Risk",
        "detection_engine": "Static analysis (YARA + indicators)",
    })
    assert "Static analysis flagged" in alert.message
    assert "malware probability" not in alert.message.lower()
    assert "confidence" not in alert.message.lower()
