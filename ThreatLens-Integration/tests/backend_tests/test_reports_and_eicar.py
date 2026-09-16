"""
Tests for EICAR detection, PDF report generation, and CSV export.
"""

import io
import csv
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import upload as upload_module
from app.database.database import Base, engine, SessionLocal
from app.models.user import User

client = TestClient(app)

EICAR_BYTES = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
FIXTURE_PE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "sample_benign.exe"


@pytest.fixture(autouse=True)
def _clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(upload_module, "UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr(upload_module, "REPORTS", {})

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def test_eicar_test_file_detected_by_yara_and_classified_malware():
    """EICAR signature must match EICAR_Test_File YARA rule and be flagged as Malware."""
    response = client.post(
        "/api/v1/upload",
        files={"file": ("eicar.pdf", io.BytesIO(EICAR_BYTES), "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()

    assert "EICAR_Test_File" in data["yara_results"]["matched_rules"]
    assert data["detection"] is not None

    threats = client.get("/api/v1/threats").json()
    assert threats["total"] == 1
    threat = threats["items"][0]
    assert threat["prediction"] == "Malware"
    assert threat["confidence"] >= 90.0
    assert "EICAR_Test_File" in (threat["yara_matches"] or [])


def test_real_pe_file_ai_inference_executes_end_to_end():
    """Valid PE binary executes real EMBER feature extraction and AI model prediction."""
    if not FIXTURE_PE.is_file():
        pytest.skip("sample_benign.exe fixture not present")

    pe_content = FIXTURE_PE.read_bytes()
    response = client.post(
        "/api/v1/upload",
        files={"file": ("sample_benign.exe", io.BytesIO(pe_content), "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()

    ai = data["ai_analysis"]
    assert ai["available"] is True
    assert ai["status"] == "Executed"
    assert ai["verdict"] in {"BENIGN", "MALWARE"}
    assert 0.0 <= ai["malware_probability"] <= 1.0
    assert "Extra Trees + Tuned LightGBM" in ai["model"]

    threats = client.get("/api/v1/threats").json()
    assert threats["total"] == 1
    recorded = threats["items"][0]
    assert recorded["prediction"] in {"Benign", "Malware"}
    assert recorded["risk_score"] >= 0


def test_download_individual_threat_report_pdf():
    """GET /api/v1/threats/{id}/report/pdf returns valid PDF binary."""
    # Upload EICAR file first
    client.post(
        "/api/v1/upload",
        files={"file": ("eicar_test.pdf", io.BytesIO(EICAR_BYTES), "application/octet-stream")},
    )
    threats = client.get("/api/v1/threats").json()
    threat_id = threats["items"][0]["id"]

    res = client.get(f"/api/v1/threats/{threat_id}/report/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]
    assert "threatlens_report_" in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF-")


def test_download_summary_report_pdf():
    """GET /api/v1/threats/reports/summary/pdf returns valid summary PDF."""
    client.post(
        "/api/v1/upload",
        files={"file": ("eicar.pdf", io.BytesIO(EICAR_BYTES), "application/octet-stream")},
    )
    res = client.get("/api/v1/threats/reports/summary/pdf?days=30")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-")


def test_export_threats_csv():
    """GET /api/v1/threats/export/csv returns valid CSV containing database records."""
    client.post(
        "/api/v1/upload",
        files={"file": ("eicar_export.pdf", io.BytesIO(EICAR_BYTES), "application/octet-stream")},
    )
    res = client.get("/api/v1/threats/export/csv")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "threatlens_reports_" in res.headers["content-disposition"]

    reader = list(csv.reader(io.StringIO(res.text)))
    assert len(reader) >= 2  # header + at least 1 row
    headers = reader[0]
    assert headers == [
        "id",
        "file_name",
        "file_size",
        "file_type",
        "sha256",
        "md5",
        "threat_score",
        "prediction",
        "confidence",
        "threat_family",
        "detection_engine",
        "yara_rule",
        "status",
        "created_at",
    ]
    row = reader[1]
    assert row[1] == "eicar_export.pdf"
    assert row[7] == "Malware"


def test_download_report_invalid_id_returns_404():
    """Non-existent threat ID returns clean 404 error."""
    res = client.get("/api/v1/threats/non-existent-id-1234/report/pdf")
    assert res.status_code == 404
    assert res.json()["detail"] == "Threat not found"
