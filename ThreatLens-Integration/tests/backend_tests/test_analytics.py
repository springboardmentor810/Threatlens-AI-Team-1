"""
Tests for the dashboard analytics aggregations.

These endpoints exist so the dashboard stops rendering fixtures. What matters
is the shape each one returns, because the chart components read specific keys
and a mismatch renders an empty chart rather than raising - see
frontend/src/api/analyticsApi.ts for the mapping and AnalyticsPage.tsx for the
keys it plots.
"""

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import upload as upload_module
from app.database.database import Base, engine

client = TestClient(app)

_PE_CANDIDATES = [
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\calc.exe"),
]


def _find_pe():
    return next((p for p in _PE_CANDIDATES if p.is_file()), None)


@pytest.fixture(autouse=True)
def _clean_db(tmp_path, monkeypatch):
    monkeypatch.setattr(upload_module, "UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr(upload_module, "REPORTS", {})
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


def _record_a_detection():
    """Drive a real scan so the aggregations have something to aggregate."""
    pe = _find_pe()
    if pe is None:
        pytest.skip("no PE sample on this host")

    resp = client.post(
        "/api/v1/upload",
        files={"file": (pe.name, io.BytesIO(pe.read_bytes()), "application/octet-stream")},
    )
    body = resp.json()
    if not body["ai_analysis"]["available"]:
        pytest.skip(f"AI stage unavailable: {body['ai_analysis']['reason']}")
    return body


# =====================================================================
# ACTIVITY FEED
# =====================================================================

def test_activity_is_empty_before_anything_happens():
    assert client.get("/api/v1/analytics/activity").json() == []


def test_activity_reports_the_timeline_of_a_real_detection():
    _record_a_detection()
    activity = client.get("/api/v1/analytics/activity").json()

    assert len(activity) >= 1
    entry = activity[0]
    assert set(entry) == {"id", "actor", "action", "time"}
    assert entry["actor"]  # never null - system events fall back to "System"
    assert entry["action"]


def test_activity_respects_the_limit():
    _record_a_detection()
    assert len(client.get("/api/v1/analytics/activity?limit=1").json()) <= 1


# =====================================================================
# WEEKLY UPLOADS
# =====================================================================

def test_weekly_uploads_always_returns_seven_days_monday_first():
    data = client.get("/api/v1/analytics/weekly-uploads").json()
    assert [d["day"] for d in data] == ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    assert all(d["uploads"] == 0 for d in data)


def test_weekly_uploads_counts_a_real_scan():
    _record_a_detection()
    data = client.get("/api/v1/analytics/weekly-uploads").json()
    assert sum(d["uploads"] for d in data) == 1


def test_weekly_uploads_uses_the_key_the_bar_chart_plots():
    """AnalyticsPage plots xKey="day", barKey="uploads"."""
    data = client.get("/api/v1/analytics/weekly-uploads").json()
    assert set(data[0]) == {"day", "uploads"}


# =====================================================================
# CLASSIFICATION
# =====================================================================

def test_classification_is_empty_before_anything_is_scanned():
    assert client.get("/api/v1/analytics/classification").json() == []


def test_classification_collapses_benign_into_one_slice():
    _record_a_detection()
    data = client.get("/api/v1/analytics/classification").json()

    assert data, "a scan should produce at least one slice"
    assert all(set(d) == {"name", "value"} for d in data), "PieChartCard reads {name, value}"
    assert sum(d["value"] for d in data) == 1


# =====================================================================
# HEAT MAP
# =====================================================================

def test_heatmap_is_a_seven_by_twentyfour_matrix():
    """HeatMapCard takes a plain number[][]; the shape is the contract."""
    matrix = client.get("/api/v1/analytics/heatmap").json()
    assert len(matrix) == 7
    assert all(len(row) == 24 for row in matrix)
    assert all(isinstance(v, int) for row in matrix for v in row)


def test_heatmap_records_a_real_scan():
    _record_a_detection()
    matrix = client.get("/api/v1/analytics/heatmap").json()
    assert sum(sum(row) for row in matrix) == 1


# =====================================================================
# MODEL PERFORMANCE
# =====================================================================

def test_model_performance_reports_the_measured_cross_validation_metrics():
    """
    These are Member 4's 5-fold results, not runtime statistics - the platform
    has no ground truth for user uploads, so precision and recall cannot be
    computed live.
    """
    data = client.get("/api/v1/analytics/model-performance").json()

    assert [d["metric"] for d in data] == [
        "Accuracy",
        "Precision",
        "Recall",
        "F1",
        "ROC-AUC",
    ]
    assert all(set(d) == {"metric", "value"} for d in data), "RadarChartCard reads {metric, value}"
    # Percentages, and the tuned model measured well above chance on all five.
    assert all(50.0 <= d["value"] <= 100.0 for d in data), data


def test_model_performance_does_not_depend_on_the_database():
    """It reads a CSV, so it must work on a system that has scanned nothing."""
    assert client.get("/api/v1/analytics/model-performance").json()
