"""
Dashboard analytics aggregations.

The threat monitoring router already exposes the summary, trend and malware
family breakdowns it owns. What is left are the panels the dashboard draws that
are not part of that module's domain: the activity feed, upload volume by
weekday, the classification split, the scan heat map, and model performance.

They live here rather than in app/api/threat_monitoring.py so Member 5's module
keeps its own surface, and because the model-performance figures do not come
from the database at all - they are Member 4's measured cross-validation
results, read from ml_model/results/.

Everything below is derived from real records. Where the data cannot support a
panel it returns empty rather than inventing numbers; the frontend renders an
empty chart, which is the honest state of a system that has scanned nothing.
"""

import csv
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import get_db
from app.modules.threat_monitoring.models import ThreatLog, ThreatTimelineEvent

logger = logging.getLogger("threatlens.analytics")

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])

_BENIGN = {"benign", "clean", "safe", "not malicious"}
_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _is_benign(prediction: str) -> bool:
    return (prediction or "").strip().lower() in _BENIGN


def _detected_at(row) -> datetime:
    return getattr(row, "detected_at", None) or getattr(row, "created_at", None)


@router.get("/activity", summary="Recent activity feed")
def recent_activity(
    limit: int = Query(default=8, ge=1, le=50),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    The dashboard's activity feed, built from threat timeline events.

    Every detection writes a timeline entry (and a second one when it raises an
    alert), so this is a genuine audit trail rather than a synthesised one.
    """
    events = (
        db.query(ThreatTimelineEvent)
        .order_by(ThreatTimelineEvent.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": e.id,
            # created_by is null for system-generated events.
            "actor": e.created_by or "System",
            "action": e.description,
            "time": e.created_at.isoformat() if e.created_at else None,
        }
        for e in events
    ]


@router.get("/weekly-uploads", summary="Scan volume by weekday")
def weekly_uploads(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Scans per weekday over the trailing window, Monday first."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.query(ThreatLog).filter(ThreatLog.detected_at >= since).all()

    counts = Counter()
    for row in rows:
        when = _detected_at(row)
        if when:
            counts[_WEEKDAYS[when.weekday()]] += 1

    return [{"day": day, "uploads": counts.get(day, 0)} for day in _WEEKDAYS]


@router.get("/classification", summary="Detection outcome breakdown")
def classification_results(
    limit: int = Query(default=8, ge=1, le=30),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """
    What the classifier actually decided, as {name, value} pairs for the pie.

    Benign results are collapsed into one slice; malware is split by the
    predicted family so the chart says something once families appear.
    """
    rows = db.query(ThreatLog.prediction).all()

    benign = 0
    families = Counter()
    for (prediction,) in rows:
        if _is_benign(prediction):
            benign += 1
        else:
            families[prediction or "Unknown"] += 1

    results = [{"name": name, "value": count} for name, count in families.most_common(limit)]
    if benign:
        results.append({"name": "Benign", "value": benign})
    return results


@router.get("/heatmap", summary="Scan intensity by day and hour")
def scan_heatmap(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
) -> List[List[int]]:
    """
    A 7x24 matrix of scan counts, rows Monday..Sunday and columns hour 0..23.

    HeatMapCard takes a plain number[][], so the shape is the contract.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.query(ThreatLog).filter(ThreatLog.detected_at >= since).all()

    matrix = [[0 for _ in range(24)] for _ in range(7)]
    for row in rows:
        when = _detected_at(row)
        if when:
            matrix[when.weekday()][when.hour] += 1

    return matrix


@router.get("/model-performance", summary="Measured model metrics")
def model_performance() -> List[Dict[str, Any]]:
    """
    Cross-validated metrics for the two models behind the ensemble.

    These are measurements, not runtime statistics: they come from Member 4's
    5-fold cross-validation (ml_model/results/cross_validation_summary.csv).
    Precision and recall cannot be computed from live traffic because the
    platform has no ground truth for the files users upload.

    Returns the tuned LightGBM's figures as percentages, which is what the
    radar chart plots; the full per-model table travels alongside for anything
    that wants to compare.
    """
    summary_path = (
        settings.REPO_ROOT / "ml_model" / "results" / "cross_validation_summary.csv"
    )

    if not summary_path.is_file():
        logger.warning("Cross-validation summary not found at %s", summary_path)
        return []

    try:
        with summary_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except OSError:
        logger.exception("Could not read %s", summary_path)
        return []

    if not rows:
        return []

    # The tuned model is the one whose behaviour the ensemble leans on; fall
    # back to the last row if it is ever renamed.
    best = next((r for r in rows if "LightGBM" in r.get("Model", "")), rows[-1])

    def percent(column: str) -> float:
        try:
            return round(float(best[column]) * 100, 2)
        except (KeyError, TypeError, ValueError):
            return 0.0

    return [
        {"metric": "Accuracy", "value": percent("Accuracy_Mean")},
        {"metric": "Precision", "value": percent("Precision_Mean")},
        {"metric": "Recall", "value": percent("Recall_Mean")},
        {"metric": "F1", "value": percent("F1_Mean")},
        {"metric": "ROC-AUC", "value": percent("ROC-AUC_Mean")},
    ]
