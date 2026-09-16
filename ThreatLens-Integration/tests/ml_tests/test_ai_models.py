"""
Tests for the AI/ML layer (Members 3 and 4).

`ml_model/` shipped two scripts named test_*.py that are not tests:
`inference/test_ai_predictor.py` reads `ml_model/dataset/train_test/X_test.parquet`,
which is gitignored and absent from a fresh clone, and
`risk_scoring/test_risk_scorer.py` prints a table and asserts nothing. Both are
useful as demos and are left in place; pytest never collects them because
pytest.ini restricts collection to `tests/`.

These tests need no dataset. They cover the pure risk-scoring logic and, when
the model artifacts are present, that both estimators load and that the
predictor accepts the input shapes its callers actually produce.
"""

import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml_model.risk_scoring.risk_scorer import RiskScorer

REPO_ROOT = Path(__file__).resolve().parents[2]
EXTRA_TREES_PKL = REPO_ROOT / "ml_model" / "saved_model" / "extra_trees_baseline.pkl"
LIGHTGBM_PKL = REPO_ROOT / "ml_model" / "saved_model" / "lightgbm_tuned.pkl"
FEATURE_COUNT = 2381
FEATURE_COLUMNS = [f"F{i}" for i in range(1, FEATURE_COUNT + 1)]

requires_models = pytest.mark.skipif(
    not (EXTRA_TREES_PKL.exists() and LIGHTGBM_PKL.exists()),
    reason="model artifacts not present in ml_model/saved_model/",
)


# =====================================================================
# RISK SCORING  (pure logic, no artifacts needed)
# =====================================================================

@pytest.mark.parametrize(
    "probability,expected",
    [(0.0, 0.0), (0.25, 25.0), (0.5, 50.0), (0.9743, 97.43), (1.0, 100.0)],
)
def test_risk_score_is_probability_as_a_percentage(probability, expected):
    assert RiskScorer.calculate_risk_score(probability) == expected


@pytest.mark.parametrize("probability", [-5.0, -0.1, 1.5, 99.0])
def test_risk_score_clamps_out_of_range_probabilities(probability):
    assert 0.0 <= RiskScorer.calculate_risk_score(probability) <= 100.0


@pytest.mark.parametrize(
    "score,level",
    [
        (0, "LOW"), (24.99, "LOW"),
        (25, "MEDIUM"), (49.99, "MEDIUM"),
        (50, "HIGH"), (74.99, "HIGH"),
        (75, "CRITICAL"), (100, "CRITICAL"),
    ],
)
def test_risk_level_boundaries(score, level):
    assert RiskScorer.get_risk_level(score) == level


@pytest.mark.parametrize(
    "probability,verdict",
    [(0.0, "BENIGN"), (0.4999, "BENIGN"), (0.5, "MALWARE"), (1.0, "MALWARE")],
)
def test_verdict_threshold_is_inclusive_at_one_half(probability, verdict):
    assert RiskScorer.get_verdict(probability) == verdict


def test_verdict_threshold_is_configurable():
    assert RiskScorer.get_verdict(0.7, threshold=0.9) == "BENIGN"
    assert RiskScorer.get_verdict(0.7, threshold=0.6) == "MALWARE"


def test_analyze_returns_the_full_result_shape():
    result = RiskScorer.analyze(0.8123)
    assert result == {
        "verdict": "MALWARE",
        "malware_probability": 0.8123,
        "risk_score": 81.23,
        "risk_level": "CRITICAL",
    }


# =====================================================================
# MODEL ARTIFACTS
# =====================================================================

@requires_models
def test_both_model_artifacts_load():
    import joblib

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        extra_trees = joblib.load(EXTRA_TREES_PKL)
        lightgbm = joblib.load(LIGHTGBM_PKL)

    assert type(extra_trees).__name__ == "ExtraTreesClassifier"
    assert type(lightgbm).__name__ == "LGBMClassifier"


@requires_models
def test_both_models_expect_the_ember_feature_width():
    """
    Pins the contract between backend/app/services/ember_extractor.py, which
    emits 2381 features, and the estimators that consume them.
    """
    import joblib

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for path in (EXTRA_TREES_PKL, LIGHTGBM_PKL):
            model = joblib.load(path)
            assert model.n_features_in_ == FEATURE_COUNT, path.name


# =====================================================================
# PREDICTOR
# =====================================================================

@pytest.fixture(scope="module")
def predictor():
    if not (EXTRA_TREES_PKL.exists() and LIGHTGBM_PKL.exists()):
        pytest.skip("model artifacts not present")

    from ml_model.inference.ai_predictor import AIPredictor

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return AIPredictor()


def _zeros_frame(rows=1, cols=FEATURE_COUNT):
    columns = FEATURE_COLUMNS if cols == FEATURE_COUNT else [f"F{i}" for i in range(1, cols + 1)]
    return pd.DataFrame(np.zeros((rows, cols)), columns=columns)


def test_predictor_ensemble_weights_sum_to_one():
    from ml_model.inference.ai_predictor import AIPredictor

    assert AIPredictor.EXTRA_TREES_WEIGHT + AIPredictor.LIGHTGBM_WEIGHT == 1.0
    assert AIPredictor.EXPECTED_FEATURE_COUNT == FEATURE_COUNT


def test_predictor_accepts_a_flat_feature_sequence(predictor):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = predictor.predict(np.zeros(FEATURE_COUNT).tolist())

    assert result["verdict"] in {"MALWARE", "BENIGN"}
    assert 0.0 <= result["risk_score"] <= 100.0
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(result["model_probabilities"]) == {"extra_trees", "lightgbm"}
    assert set(result["ensemble_weights"]) == {"extra_trees", "lightgbm"}


def test_predictor_accepts_the_dataframe_the_ember_extractor_returns(predictor):
    """
    Regression test. predict() validated the input with len(features), which
    for a DataFrame counts rows — so the single-row frame that
    extract_ember_features() returns was rejected as "1 feature", even though
    predict() has an explicit DataFrame branch. The extractor and the predictor
    could therefore never have been wired together.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = predictor.predict(_zeros_frame())

    assert result["verdict"] in {"MALWARE", "BENIGN"}


def test_predictor_agrees_across_both_input_shapes(predictor):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from_list = predictor.predict(np.zeros(FEATURE_COUNT).tolist())
        from_frame = predictor.predict(_zeros_frame())

    assert from_list == from_frame


@pytest.mark.parametrize("width", [1, 100, 2380, 2382])
def test_predictor_rejects_wrong_feature_widths(predictor, width):
    with pytest.raises(ValueError, match=f"received {width}"):
        predictor.predict(np.zeros(width).tolist())


def test_predictor_rejects_a_wrong_width_dataframe(predictor):
    with pytest.raises(ValueError, match="received 100"):
        predictor.predict(_zeros_frame(cols=100))


def test_predictor_rejects_a_multi_row_dataframe(predictor):
    """One sample at a time; a batch would silently score only the first row."""
    with pytest.raises(ValueError, match="single sample"):
        predictor.predict(_zeros_frame(rows=3))


# =====================================================================
# CROSS-MODULE CONTRACT
# =====================================================================

def test_extractor_and_predictor_agree_on_feature_width():
    """The two halves of the Phase 6b wiring must declare the same width."""
    from app.services import ember_extractor
    from ml_model.inference.ai_predictor import AIPredictor

    assert ember_extractor.EXPECTED_FEATURE_COUNT == AIPredictor.EXPECTED_FEATURE_COUNT
    assert ember_extractor.FEATURE_COLUMNS == FEATURE_COLUMNS
