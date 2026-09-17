"""
Extractor-to-predictor integration tests (Members 2 and 3).

These are the checks Member 3's handoff asked for before the upload API is
connected: that the EMBER extractor produces exactly what AIPredictor expects,
from a real PE file rather than a synthetic vector.

    <PE file> -> extract_ember_features() -> F1..F2381 -> AIPredictor.predict()

They skip when EMBER is not installed (it is not on PyPI; see
backend/requirements.txt) or when no PE sample is available on the host.

What these tests do NOT establish: that the feature *values* match those the
models were trained on. EMBER v2 features were computed with LIEF 0.9.0,
Member 2 validated with 0.11.4, and this runs 0.12.3 - EMBER itself warns of
"slight inconsistencies". Proving equivalence needs a known-good vector from
Member 2's environment to diff against.
"""

import warnings
from pathlib import Path

import numpy as np
import pytest

from app.services import ember_extractor
from ml_model.inference.ai_predictor import AIPredictor

FEATURE_COUNT = 2381
FEATURE_COLUMNS = [f"F{i}" for i in range(1, FEATURE_COUNT + 1)]

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = REPO_ROOT / "ml_model" / "saved_model"

# Candidate PE files: a sample committed by the team if present, otherwise a
# stock Windows binary. Nothing in the repo ships a PE, so this is host-dependent.
_PE_CANDIDATES = [
    REPO_ROOT / "tests" / "fixtures" / "normal.exe",
    Path(r"C:\Windows\System32\notepad.exe"),
    Path(r"C:\Windows\System32\calc.exe"),
]


def _find_pe() -> Path | None:
    return next((p for p in _PE_CANDIDATES if p.is_file()), None)


requires_ember = pytest.mark.skipif(
    not ember_extractor.is_available(),
    reason="EMBER is not installed (pip install git+https://github.com/elastic/ember.git)",
)
requires_models = pytest.mark.skipif(
    not (MODEL_DIR / "extra_trees_baseline.pkl").is_file(),
    reason="model artifacts not present",
)
requires_pe = pytest.mark.skipif(_find_pe() is None, reason="no PE sample available on this host")


@pytest.fixture(scope="module")
def extracted():
    """Extract once; the feature pass is the slow part."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ember_extractor.extract_ember_features(str(_find_pe()))


@pytest.fixture(scope="module")
def predictor():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return AIPredictor()


# =====================================================================
# 1-3. The extracted vector
# =====================================================================

@requires_ember
@requires_pe
def test_extraction_produces_exactly_2381_features(extracted):
    assert extracted.shape == (1, FEATURE_COUNT)


@requires_ember
@requires_pe
def test_feature_names_and_order_are_f1_to_f2381(extracted):
    assert list(extracted.columns) == FEATURE_COLUMNS


@requires_ember
@requires_pe
def test_no_nan_or_inf_reaches_the_model(extracted):
    values = extracted.to_numpy(dtype=np.float64)
    assert not np.isnan(values).any(), f"{int(np.isnan(values).sum())} NaN values"
    assert not np.isinf(values).any(), f"{int(np.isinf(values).sum())} Inf values"


@requires_ember
@requires_pe
def test_extraction_is_not_degenerate(extracted):
    """A vector of all zeros would satisfy the checks above and mean nothing."""
    values = extracted.to_numpy(dtype=np.float64)
    assert np.count_nonzero(values) > 100


# =====================================================================
# 4-5. AIPredictor accepts it and completes
# =====================================================================

@requires_ember
@requires_pe
@requires_models
def test_predictor_accepts_the_extracted_vector(extracted, predictor):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = predictor.predict(extracted)
    assert isinstance(result, dict)


@requires_ember
@requires_pe
@requires_models
def test_prediction_carries_every_documented_field(extracted, predictor):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = predictor.predict(extracted)

    assert {
        "verdict",
        "malware_probability",
        "risk_score",
        "risk_level",
        "model",
        "model_probabilities",
        "ensemble_weights",
    } <= set(result)

    assert result["verdict"] in {"MALWARE", "BENIGN"}
    assert 0.0 <= result["malware_probability"] <= 1.0
    assert 0.0 <= result["risk_score"] <= 100.0
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(result["model_probabilities"]) == {"extra_trees", "lightgbm"}


@requires_ember
@requires_pe
@requires_models
def test_a_stock_windows_binary_is_not_flagged_as_malware(extracted, predictor):
    """
    Directional sanity check. These are Microsoft-signed system binaries; a
    model that calls them malware has something badly wrong, independent of any
    feature-fidelity question.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = predictor.predict(extracted)

    assert result["verdict"] == "BENIGN", (
        f"{_find_pe()} classified as malware "
        f"(probability {result['malware_probability']})"
    )


# =====================================================================
# The compatibility shims
# =====================================================================

def test_shims_are_idempotent_and_preserve_hasher_behaviour():
    from app.services import ember_compat

    ember_compat.apply()
    ember_compat.apply()  # must not double-wrap

    import numpy as np_mod
    from sklearn.feature_extraction import FeatureHasher

    assert np_mod.int is int

    # A bare string is what EMBER passes and what plain sklearn rejects.
    hasher = FeatureHasher(8, input_type="string")
    from_bare = hasher.transform(["entrypoint"]).toarray()
    # Already-nested input must be unaffected by the shim.
    from_nested = hasher.transform([["entrypoint"]]).toarray()

    assert np_mod.array_equal(from_bare, from_nested)
