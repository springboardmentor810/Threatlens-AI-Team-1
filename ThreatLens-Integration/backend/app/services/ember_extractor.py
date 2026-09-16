"""
EMBER v2 feature extraction (Member 2).

Turns a PE file into the 2,381-feature vector that the AI models expect —
`ml_model/inference/ai_predictor.py` validates exactly this width, and names
the columns F1..F2381 to match how the models were trained.

Installing EMBER
----------------
EMBER is **not on PyPI**; `pip install ember` fails with "No matching
distribution found". It has to come from source:

    pip install git+https://github.com/elastic/ember.git

The import is therefore deferred into `_get_extractor()` rather than done at
module scope. Importing it eagerly, and building the extractor as a module
level side effect, meant that merely importing this module raised ImportError
on any machine without EMBER — which would take down anything that imported it,
including the upload API once the two are wired together in Phase 6b.

`is_available()` lets callers check for the capability without triggering an
exception, so an upload of a non-PE file can report "static analysis only"
instead of failing.
"""

import os
from typing import Optional

import numpy as np
import pandas as pd

EXPECTED_FEATURE_COUNT = 2381
FEATURE_COLUMNS = [f"F{i}" for i in range(1, EXPECTED_FEATURE_COUNT + 1)]

_extractor = None


def _get_extractor():
    """
    Build the EMBER extractor on first use and cache it.

    Raises RuntimeError with an actionable message when EMBER is absent,
    rather than a bare ImportError from deep inside the call stack.
    """
    global _extractor

    if _extractor is None:
        try:
            # EMBER is unmaintained and does not import cleanly against modern
            # numpy/scikit-learn. These shims restore the APIs it expects
            # without touching how any feature is computed - see ember_compat.
            from app.services import ember_compat

            ember_compat.apply()

            from ember.features import PEFeatureExtractor
        except ImportError as exc:
            raise RuntimeError(
                "EMBER is not installed, so PE feature extraction is "
                "unavailable. It is not on PyPI; install it with: "
                "pip install git+https://github.com/elastic/ember.git"
            ) from exc

        _extractor = PEFeatureExtractor(feature_version=2)

    return _extractor


def is_available() -> bool:
    """True when EMBER can be imported, without raising if it cannot."""
    try:
        _get_extractor()
        return True
    except RuntimeError:
        return False


def extract_ember_features(file_path: str, extractor: Optional[object] = None):
    """
    Extract EMBER v2 features from a PE file.

    Returns a single-row DataFrame with columns F1..F2381, ready to hand to
    ml_model.inference.ai_predictor.AIPredictor.predict().
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found")

    extractor = extractor or _get_extractor()

    with open(file_path, "rb") as f:
        bytez = f.read()

    features = extractor.feature_vector(bytez)

    features = np.array(features).reshape(1, -1)

    if features.shape[1] != EXPECTED_FEATURE_COUNT:
        raise ValueError(
            f"EMBER returned {features.shape[1]} features, expected "
            f"{EXPECTED_FEATURE_COUNT}. Check that feature_version=2 matches "
            f"the version the models in ml_model/saved_model/ were trained on."
        )

    return pd.DataFrame(features, columns=FEATURE_COLUMNS)
