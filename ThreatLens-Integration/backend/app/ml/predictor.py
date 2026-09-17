"""
Backend adapter for the AI inference pipeline (bridges Members 3 and 2).

`ml_model/inference/ai_predictor.py` is Member 3's module and is written to be
run from the repository root as a script. Three things have to change before an
API can call it, and none of them belong in Member 3's file:

  * **Model location.** AIPredictor addresses `ml_model/saved_model/*.pkl`
    relative to the current working directory. The API starts in `backend/`, so
    those paths do not resolve. Here they come from `settings.ML_MODEL_DIR`,
    which defaults to a path derived from the repository root.

  * **Load cost.** `AIPredictor()` joblib-loads a 47 MB ExtraTrees forest and a
    LightGBM booster. Doing that per request would add seconds to every upload,
    so the instance is built once and reused. `warm_up()` is called from the
    application lifespan so the cost is paid at start-up, not by the first user.

  * **Blocking work in an async endpoint.** scikit-learn and LightGBM inference
    is CPU-bound and releases no control to the event loop. `predict()` is
    therefore async and hands the work to a worker thread; calling the
    estimators directly from a coroutine would stall every other request.

Absence is not an error. If the artifacts are missing, or ML_ENABLED is false,
`is_available()` reports false and the upload endpoint returns its static
analysis with the AI stage marked unavailable.
"""

import logging
import sys
import threading
from pathlib import Path
from typing import Any, Optional

from starlette.concurrency import run_in_threadpool

from app.config import settings

logger = logging.getLogger("threatlens.ml")

EXTRA_TREES_FILENAME = "extra_trees_baseline.pkl"
LIGHTGBM_FILENAME = "lightgbm_tuned.pkl"

_predictor: Optional[Any] = None
_load_failed = False
_lock = threading.Lock()


def model_dir() -> Path:
    return Path(settings.ML_MODEL_DIR)


def artifacts_present() -> bool:
    directory = model_dir()
    return (directory / EXTRA_TREES_FILENAME).is_file() and (
        directory / LIGHTGBM_FILENAME
    ).is_file()


def _ensure_ml_model_importable() -> None:
    """
    Put the repository root on sys.path so `ml_model` can be imported.

    `backend/` and `ml_model/` are siblings, and the API is started from inside
    `backend/` (its package imports are `app.*`), so the repository root is not
    on the path by default. pytest supplies it through pytest.ini's
    `pythonpath = backend .`; uvicorn has no equivalent.

    The alternative is packaging ml_model and installing it, which is the right
    long-term answer but changes how every member runs their scripts.
    """
    root = str(settings.REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _build_predictor():
    """
    Instantiate Member 3's AIPredictor with the model paths resolved.

    Subclassed rather than mutating AIPredictor's class attributes, so running
    `python ml_model/inference/test_ai_predictor.py` from the repository root
    keeps behaving exactly as it did.
    """
    _ensure_ml_model_importable()

    from ml_model.inference.ai_predictor import AIPredictor

    directory = model_dir()

    class _ResolvedPathPredictor(AIPredictor):
        EXTRA_TREES_PATH = str(directory / EXTRA_TREES_FILENAME)
        LIGHTGBM_PATH = str(directory / LIGHTGBM_FILENAME)

    return _ResolvedPathPredictor()


def get_predictor():
    """
    Return the shared predictor, loading it on first use.

    Returns None when the models cannot be loaded. A failed load is remembered
    so that every subsequent upload does not retry a 47 MB read.
    """
    global _predictor, _load_failed

    if _predictor is not None:
        return _predictor

    if _load_failed or not settings.ML_ENABLED:
        return None

    with _lock:
        # Re-check: another thread may have loaded it while this one waited.
        if _predictor is not None:
            return _predictor
        if _load_failed:
            return None

        if not artifacts_present():
            _load_failed = True
            logger.warning(
                "AI models not found in %s. Uploads will be analysed statically "
                "only. Expected %s and %s.",
                model_dir(),
                EXTRA_TREES_FILENAME,
                LIGHTGBM_FILENAME,
            )
            return None

        try:
            _predictor = _build_predictor()
            logger.info("AI models loaded from %s.", model_dir())
        except Exception:
            _load_failed = True
            logger.exception(
                "Failed to load the AI models from %s. Uploads will be analysed "
                "statically only.",
                model_dir(),
            )
            return None

    return _predictor


def is_available() -> bool:
    """True when a prediction can actually be produced."""
    return get_predictor() is not None


def warm_up() -> bool:
    """
    Load the models during application start-up.

    Returns True when the predictor is ready. Never raises: a missing model
    must not stop the API from serving auth, alerts and threat monitoring.
    """
    if not settings.ML_ENABLED:
        logger.info("ML_ENABLED is false; skipping AI model load.")
        return False

    return get_predictor() is not None


async def predict(features) -> Optional[dict]:
    """
    Score one sample, off the event loop.

    `features` is either a flat 2381-value sequence or the single-row DataFrame
    that app.services.ember_extractor.extract_ember_features() returns.

    Returns AIPredictor's result dict, or None when the models are unavailable.
    Propagates ValueError for a malformed feature vector, because that is a
    caller error worth surfacing rather than silently degrading.
    """
    predictor = get_predictor()
    if predictor is None:
        return None

    return await run_in_threadpool(predictor.predict, features)


def reset_for_tests() -> None:
    """Drop the cached predictor so tests can exercise the load path."""
    global _predictor, _load_failed
    with _lock:
        _predictor = None
        _load_failed = False
