"""
Compatibility shims that let the unmaintained `ember` package import and run
against a modern numpy / scikit-learn.

NEITHER SHIM ALTERS FEATURE COMPUTATION. Both restore an API that EMBER was
written against and that its dependencies later removed; the arithmetic that
produces the 2,381 values is untouched. That is deliberate: the models were
trained on EMBER's output, so re-implementing any of it by hand is the change
most likely to move feature values away from what they were trained on.

Why each is needed
------------------
1. ``numpy.int`` - EMBER's features.py calls ``np.zeros(..., dtype=np.int)``.
   numpy removed that alias in 1.24. It was only ever an alias for the builtin
   ``int``, so restoring it changes nothing about the resulting array.

2. ``FeatureHasher.transform`` - EMBER calls
   ``FeatureHasher(50, input_type="string").transform([raw_obj['entry']])``
   where ``entry`` is a single string. Older scikit-learn accepted that;
   current versions raise "Samples can not be a single string. The input must
   be an iterable over iterables of strings." Wrapping a lone string as
   ``[string]`` is exactly the input the old behaviour produced.

Import this module *before* ``ember.features``. ``ember_extractor`` does that
inside its deferred import, so nothing pays the cost unless a file is actually
being featurised.

When EMBER is fixed upstream, or the extractor is vendored, delete this file
and the one call to :func:`apply` in ember_extractor.py.
"""

import logging

logger = logging.getLogger("threatlens.ember_compat")

_applied = False


def _restore_numpy_int() -> None:
    import numpy as np

    if not hasattr(np, "int"):
        # numpy removed this alias in 1.24; it was a plain alias for `int`.
        np.int = int  # type: ignore[attr-defined]


def _patch_feature_hasher() -> None:
    from sklearn.feature_extraction import FeatureHasher

    if getattr(FeatureHasher.transform, "_threatlens_patched", False):
        return

    original_transform = FeatureHasher.transform

    def transform(self, raw_X):
        # Only reshape the exact case EMBER produces: a top-level sequence
        # holding bare strings. Anything already iterable-of-iterables is
        # passed through untouched.
        if self.input_type == "string":
            raw_X = [[item] if isinstance(item, str) else item for item in raw_X]
        return original_transform(self, raw_X)

    transform._threatlens_patched = True  # type: ignore[attr-defined]
    FeatureHasher.transform = transform  # type: ignore[method-assign]


def apply() -> None:
    """Apply both shims once. Safe to call repeatedly."""
    global _applied

    if _applied:
        return

    _restore_numpy_int()
    _patch_feature_hasher()
    _applied = True

    logger.debug(
        "Applied EMBER compatibility shims (numpy.int alias, FeatureHasher "
        "string input). Feature computation is unaffected."
    )
