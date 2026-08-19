import os
import sys
import numpy as np
import ember


# ============================================================
# CONFIGURATION
# ============================================================

EXPECTED_FEATURES = 2381

# Use a legitimate Windows PE file for testing.
# This example uses Windows Notepad.
DEFAULT_EXE = r"C:\Windows\System32\notepad.exe"


# ============================================================
# GET FILE PATH
# ============================================================

if len(sys.argv) >= 2:
    exe_path = sys.argv[1]
else:
    exe_path = DEFAULT_EXE


# ============================================================
# CHECK FILE
# ============================================================

print("=" * 65)
print("THREATLENS - EMBER FEATURE EXTRACTOR TEST")
print("=" * 65)

print("\nTesting file:")
print(exe_path)

if not os.path.isfile(exe_path):

    print("\n❌ File not found!")

    print(
        "\nUsage:"
    )

    print(
        'python .\\ml_model\\prediction\\test_extractor.py "path\\to\\file.exe"'
    )

    sys.exit(1)


# ============================================================
# READ FILE
# ============================================================

print("\nReading PE file...")

with open(
    exe_path,
    "rb"
) as f:

    bytez = f.read()


print(
    "File size:",
    f"{len(bytez):,}",
    "bytes"
)


# ============================================================
# CREATE EMBER EXTRACTOR
# ============================================================

print("\nCreating EMBER feature extractor...")

extractor = ember.PEFeatureExtractor(
    feature_version=2
)

print("✅ EMBER feature version 2 selected")


# ============================================================
# EXTRACT FEATURES
# ============================================================

print("\nExtracting features...")

features = extractor.feature_vector(
    bytez
)


# ============================================================
# CONVERT TO NUMPY
# ============================================================

features = np.asarray(
    features,
    dtype=np.float32
)


# ============================================================
# CHECK FEATURE COUNT
# ============================================================

print(
    "\nExtracted features:",
    features.shape[0]
)

print(
    "Expected features:",
    EXPECTED_FEATURES
)


if features.shape[0] != EXPECTED_FEATURES:

    print("\n❌ FEATURE COUNT MISMATCH!")

    print(
        f"EMBER produced {features.shape[0]} "
        f"features, but the model expects "
        f"{EXPECTED_FEATURES}."
    )

    sys.exit(1)


print(
    "\n✅ EXACT FEATURE COUNT MATCH!"
)


# ============================================================
# CHECK VALUES
# ============================================================

print("\nChecking feature values...")

print(
    "NaN values:",
    np.isnan(features).sum()
)

print(
    "Infinite values:",
    np.isinf(features).sum()
)

print(
    "Minimum:",
    np.min(features)
)

print(
    "Maximum:",
    np.max(features)
)


# ============================================================
# CLEAN FEATURES
# ============================================================

features = np.nan_to_num(
    features,
    nan=0.0,
    posinf=0.0,
    neginf=0.0
)


# ============================================================
# FINAL
# ============================================================

print("\n" + "=" * 65)
print("EXTRACTOR TEST COMPLETED")
print("=" * 65)

print("\n✅ PE file successfully read")
print("✅ EMBER feature version 2 loaded")
print("✅ 2,381 features extracted")
print("✅ Feature vector is ready for XGBoost V2")

print("\nNext step:")
print("EXE → EMBER → 2,381 features → XGBoost V2")

print("\n" + "=" * 65)