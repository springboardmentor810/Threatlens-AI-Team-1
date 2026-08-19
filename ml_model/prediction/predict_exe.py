import os
import sys
import time
import joblib
import numpy as np
import ember


# ============================================================
# THREATLENS - FINAL MALWARE PREDICTION
# Model: Extra Trees Final 80:20
# Features: EMBER V2 - 2381 features
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = os.path.join(
    "ml_model",
    "saved_model",
    "extra_trees_final_80_20.pkl"
)

EXPECTED_FEATURES = 2381


# ============================================================
# HEADER
# ============================================================

print("=" * 60)
print("THREATLENS - MALWARE DETECTION")
print("=" * 60)


# ============================================================
# CHECK COMMAND LINE
# ============================================================

if len(sys.argv) != 2:

    print("\nUsage:")
    print(
        'python .\\ml_model\\prediction\\predict_exe.py '
        '"path\\to\\file.exe"'
    )

    sys.exit(1)


EXE_PATH = sys.argv[1]


# ============================================================
# CHECK EXE FILE
# ============================================================

if not os.path.isfile(EXE_PATH):

    print("\nERROR: File not found!")
    print("File:", EXE_PATH)

    sys.exit(1)


print("\nFile:", os.path.basename(EXE_PATH))


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading Extra Trees Final model...")

if not os.path.exists(MODEL_PATH):

    print("\nERROR: Model file not found!")
    print("Expected:", MODEL_PATH)

    sys.exit(1)


try:

    model = joblib.load(MODEL_PATH)

    print("Extra Trees Final model loaded successfully!")

except Exception as e:

    print("\nERROR: Could not load model.")
    print(str(e))

    sys.exit(1)


# ============================================================
# CHECK MODEL FEATURES
# ============================================================

if hasattr(model, "n_features_in_"):

    model_features = model.n_features_in_

else:

    model_features = EXPECTED_FEATURES


print(
    "Model features:",
    model_features
)

if model_features != EXPECTED_FEATURES:

    print(
        "\nERROR: Model feature count mismatch!"
    )

    print(
        "Expected:",
        EXPECTED_FEATURES
    )

    print(
        "Model has:",
        model_features
    )

    sys.exit(1)


# ============================================================
# READ PE FILE
# ============================================================

print("\nReading PE file...")

try:

    with open(
        EXE_PATH,
        "rb"
    ) as f:

        bytez = f.read()

except Exception as e:

    print("\nERROR: Could not read EXE file.")
    print(str(e))

    sys.exit(1)


print(
    "File size:",
    f"{len(bytez):,}",
    "bytes"
)


# ============================================================
# CREATE EMBER FEATURE EXTRACTOR
# ============================================================

print("\nCreating EMBER feature extractor...")

try:

    extractor = ember.PEFeatureExtractor(
        feature_version=2
    )

    print("EMBER feature version 2 selected")

except Exception as e:

    print("\nERROR: Could not create EMBER extractor.")
    print(str(e))

    sys.exit(1)


# ============================================================
# EXTRACT FEATURES
# ============================================================

print("\nExtracting EMBER features...")

start_time = time.perf_counter()

try:

    features = extractor.feature_vector(
        bytez
    )

except Exception as e:

    print("\nERROR: Feature extraction failed.")
    print(str(e))

    sys.exit(1)

extraction_time = (
    time.perf_counter() - start_time
)


# ============================================================
# CONVERT FEATURES
# ============================================================

features = np.asarray(
    features,
    dtype=np.float32
)


print(
    "\nExtracted features:",
    len(features)
)

print(
    "Expected features:",
    EXPECTED_FEATURES
)


# ============================================================
# FEATURE COUNT CHECK
# ============================================================

if len(features) != EXPECTED_FEATURES:

    print(
        "\nERROR: Feature count mismatch!"
    )

    print(
        "Expected:",
        EXPECTED_FEATURES
    )

    print(
        "Extracted:",
        len(features)
    )

    sys.exit(1)


print("Feature count confirmed: 2381")


# ============================================================
# CLEAN FEATURE VALUES
# ============================================================

features = np.nan_to_num(
    features,
    nan=0.0,
    posinf=0.0,
    neginf=0.0
)


# ============================================================
# PREPARE MODEL INPUT
# ============================================================

X = features.reshape(
    1,
    -1
)


# ============================================================
# PREDICTION
# ============================================================

print("\nRunning Extra Trees prediction...")

start_time = time.perf_counter()

try:

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

except Exception as e:

    print("\nERROR: Prediction failed.")
    print(str(e))

    sys.exit(1)

prediction_time = (
    time.perf_counter() - start_time
)


# ============================================================
# GET PROBABILITIES
# ============================================================

classes = list(
    model.classes_
)

try:

    benign_index = classes.index(0)
    malware_index = classes.index(1)

    benign_probability = (
        probabilities[benign_index]
    )

    malware_probability = (
        probabilities[malware_index]
    )

except ValueError:

    print(
        "\nERROR: Model does not contain "
        "expected classes 0 and 1."
    )

    print(
        "Model classes:",
        classes
    )

    sys.exit(1)


# ============================================================
# FINAL RESULT
# ============================================================

if prediction == 1:

    result = "MALWARE"
    confidence = malware_probability

else:

    result = "BENIGN"
    confidence = benign_probability


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 60)
print("THREATLENS RESULT")
print("=" * 60)

print(
    "\nPrediction:",
    result
)

print(
    f"Confidence: {confidence * 100:.2f}%"
)

print(
    f"\nBenign probability: "
    f"{benign_probability * 100:.2f}%"
)

print(
    f"Malware probability: "
    f"{malware_probability * 100:.2f}%"
)

print(
    "\nModel: Extra Trees Final 80:20"
)

print(
    "Features: 2381"
)

print(
    f"Feature extraction time: "
    f"{extraction_time:.2f}s"
)

print(
    f"Prediction time: "
    f"{prediction_time:.2f}s"
)


# ============================================================
# FINAL STATUS
# ============================================================

print("\n")
print("=" * 60)
print("PREDICTION COMPLETED")
print("=" * 60)