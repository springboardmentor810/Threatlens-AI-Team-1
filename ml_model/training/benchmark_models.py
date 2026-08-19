import os
import time
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


# ============================================================
# CONFIGURATION
# ============================================================

TEST_PATH = (
    "ml_model/dataset/raw/ember2018/"
    "test_ember_2018_v2_features.parquet"
)

EXTRA_TREES_PATH = (
    "ml_model/saved_model/"
    "extra_trees_ember_v2.pkl"
)

XGBOOST_PATH = (
    "ml_model/saved_model/"
    "xgboost_ember_v2.json"
)

RESULT_PATH = (
    "ml_model/training/"
    "model_benchmark_results.csv"
)

EXPECTED_FEATURES = 2381

# To avoid excessive RAM usage
CHUNK_SIZE = 25000


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("THREATLENS - MODEL BENCHMARK")
print("=" * 70)


# ============================================================
# CHECK FILES
# ============================================================

print("\nChecking required files...")

for path in [
    TEST_PATH,
    EXTRA_TREES_PATH,
    XGBOOST_PATH,
]:

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"\n❌ File not found:\n{path}"
        )

    print(
        "✅",
        path
    )


# ============================================================
# READ TEST DATA METADATA
# ============================================================

print("\nReading test dataset metadata...")

import pyarrow.parquet as pq

parquet_file = pq.ParquetFile(
    TEST_PATH
)

total_rows = parquet_file.metadata.num_rows

columns = parquet_file.schema.names

print(
    "Total test rows:",
    total_rows
)

print(
    "Total columns:",
    len(columns)
)


# ============================================================
# LOAD TEST DATA
# ============================================================

print("\nLoading test dataset...")

df = pd.read_parquet(
    TEST_PATH
)

print(
    "Dataset loaded:",
    df.shape
)


# ============================================================
# IDENTIFY LABEL
# ============================================================

if "Label" not in df.columns:

    raise ValueError(
        "Label column not found!"
    )

print(
    "\nOriginal label distribution:"
)

print(
    df["Label"].value_counts()
)


# ============================================================
# REMOVE UNKNOWN LABELS
# ============================================================

print(
    "\nRemoving unknown labels (-1)..."
)

df = df[
    df["Label"].isin([0, 1])
].copy()

print(
    "Samples after cleaning:",
    len(df)
)


# ============================================================
# PREPARE FEATURES
# ============================================================

feature_columns = [
    col
    for col in df.columns
    if col != "Label"
]


print(
    "\nNumber of features:",
    len(feature_columns)
)


if len(feature_columns) != EXPECTED_FEATURES:

    raise ValueError(
        f"Expected {EXPECTED_FEATURES} "
        f"features but found "
        f"{len(feature_columns)}"
    )


X_test = df[
    feature_columns
].astype(
    np.float32
)

y_test = df[
    "Label"
].astype(
    np.int8
)


# ============================================================
# CLEAN DATA
# ============================================================

print(
    "\nCleaning test features..."
)

X_test = X_test.replace(
    [np.inf, -np.inf],
    np.nan
)

X_test = X_test.fillna(
    0
)

print(
    "✅ Test data ready"
)

print(
    "Test shape:",
    X_test.shape
)


# ============================================================
# RESULTS STORAGE
# ============================================================

results = []


# ============================================================
# EXTRA TREES
# ============================================================

print("\n")
print("=" * 70)
print("EXTRA TREES")
print("=" * 70)

print(
    "\nLoading Extra Trees model..."
)

extra_trees = joblib.load(
    EXTRA_TREES_PATH
)

print(
    "✅ Extra Trees loaded"
)

print(
    "Number of trees:",
    extra_trees.n_estimators
)


# ------------------------------------------------------------
# EXTRA TREES PREDICTION
# ------------------------------------------------------------

print(
    "\nRunning Extra Trees predictions..."
)

start_time = time.perf_counter()

et_predictions = extra_trees.predict(
    X_test
)

et_probabilities = extra_trees.predict_proba(
    X_test
)[:, 1]

et_prediction_time = (
    time.perf_counter()
    - start_time
)


# ------------------------------------------------------------
# EXTRA TREES METRICS
# ------------------------------------------------------------

et_accuracy = accuracy_score(
    y_test,
    et_predictions
)

et_precision = precision_score(
    y_test,
    et_predictions,
    zero_division=0
)

et_recall = recall_score(
    y_test,
    et_predictions,
    zero_division=0
)

et_f1 = f1_score(
    y_test,
    et_predictions,
    zero_division=0
)

et_auc = roc_auc_score(
    y_test,
    et_probabilities
)

et_cm = confusion_matrix(
    y_test,
    et_predictions
)


print("\nEXTRA TREES RESULTS")

print(
    f"Accuracy     : {et_accuracy:.4f}"
)

print(
    f"Precision    : {et_precision:.4f}"
)

print(
    f"Recall       : {et_recall:.4f}"
)

print(
    f"F1 Score     : {et_f1:.4f}"
)

print(
    f"ROC-AUC      : {et_auc:.4f}"
)

print(
    f"Prediction Time: {et_prediction_time:.2f}s"
)

print(
    "\nConfusion Matrix:"
)

print(
    et_cm
)


results.append(
    {
        "Model": "Extra Trees",
        "Accuracy": et_accuracy,
        "Precision": et_precision,
        "Recall": et_recall,
        "F1": et_f1,
        "ROC-AUC": et_auc,
        "Train Time": np.nan,
        "Prediction Time": et_prediction_time,
    }
)


# ============================================================
# XGBOOST
# ============================================================

print("\n")
print("=" * 70)
print("XGBOOST")
print("=" * 70)

print(
    "\nLoading XGBoost V2 model..."
)

xgb_model = xgb.XGBClassifier()

xgb_model.load_model(
    XGBOOST_PATH
)

print(
    "✅ XGBoost loaded"
)

print(
    "Number of features:",
    xgb_model.n_features_in_
)


if xgb_model.n_features_in_ != EXPECTED_FEATURES:

    raise ValueError(
        f"XGBoost expects "
        f"{xgb_model.n_features_in_} "
        f"features"
    )


# ------------------------------------------------------------
# XGBOOST PREDICTION
# ------------------------------------------------------------

print(
    "\nRunning XGBoost predictions..."
)

start_time = time.perf_counter()

xgb_predictions = xgb_model.predict(
    X_test
)

xgb_probabilities = xgb_model.predict_proba(
    X_test
)[:, 1]

xgb_prediction_time = (
    time.perf_counter()
    - start_time
)


# ------------------------------------------------------------
# XGBOOST METRICS
# ------------------------------------------------------------

xgb_accuracy = accuracy_score(
    y_test,
    xgb_predictions
)

xgb_precision = precision_score(
    y_test,
    xgb_predictions,
    zero_division=0
)

xgb_recall = recall_score(
    y_test,
    xgb_predictions,
    zero_division=0
)

xgb_f1 = f1_score(
    y_test,
    xgb_predictions,
    zero_division=0
)

xgb_auc = roc_auc_score(
    y_test,
    xgb_probabilities
)

xgb_cm = confusion_matrix(
    y_test,
    xgb_predictions
)


print("\nXGBOOST RESULTS")

print(
    f"Accuracy     : {xgb_accuracy:.4f}"
)

print(
    f"Precision    : {xgb_precision:.4f}"
)

print(
    f"Recall       : {xgb_recall:.4f}"
)

print(
    f"F1 Score     : {xgb_f1:.4f}"
)

print(
    f"ROC-AUC      : {xgb_auc:.4f}"
)

print(
    f"Prediction Time: {xgb_prediction_time:.2f}s"
)

print(
    "\nConfusion Matrix:"
)

print(
    xgb_cm
)


results.append(
    {
        "Model": "XGBoost",
        "Accuracy": xgb_accuracy,
        "Precision": xgb_precision,
        "Recall": xgb_recall,
        "F1": xgb_f1,
        "ROC-AUC": xgb_auc,
        "Train Time": np.nan,
        "Prediction Time": xgb_prediction_time,
    }
)


# ============================================================
# FINAL COMPARISON
# ============================================================

results_df = pd.DataFrame(
    results
)


# ============================================================
# DISPLAY
# ============================================================

print("\n")
print("=" * 70)
print("FINAL MODEL COMPARISON")
print("=" * 70)

display_df = results_df.copy()

for column in [
    "Accuracy",
    "Precision",
    "Recall",
    "F1",
    "ROC-AUC",
]:

    display_df[column] = (
        display_df[column] * 100
    ).round(2)

print(
    display_df[
        [
            "Model",
            "Accuracy",
            "Precision",
            "Recall",
            "F1",
            "ROC-AUC",
            "Train Time",
            "Prediction Time",
        ]
    ].to_string(
        index=False
    )
)


# ============================================================
# BEST MODEL
# ============================================================

best_index = results_df[
    "F1"
].idxmax()

best_model = results_df.loc[
    best_index,
    "Model"
]

best_f1 = results_df.loc[
    best_index,
    "F1"
]

print("\n")
print("=" * 70)
print("BEST MODEL")
print("=" * 70)

print(
    "Model:",
    best_model
)

print(
    f"F1 Score: {best_f1 * 100:.2f}%"
)


# ============================================================
# SAVE CSV
# ============================================================

results_df.to_csv(
    RESULT_PATH,
    index=False
)

print("\n")
print(
    "✅ Results saved to:"
)

print(
    RESULT_PATH
)


print("\n")
print("=" * 70)
print("BENCHMARK COMPLETED")
print("=" * 70)