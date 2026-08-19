import os
import gc
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import joblib

from xgboost import XGBClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PATHS
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


# ============================================================
# LOAD TEST DATA
# ============================================================

print("=" * 65)
print("EMBER 2018 - VERSION 2 FINAL TEST")
print("=" * 65)

print("\nReading test dataset...")

df = pd.read_parquet(
    TEST_PATH
)

print(
    "Test dataset shape:",
    df.shape
)


# ============================================================
# CHECK LABEL
# ============================================================

if "Label" not in df.columns:
    raise ValueError(
        "Label column not found!"
    )


print("\nLabel distribution:")

print(
    df["Label"].value_counts(
        dropna=False
    )
)


# ============================================================
# REMOVE UNKNOWN LABELS
# ============================================================

print("\nRemoving unknown labels...")

df = df[
    df["Label"] != -1
].copy()

print(
    "Test samples:",
    len(df)
)


# ============================================================
# SEPARATE FEATURES AND TARGET
# ============================================================

X_test = df.drop(
    columns=["Label"]
)

y_test = df["Label"]


# ============================================================
# VERIFY FEATURES
# ============================================================

print(
    "\nNumber of features:",
    X_test.shape[1]
)

if X_test.shape[1] != 2381:
    raise ValueError(
        f"Expected 2381 features, "
        f"found {X_test.shape[1]}"
    )

print("✅ 2,381 features confirmed")


# ============================================================
# CLEAN DATA
# ============================================================

print("\nPreparing test features...")

X_test = X_test.astype(
    np.float32
)

X_test = X_test.replace(
    [np.inf, -np.inf],
    np.nan
)

X_test = X_test.fillna(0)

y_test = y_test.astype(
    np.int8
)


# ============================================================
# EVALUATION FUNCTION
# ============================================================

def evaluate_model(
    name,
    model,
    X,
    y
):

    print("\n")
    print("=" * 65)
    print(name)
    print("=" * 65)

    print("\nRunning predictions...")

    predictions = model.predict(X)

    accuracy = accuracy_score(
        y,
        predictions
    )

    precision = precision_score(
        y,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y,
        predictions,
        zero_division=0
    )

    print("\nRESULTS")

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1 Score  : {f1:.4f}"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y,
            predictions,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y,
            predictions
        )
    )

    return {
        "Model": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1
    }


# ============================================================
# LOAD EXTRA TREES V2
# ============================================================

print("\n")
print("=" * 65)
print("LOADING EXTRA TREES V2")
print("=" * 65)

extra_trees = joblib.load(
    EXTRA_TREES_PATH
)

print(
    "✅ Extra Trees V2 loaded"
)

print(
    "Features:",
    extra_trees.n_features_in_
)


# ============================================================
# TEST EXTRA TREES
# ============================================================

et_result = evaluate_model(
    "EXTRA TREES V2",
    extra_trees,
    X_test,
    y_test
)


del extra_trees
gc.collect()


# ============================================================
# LOAD XGBOOST V2
# ============================================================

print("\n")
print("=" * 65)
print("LOADING XGBOOST V2")
print("=" * 65)

xgb_model = XGBClassifier()

xgb_model.load_model(
    XGBOOST_PATH
)

print(
    "✅ XGBoost V2 loaded"
)

print(
    "Features:",
    xgb_model.n_features_in_
)


# ============================================================
# TEST XGBOOST
# ============================================================

xgb_result = evaluate_model(
    "XGBOOST V2",
    xgb_model,
    X_test,
    y_test
)


# ============================================================
# FINAL COMPARISON
# ============================================================

print("\n")
print("=" * 65)
print("V2 FINAL TEST COMPARISON")
print("=" * 65)

results = pd.DataFrame(
    [
        et_result,
        xgb_result
    ]
)

print(
    results.to_string(
        index=False,
        float_format=lambda x: f"{x:.4f}"
    )
)


# ============================================================
# SELECT BEST MODEL
# ============================================================

best = results.loc[
    results["F1"].idxmax()
]

print("\n")
print("=" * 65)
print("FINAL MODEL")
print("=" * 65)

print(
    "🏆 Model:",
    best["Model"]
)

print(
    f"Accuracy : {best['Accuracy']:.4f}"
)

print(
    f"Precision: {best['Precision']:.4f}"
)

print(
    f"Recall   : {best['Recall']:.4f}"
)

print(
    f"F1 Score : {best['F1']:.4f}"
)


print("\n")
print("=" * 65)
print("V2 FINAL TEST COMPLETED")
print("=" * 65)