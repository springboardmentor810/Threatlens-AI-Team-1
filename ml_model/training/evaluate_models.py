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
# CONFIGURATION
# ============================================================

TEST_PATH = (
    "ml_model/dataset/raw/ember2018/"
    "test_ember_2018_v2_features.parquet"
)

EXTRA_TREES_PATH = (
    "ml_model/saved_model/"
    "extra_trees_ember.pkl"
)

XGBOOST_PATH = (
    "ml_model/saved_model/"
    "xgboost_ember.json"
)

# Test only a manageable number of samples
# because your PC has 16 GB RAM.
TEST_SAMPLE_SIZE = 100_000

RANDOM_STATE = 42


# ============================================================
# LOAD TEST DATA
# ============================================================

print("=" * 65)
print("EMBER 2018 - FINAL MODEL EVALUATION")
print("=" * 65)

print("\nReading test dataset metadata...")

parquet_file = pq.ParquetFile(TEST_PATH)

total_rows = parquet_file.metadata.num_rows
total_columns = len(parquet_file.schema.names)

print("Total test rows:", total_rows)
print("Total columns:", total_columns)


# ============================================================
# LOAD TEST SAMPLE
# ============================================================

print(
    f"\nLoading {TEST_SAMPLE_SIZE:,} test samples..."
)

batches = []
rows_read = 0

for batch in parquet_file.iter_batches(
    batch_size=25_000
):

    df_batch = batch.to_pandas()

    remaining = TEST_SAMPLE_SIZE - rows_read

    if remaining <= 0:
        break

    if len(df_batch) > remaining:
        df_batch = df_batch.iloc[:remaining]

    batches.append(df_batch)

    rows_read += len(df_batch)

    print(
        f"Loaded {rows_read:,} / "
        f"{TEST_SAMPLE_SIZE:,}"
    )

    if rows_read >= TEST_SAMPLE_SIZE:
        break


test_df = pd.concat(
    batches,
    ignore_index=True
)

del batches

gc.collect()

print(
    "\nLoaded test shape:",
    test_df.shape
)


# ============================================================
# CHECK LABEL
# ============================================================

if "Label" not in test_df.columns:

    raise ValueError(
        "ERROR: Label column not found!"
    )


print("\nOriginal test label distribution:")

print(
    test_df["Label"].value_counts(
        dropna=False
    )
)


# ============================================================
# REMOVE UNKNOWN LABELS
# ============================================================

print("\nRemoving unknown labels (-1)...")

test_df = test_df[
    test_df["Label"] != -1
].copy()

print(
    "Test samples after removing unknown labels:",
    len(test_df)
)


# ============================================================
# SEPARATE FEATURES AND LABEL
# ============================================================

X_test = test_df.drop(
    columns=["Label"]
)

y_test = test_df["Label"]


# ============================================================
# VERIFY FEATURES
# ============================================================

print(
    "\nNumber of test features:",
    X_test.shape[1]
)

if X_test.shape[1] != 2381:

    raise ValueError(
        f"Expected 2381 features, "
        f"but found {X_test.shape[1]}"
    )

print("✅ Correct number of features: 2381")


# ============================================================
# CLEAN FEATURES
# ============================================================

print("\nCleaning test features...")

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


print("Test data ready.")


# ============================================================
# FUNCTION FOR MODEL EVALUATION
# ============================================================

def evaluate_model(
    model_name,
    model,
    X,
    y
):

    print("\n")
    print("=" * 65)
    print(model_name)
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
        average="binary",
        zero_division=0
    )

    recall = recall_score(
        y,
        predictions,
        average="binary",
        zero_division=0
    )

    f1 = f1_score(
        y,
        predictions,
        average="binary",
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

    cm = confusion_matrix(
        y,
        predictions
    )

    print(cm)

    return {
        "Model": model_name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1
    }


# ============================================================
# LOAD EXTRA TREES
# ============================================================

print("\n")
print("=" * 65)
print("LOADING EXTRA TREES")
print("=" * 65)

if not os.path.exists(
    EXTRA_TREES_PATH
):

    raise FileNotFoundError(
        "Extra Trees model not found!"
    )

extra_trees = joblib.load(
    EXTRA_TREES_PATH
)

print(
    "✅ Extra Trees loaded successfully"
)

print(
    "Features expected:",
    extra_trees.n_features_in_
)


# ============================================================
# EVALUATE EXTRA TREES
# ============================================================

extra_trees_result = evaluate_model(
    "EXTRA TREES",
    extra_trees,
    X_test,
    y_test
)


# ============================================================
# DELETE EXTRA TREES
# ============================================================

del extra_trees

gc.collect()


# ============================================================
# LOAD XGBOOST
# ============================================================

print("\n")
print("=" * 65)
print("LOADING XGBOOST")
print("=" * 65)

if not os.path.exists(
    XGBOOST_PATH
):

    raise FileNotFoundError(
        "XGBoost model not found!"
    )

xgb_model = XGBClassifier()

xgb_model.load_model(
    XGBOOST_PATH
)

print(
    "✅ XGBoost loaded successfully"
)

print(
    "Features expected:",
    xgb_model.n_features_in_
)


# ============================================================
# EVALUATE XGBOOST
# ============================================================

xgb_result = evaluate_model(
    "XGBOOST",
    xgb_model,
    X_test,
    y_test
)


# ============================================================
# COMPARISON
# ============================================================

print("\n")
print("=" * 65)
print("MODEL COMPARISON")
print("=" * 65)

results = pd.DataFrame(
    [
        extra_trees_result,
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
# FIND BEST MODEL
# ============================================================

best_model = results.loc[
    results["F1 Score"].idxmax()
]

print("\n")
print("=" * 65)
print("BEST MODEL")
print("=" * 65)

print(
    "Model:",
    best_model["Model"]
)

print(
    f"Accuracy: "
    f"{best_model['Accuracy']:.4f}"
)

print(
    f"Precision: "
    f"{best_model['Precision']:.4f}"
)

print(
    f"Recall: "
    f"{best_model['Recall']:.4f}"
)

print(
    f"F1 Score: "
    f"{best_model['F1 Score']:.4f}"
)


print("\n")
print("=" * 65)
print("FINAL EVALUATION COMPLETED")
print("=" * 65)