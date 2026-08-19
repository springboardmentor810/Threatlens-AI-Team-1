import os
import gc

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = (
    "ml_model/dataset/raw/ember2018/"
    "train_ember_2018_v2_features.parquet"
)

EXTRA_TREES_PATH = (
    "ml_model/saved_model/"
    "extra_trees_ember_v2.pkl"
)

XGBOOST_PATH = (
    "ml_model/saved_model/"
    "xgboost_ember_v2.json"
)

# Number of samples from EACH class
SAMPLES_PER_CLASS = 60_000

RANDOM_STATE = 42

BATCH_SIZE = 25_000


# ============================================================
# CREATE SAVE DIRECTORY
# ============================================================

os.makedirs(
    "ml_model/saved_model",
    exist_ok=True
)


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("EMBER 2018 - VERSION 2 TRAINING")
print("=" * 70)

print("\nTraining strategy:")
print("60,000 Benign + 60,000 Malware")
print("Total selected samples: 120,000")
print("Features: 2,381")


# ============================================================
# OPEN PARQUET
# ============================================================

print("\nOpening EMBER training dataset...")

parquet_file = pq.ParquetFile(
    DATA_PATH
)

total_rows = parquet_file.metadata.num_rows
total_columns = len(
    parquet_file.schema.names
)

print("Total rows:", f"{total_rows:,}")
print("Total columns:", total_columns)


# ============================================================
# VERIFY DATASET STRUCTURE
# ============================================================

if "Label" not in parquet_file.schema.names:

    raise ValueError(
        "Label column not found!"
    )

feature_columns = [
    column
    for column in parquet_file.schema.names
    if column != "Label"
]

print(
    "Feature columns:",
    len(feature_columns)
)

if len(feature_columns) != 2381:

    raise ValueError(
        f"Expected 2381 features, "
        f"found {len(feature_columns)}"
    )

print("✅ Dataset structure verified")


# ============================================================
# READ ONLY LABEL COLUMN
# ============================================================

print("\nReading labels...")

label_df = pd.read_parquet(
    DATA_PATH,
    columns=["Label"]
)

labels = label_df["Label"].to_numpy()

print(
    "Labels loaded:",
    len(labels)
)


# ============================================================
# FIND VALID INDICES
# ============================================================

print("\nFinding labeled samples...")

benign_indices = np.where(
    labels == 0
)[0]

malware_indices = np.where(
    labels == 1
)[0]

unknown_indices = np.where(
    labels == -1
)[0]

print(
    "Benign samples:",
    f"{len(benign_indices):,}"
)

print(
    "Malware samples:",
    f"{len(malware_indices):,}"
)

print(
    "Unknown samples:",
    f"{len(unknown_indices):,}"
)


# ============================================================
# CHECK SAMPLE AVAILABILITY
# ============================================================

if len(benign_indices) < SAMPLES_PER_CLASS:

    raise ValueError(
        "Not enough benign samples!"
    )

if len(malware_indices) < SAMPLES_PER_CLASS:

    raise ValueError(
        "Not enough malware samples!"
    )


# ============================================================
# RANDOM SAMPLING
# ============================================================

print("\nRandomly sampling the entire dataset...")

rng = np.random.default_rng(
    RANDOM_STATE
)

selected_benign = rng.choice(
    benign_indices,
    size=SAMPLES_PER_CLASS,
    replace=False
)

selected_malware = rng.choice(
    malware_indices,
    size=SAMPLES_PER_CLASS,
    replace=False
)


# Combine indices

selected_indices = np.concatenate(
    [
        selected_benign,
        selected_malware
    ]
)

# Sort indices so Parquet is read sequentially

selected_indices.sort()

print(
    "Selected samples:",
    f"{len(selected_indices):,}"
)

print(
    "Selected benign:",
    f"{SAMPLES_PER_CLASS:,}"
)

print(
    "Selected malware:",
    f"{SAMPLES_PER_CLASS:,}"
)


# ============================================================
# FREE LABEL DATA
# ============================================================

del label_df
del labels
del benign_indices
del malware_indices
del unknown_indices

gc.collect()


# ============================================================
# READ SELECTED FEATURES
# ============================================================

print("\nReading selected feature rows...")

selected_batches = []

selected_pointer = 0

row_start = 0


for batch_number, batch in enumerate(
    parquet_file.iter_batches(
        batch_size=BATCH_SIZE
    ),
    start=1
):

    row_end = row_start + batch.num_rows

    # Find selected indices belonging to this batch

    while (
        selected_pointer
        < len(selected_indices)
        and selected_indices[selected_pointer]
        < row_start
    ):
        selected_pointer += 1

    batch_pointer = selected_pointer

    while (
        batch_pointer
        < len(selected_indices)
        and selected_indices[batch_pointer]
        < row_end
    ):
        batch_pointer += 1

    # If this batch contains selected rows

    if batch_pointer > selected_pointer:

        relative_indices = (
            selected_indices[
                selected_pointer:batch_pointer
            ]
            - row_start
        )

        batch_df = batch.to_pandas()

        selected_df = batch_df.iloc[
            relative_indices
        ].copy()

        selected_batches.append(
            selected_df
        )

        print(
            f"Batch {batch_number}: "
            f"selected "
            f"{len(selected_df):,} rows"
        )

        del batch_df
        del selected_df

    row_start = row_end

    selected_pointer = batch_pointer

    if selected_pointer >= len(
        selected_indices
    ):
        break


# ============================================================
# COMBINE SELECTED DATA
# ============================================================

print("\nCombining selected samples...")

df = pd.concat(
    selected_batches,
    ignore_index=True
)

del selected_batches
del selected_indices

gc.collect()


print(
    "Selected dataset shape:",
    df.shape
)


# ============================================================
# VERIFY SHAPE
# ============================================================

if df.shape[0] != (
    SAMPLES_PER_CLASS * 2
):

    raise ValueError(
        "Incorrect number of selected samples!"
    )

if df.shape[1] != 2382:

    raise ValueError(
        "Incorrect number of columns!"
    )


# ============================================================
# SHUFFLE DATASET
# ============================================================

print("\nShuffling selected dataset...")

df = df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(
    drop=True
)


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\nSelected label distribution:")

print(
    df["Label"].value_counts()
)


# ============================================================
# SEPARATE X AND Y
# ============================================================

print("\nSeparating features and target...")

X = df.drop(
    columns=["Label"]
)

y = df["Label"]


# ============================================================
# VERIFY FEATURES
# ============================================================

print(
    "\nNumber of features:",
    X.shape[1]
)

if X.shape[1] != 2381:

    raise ValueError(
        f"Expected 2381 features, "
        f"found {X.shape[1]}"
    )

print("✅ Exactly 2,381 features")


# ============================================================
# CONVERT DATA TYPE
# ============================================================

print("\nConverting features to float32...")

X = X.astype(
    np.float32
)

y = y.astype(
    np.int8
)


# ============================================================
# CLEAN DATA
# ============================================================

print("Cleaning NaN and infinite values...")

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0)


# ============================================================
# TRAIN / VALIDATION SPLIT
# ============================================================

print("\nCreating train/validation split...")

X_train, X_val, y_train, y_val = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y
)


print(
    "\nTraining samples:",
    f"{len(X_train):,}"
)

print(
    "Validation samples:",
    f"{len(X_val):,}"
)


# ============================================================
# EXTRA TREES
# ============================================================

print("\n")
print("=" * 70)
print("TRAINING EXTRA TREES V2")
print("=" * 70)

extra_trees = ExtraTreesClassifier(
    n_estimators=100,
    max_depth=25,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print("\nTraining Extra Trees...")

extra_trees.fit(
    X_train,
    y_train
)

print("✅ Extra Trees training completed")


# ============================================================
# EXTRA TREES VALIDATION
# ============================================================

print("\nRunning Extra Trees validation...")

et_predictions = extra_trees.predict(
    X_val
)


et_accuracy = accuracy_score(
    y_val,
    et_predictions
)

et_precision = precision_score(
    y_val,
    et_predictions,
    zero_division=0
)

et_recall = recall_score(
    y_val,
    et_predictions,
    zero_division=0
)

et_f1 = f1_score(
    y_val,
    et_predictions,
    zero_division=0
)


print("\nEXTRA TREES V2 RESULTS")

print(
    f"Accuracy  : {et_accuracy:.4f}"
)

print(
    f"Precision : {et_precision:.4f}"
)

print(
    f"Recall    : {et_recall:.4f}"
)

print(
    f"F1 Score  : {et_f1:.4f}"
)

print("\nClassification Report:")

print(
    classification_report(
        y_val,
        et_predictions,
        zero_division=0
    )
)

print("Confusion Matrix:")

print(
    confusion_matrix(
        y_val,
        et_predictions
    )
)


# ============================================================
# SAVE EXTRA TREES
# ============================================================

print("\nSaving Extra Trees V2...")

joblib.dump(
    extra_trees,
    EXTRA_TREES_PATH,
    compress=3
)

print(
    "✅ Saved:",
    EXTRA_TREES_PATH
)


# ============================================================
# FREE EXTRA TREES MEMORY
# ============================================================

del extra_trees
del et_predictions

gc.collect()


# ============================================================
# XGBOOST
# ============================================================

print("\n")
print("=" * 70)
print("TRAINING XGBOOST V2")
print("=" * 70)

xgb_model = XGBClassifier(
    n_estimators=250,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    tree_method="hist",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print("\nTraining XGBoost...")

xgb_model.fit(
    X_train,
    y_train
)

print("✅ XGBoost training completed")


# ============================================================
# XGBOOST VALIDATION
# ============================================================

print("\nRunning XGBoost validation...")

xgb_predictions = xgb_model.predict(
    X_val
)


xgb_accuracy = accuracy_score(
    y_val,
    xgb_predictions
)

xgb_precision = precision_score(
    y_val,
    xgb_predictions,
    zero_division=0
)

xgb_recall = recall_score(
    y_val,
    xgb_predictions,
    zero_division=0
)

xgb_f1 = f1_score(
    y_val,
    xgb_predictions,
    zero_division=0
)


print("\nXGBOOST V2 RESULTS")

print(
    f"Accuracy  : {xgb_accuracy:.4f}"
)

print(
    f"Precision : {xgb_precision:.4f}"
)

print(
    f"Recall    : {xgb_recall:.4f}"
)

print(
    f"F1 Score  : {xgb_f1:.4f}"
)

print("\nClassification Report:")

print(
    classification_report(
        y_val,
        xgb_predictions,
        zero_division=0
    )
)

print("Confusion Matrix:")

print(
    confusion_matrix(
        y_val,
        xgb_predictions
    )
)


# ============================================================
# SAVE XGBOOST
# ============================================================

print("\nSaving XGBoost V2...")

xgb_model.save_model(
    XGBOOST_PATH
)

print(
    "✅ Saved:",
    XGBOOST_PATH
)


# ============================================================
# FINAL COMPARISON
# ============================================================

print("\n")
print("=" * 70)
print("VERSION 2 MODEL COMPARISON")
print("=" * 70)

print(
    f"{'Model':<20}"
    f"{'Accuracy':<12}"
    f"{'Precision':<12}"
    f"{'Recall':<12}"
    f"{'F1':<12}"
)

print("-" * 70)

print(
    f"{'Extra Trees':<20}"
    f"{et_accuracy:<12.4f}"
    f"{et_precision:<12.4f}"
    f"{et_recall:<12.4f}"
    f"{et_f1:<12.4f}"
)

print(
    f"{'XGBoost':<20}"
    f"{xgb_accuracy:<12.4f}"
    f"{xgb_precision:<12.4f}"
    f"{xgb_recall:<12.4f}"
    f"{xgb_f1:<12.4f}"
)


# ============================================================
# BEST MODEL
# ============================================================

if xgb_f1 > et_f1:

    best_model = "XGBoost"

    best_f1 = xgb_f1

else:

    best_model = "Extra Trees"

    best_f1 = et_f1


print("\n")
print("=" * 70)
print("BEST VALIDATION MODEL")
print("=" * 70)

print(
    "Model:",
    best_model
)

print(
    f"F1 Score: {best_f1:.4f}"
)


# ============================================================
# FINAL
# ============================================================

print("\n")
print("=" * 70)
print("VERSION 2 TRAINING COMPLETED")
print("=" * 70)

print("\nModels saved:")

print(
    "Extra Trees:",
    EXTRA_TREES_PATH
)

print(
    "XGBoost:",
    XGBOOST_PATH
)

print("\n✅ DONE!")