import os
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from sklearn.model_selection import train_test_split
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

MODEL_PATH = "ml_model/saved_model/xgboost_ember.json"

SAMPLE_SIZE = 100_000

RANDOM_STATE = 42


# ============================================================
# CREATE MODEL DIRECTORY
# ============================================================

os.makedirs("ml_model/saved_model", exist_ok=True)


# ============================================================
# LOAD PARQUET
# ============================================================

print("=" * 60)
print("EMBER 2018 - XGBOOST TRAINING")
print("=" * 60)

print("\nReading dataset...")

parquet_file = pq.ParquetFile(DATA_PATH)

total_rows = parquet_file.metadata.num_rows

print("Total dataset rows:", total_rows)
print("Total columns:", len(parquet_file.schema.names))


# ============================================================
# LOAD 100,000 SAMPLES
# ============================================================

print("\nReading a manageable subset...")

batches = []
rows_read = 0

for batch in parquet_file.iter_batches(batch_size=25_000):

    df_batch = batch.to_pandas()

    remaining = SAMPLE_SIZE - rows_read

    if remaining <= 0:
        break

    if len(df_batch) > remaining:
        df_batch = df_batch.iloc[:remaining]

    batches.append(df_batch)

    rows_read += len(df_batch)

    print(
        f"Loaded {rows_read:,} / "
        f"{SAMPLE_SIZE:,} samples"
    )

    if rows_read >= SAMPLE_SIZE:
        break


df = pd.concat(
    batches,
    ignore_index=True
)

del batches

print("\nLoaded dataset shape:", df.shape)


# ============================================================
# CHECK LABEL
# ============================================================

if "Label" not in df.columns:
    raise ValueError(
        "Label column was not found."
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

df = df[df["Label"] != -1]

print(
    "Shape after removing unknown labels:",
    df.shape
)


# ============================================================
# FEATURES AND LABEL
# ============================================================

X = df.drop(columns=["Label"])

y = df["Label"]


# ============================================================
# CONVERT FEATURES
# ============================================================

print("\nConverting features to float32...")

X = X.astype(np.float32)

y = y.astype(np.int8)


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
    len(X_train)
)

print(
    "Validation samples:",
    len(X_val)
)


# ============================================================
# XGBOOST MODEL
# ============================================================

print("\nCreating XGBoost model...")

model = XGBClassifier(
    n_estimators=200,
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


# ============================================================
# TRAIN
# ============================================================

print("\nTraining XGBoost...")
print("This may take some time.")

model.fit(
    X_train,
    y_train
)

print("\nTraining completed!")


# ============================================================
# PREDICTION
# ============================================================

print("\nRunning validation...")

y_pred = model.predict(X_val)


# ============================================================
# EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_val,
    y_pred
)

precision = precision_score(
    y_val,
    y_pred,
    average="binary",
    zero_division=0
)

recall = recall_score(
    y_val,
    y_pred,
    average="binary",
    zero_division=0
)

f1 = f1_score(
    y_val,
    y_pred,
    average="binary",
    zero_division=0
)


print("\n" + "=" * 60)
print("XGBOOST RESULTS")
print("=" * 60)

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")


print("\nClassification Report:")

print(
    classification_report(
        y_val,
        y_pred,
        zero_division=0
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_val,
        y_pred
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

print("\nSaving model...")

model.save_model(MODEL_PATH)

print("\nModel saved successfully!")

print(
    "Location:",
    MODEL_PATH
)

print("\nDONE!")