import os
import random
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.model_selection import train_test_split


# ============================================================
# CONFIGURATION
# ============================================================

SOURCE_FILE = (
    "ml_model/dataset/raw/ember2018/"
    "train_ember_2018_v2_features.parquet"
)

OUTPUT_DIR = (
    "ml_model/dataset/processed/final_80_20"
)

TOTAL_SAMPLES = 200_000
SAMPLES_PER_CLASS = 100_000

TEST_SIZE = 0.20
RANDOM_STATE = 42

EXPECTED_FEATURES = 2381


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("THREATLENS - FINAL 200K BALANCED DATASET CREATION")
print("=" * 70)


# ============================================================
# CHECK SOURCE
# ============================================================

if not os.path.exists(SOURCE_FILE):
    raise FileNotFoundError(
        f"Dataset not found:\n{SOURCE_FILE}"
    )

print("\nSource dataset:")
print(SOURCE_FILE)


# ============================================================
# READ LABEL COLUMN ONLY
# ============================================================

print("\nReading labels...")

parquet_file = pq.ParquetFile(SOURCE_FILE)

total_rows = parquet_file.metadata.num_rows

print("Total source rows:", total_rows)


# ------------------------------------------------------------
# First pass: collect indices for labels 0 and 1
# ------------------------------------------------------------

benign_indices = []
malware_indices = []

current_index = 0

for batch in parquet_file.iter_batches(
    batch_size=25000,
    columns=["Label"]
):

    labels = batch.column("Label").to_numpy()

    for i, label in enumerate(labels):

        row_index = current_index + i

        if label == 0:
            benign_indices.append(row_index)

        elif label == 1:
            malware_indices.append(row_index)

    current_index += len(labels)


print("\nAvailable classes:")

print(
    "Benign (0):",
    len(benign_indices)
)

print(
    "Malware (1):",
    len(malware_indices)
)


# ============================================================
# CHECK SAMPLE AVAILABILITY
# ============================================================

if len(benign_indices) < SAMPLES_PER_CLASS:
    raise ValueError(
        "Not enough benign samples."
    )

if len(malware_indices) < SAMPLES_PER_CLASS:
    raise ValueError(
        "Not enough malware samples."
    )


# ============================================================
# RANDOMLY SELECT 100K FROM EACH CLASS
# ============================================================

print("\nSelecting balanced samples...")

random.seed(RANDOM_STATE)

selected_benign = random.sample(
    benign_indices,
    SAMPLES_PER_CLASS
)

selected_malware = random.sample(
    malware_indices,
    SAMPLES_PER_CLASS
)

selected_indices = (
    selected_benign +
    selected_malware
)

selected_indices = np.array(
    selected_indices,
    dtype=np.int64
)

print(
    "Selected benign:",
    len(selected_benign)
)

print(
    "Selected malware:",
    len(selected_malware)
)

print(
    "Total selected:",
    len(selected_indices)
)


# ============================================================
# SECOND PASS - LOAD ONLY SELECTED ROWS
# ============================================================

print("\nReading selected feature rows...")
print("This may take some time...")

selected_set = set(
    selected_indices.tolist()
)

selected_rows = []

current_index = 0

all_columns = parquet_file.schema.names

for batch in parquet_file.iter_batches(
    batch_size=10000,
    columns=all_columns
):

    batch_df = batch.to_pandas()

    batch_start = current_index
    batch_end = (
        current_index +
        len(batch_df)
    )

    # Find selected indices inside this batch
    local_indices = [
        idx - batch_start
        for idx in selected_indices
        if batch_start <= idx < batch_end
    ]

    if local_indices:

        selected_batch = batch_df.iloc[
            local_indices
        ]

        selected_rows.append(
            selected_batch
        )

    current_index = batch_end

    if current_index % 100000 == 0:
        print(
            f"Processed {current_index:,} / "
            f"{total_rows:,} rows..."
        )


# ============================================================
# COMBINE
# ============================================================

print("\nCombining selected samples...")

df = pd.concat(
    selected_rows,
    ignore_index=True
)

print(
    "Selected dataset shape:",
    df.shape
)


# ============================================================
# REMOVE UNKNOWN LABELS IF ANY
# ============================================================

df = df[
    df["Label"].isin([0, 1])
].copy()


# ============================================================
# VERIFY FEATURES
# ============================================================

feature_columns = [
    col
    for col in df.columns
    if col != "Label"
]

print(
    "\nFeature count:",
    len(feature_columns)
)

if len(feature_columns) != EXPECTED_FEATURES:

    raise ValueError(
        f"Expected {EXPECTED_FEATURES} features "
        f"but found {len(feature_columns)}"
    )


# ============================================================
# VERIFY BALANCE
# ============================================================

print("\nFinal class distribution:")

print(
    df["Label"].value_counts()
)


# ============================================================
# SHUFFLE
# ============================================================

print("\nShuffling dataset...")

df = df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(
    drop=True
)


# ============================================================
# SEPARATE X AND Y
# ============================================================

X = df[
    feature_columns
].copy()

y = df[
    "Label"
].astype(
    np.int8
)


# ============================================================
# CONVERT FEATURES TO FLOAT32
# ============================================================

print(
    "\nConverting features to float32..."
)

X = X.astype(
    np.float32
)


# ============================================================
# 80:20 STRATIFIED SPLIT
# ============================================================

print("\nCreating 80:20 split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y
)


# ============================================================
# PRINT SHAPES
# ============================================================

print("\n" + "=" * 70)
print("FINAL SPLIT")
print("=" * 70)

print(
    "X_train:",
    X_train.shape
)

print(
    "X_test :",
    X_test.shape
)

print(
    "y_train:",
    y_train.shape
)

print(
    "y_test :",
    y_test.shape
)


# ============================================================
# VERIFY CLASS DISTRIBUTION
# ============================================================

print("\nTraining labels:")

print(
    y_train.value_counts()
)

print("\nTesting labels:")

print(
    y_test.value_counts()
)


# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# SAVE FILES
# ============================================================

print("\nSaving parquet files...")

X_train.to_parquet(
    os.path.join(
        OUTPUT_DIR,
        "X_train.parquet"
    ),
    index=False
)

X_test.to_parquet(
    os.path.join(
        OUTPUT_DIR,
        "X_test.parquet"
    ),
    index=False
)

y_train.to_frame(
    name="Label"
).to_parquet(
    os.path.join(
        OUTPUT_DIR,
        "y_train.parquet"
    ),
    index=False
)

y_test.to_frame(
    name="Label"
).to_parquet(
    os.path.join(
        OUTPUT_DIR,
        "y_test.parquet"
    ),
    index=False
)


# ============================================================
# FINAL VERIFICATION
# ============================================================

print("\n" + "=" * 70)
print("SPLIT CREATION COMPLETED")
print("=" * 70)

print("\nFiles created:")

print(
    os.path.join(
        OUTPUT_DIR,
        "X_train.parquet"
    )
)

print(
    os.path.join(
        OUTPUT_DIR,
        "X_test.parquet"
    )
)

print(
    os.path.join(
        OUTPUT_DIR,
        "y_train.parquet"
    )
)

print(
    os.path.join(
        OUTPUT_DIR,
        "y_test.parquet"
    )
)

print("\nExpected final structure:")

print(
    "200,000 balanced samples"
)

print(
    "160,000 training samples"
)

print(
    "40,000 testing samples"
)

print(
    "2,381 features"
)

print(
    "80:20 stratified split"
)

print(
    "Random State: 42"
)

print("\nDONE!")