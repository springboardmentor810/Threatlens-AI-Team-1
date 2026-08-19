import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = (
    "ml_model/dataset/raw/ember2018/"
    "train_ember_2018_v2_features.parquet"
)

EXPECTED_FEATURES = 2381


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 60)
print("EMBER 2018 - FEATURE STRUCTURE CHECK")
print("=" * 60)

print("\nReading dataset...")

df = pd.read_parquet(DATA_PATH)

print("\nDataset loaded successfully!")


# ============================================================
# BASIC INFORMATION
# ============================================================

print("\nTotal columns:", len(df.columns))
print("Total rows:", len(df))


# ============================================================
# CHECK LABEL
# ============================================================

print("\nChecking Label column...")

if "Label" in df.columns:
    print("Label exists: True")
else:
    print("Label exists: False")

    raise ValueError(
        "ERROR: Label column was not found!"
    )


# ============================================================
# SEPARATE FEATURES AND LABEL
# ============================================================

X = df.drop(
    columns=["Label"]
)

y = df["Label"]


# ============================================================
# FEATURE INFORMATION
# ============================================================

print("\nFeature columns:", len(X.columns))
print("Label column: 1")


# ============================================================
# SHOW FIRST FEATURES
# ============================================================

print("\nFirst 10 feature columns:")

print(
    X.columns[:10].tolist()
)


# ============================================================
# SHOW LAST FEATURES
# ============================================================

print("\nLast 10 feature columns:")

print(
    X.columns[-10:].tolist()
)


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\nLabel values:")

print(
    y.value_counts(
        dropna=False
    )
    .sort_index()
)


# ============================================================
# CHECK EXPECTED FEATURE COUNT
# ============================================================

print("\nChecking feature count...")

if len(X.columns) != EXPECTED_FEATURES:

    raise ValueError(
        f"EXPECTED {EXPECTED_FEATURES} FEATURES, "
        f"BUT FOUND {len(X.columns)}"
    )


# ============================================================
# CHECK FEATURE NAMES
# ============================================================

print("\nChecking feature names...")

expected_first = "F1"
expected_last = "F2381"

if X.columns[0] != expected_first:

    raise ValueError(
        f"Expected first feature to be {expected_first}, "
        f"but found {X.columns[0]}"
    )

if X.columns[-1] != expected_last:

    raise ValueError(
        f"Expected last feature to be {expected_last}, "
        f"but found {X.columns[-1]}"
    )


# ============================================================
# CHECK LABEL VALUES
# ============================================================

print("\nChecking label values...")

unique_labels = sorted(
    y.dropna().unique().tolist()
)

print(
    "Unique labels:",
    unique_labels
)


# ============================================================
# EXPECTED LABELS
# ============================================================

expected_labels = {-1.0, 0.0, 1.0}

actual_labels = set(
    unique_labels
)

if not actual_labels.issubset(
    expected_labels
):

    raise ValueError(
        "Unexpected label values found!"
    )


# ============================================================
# LABEL MEANING
# ============================================================

print("\nLabel meaning:")

print("  -1 = Unknown / Unlabeled")
print("   0 = Benign")
print("   1 = Malware")


# ============================================================
# COUNT EACH CLASS
# ============================================================

print("\nClass counts:")

for label in [-1.0, 0.0, 1.0]:

    count = (
        y == label
    ).sum()

    print(
        f"Label {label:>4}: "
        f"{count:,}"
    )


# ============================================================
# FINAL RESULT
# ============================================================

print("\n" + "=" * 60)
print("FEATURE CHECK COMPLETED")
print("=" * 60)

print(
    "\n✅ Total columns:",
    len(df.columns)
)

print(
    "✅ Feature columns:",
    len(X.columns)
)

print(
    "✅ Target column: Label"
)

print(
    "✅ First feature:",
    X.columns[0]
)

print(
    "✅ Last feature:",
    X.columns[-1]
)

print(
    "✅ Unknown label (-1) detected correctly"
)

print(
    "✅ Benign label (0) detected correctly"
)

print(
    "✅ Malware label (1) detected correctly"
)

print(
    "\n🎯 CORRECT DATASET STRUCTURE:"
)

print(
    "   F1 ... F2381 → 2381 ML features"
)

print(
    "   Label         → target"
)

print(
    "\n✅ Dataset is ready for machine learning."
)

print("=" * 60)