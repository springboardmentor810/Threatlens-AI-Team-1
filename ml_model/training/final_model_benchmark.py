import os
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = "ml_model/dataset/processed/final_80_20"

X_TRAIN_PATH = os.path.join(DATA_DIR, "X_train.parquet")
X_TEST_PATH = os.path.join(DATA_DIR, "X_test.parquet")
Y_TRAIN_PATH = os.path.join(DATA_DIR, "y_train.parquet")
Y_TEST_PATH = os.path.join(DATA_DIR, "y_test.parquet")

MODEL_DIR = "ml_model/saved_model"

EXTRA_TREES_PATH = os.path.join(
    MODEL_DIR,
    "extra_trees_final_80_20.pkl"
)

XGBOOST_PATH = os.path.join(
    MODEL_DIR,
    "xgboost_final_80_20.json"
)

RESULT_PATH = (
    "ml_model/training/"
    "final_80_20_model_results.csv"
)

EXPECTED_FEATURES = 2381
RANDOM_STATE = 42


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("THREATLENS - FINAL 80:20 MODEL BENCHMARK")
print("=" * 70)


# ============================================================
# CHECK FILES
# ============================================================

print("\nChecking dataset files...")

required_files = [
    X_TRAIN_PATH,
    X_TEST_PATH,
    Y_TRAIN_PATH,
    Y_TEST_PATH,
]

for path in required_files:

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"File not found:\n{path}"
        )

    print("OK:", path)


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading training and testing data...")
print("This may take some time...")

X_train = pd.read_parquet(X_TRAIN_PATH)
X_test = pd.read_parquet(X_TEST_PATH)

y_train = pd.read_parquet(
    Y_TRAIN_PATH
).iloc[:, 0]

y_test = pd.read_parquet(
    Y_TEST_PATH
).iloc[:, 0]


# ============================================================
# DATA INFORMATION
# ============================================================

print("\n" + "=" * 70)
print("DATASET INFORMATION")
print("=" * 70)

print("X_train shape:", X_train.shape)
print("X_test shape :", X_test.shape)
print("y_train shape:", y_train.shape)
print("y_test shape :", y_test.shape)


# ============================================================
# VERIFY DATASET
# ============================================================

if X_train.shape != (160000, EXPECTED_FEATURES):
    raise ValueError(
        f"Unexpected X_train shape: {X_train.shape}"
    )

if X_test.shape != (40000, EXPECTED_FEATURES):
    raise ValueError(
        f"Unexpected X_test shape: {X_test.shape}"
    )

if len(y_train) != 160000:
    raise ValueError(
        f"Expected 160000 training labels, "
        f"found {len(y_train)}"
    )

if len(y_test) != 40000:
    raise ValueError(
        f"Expected 40000 testing labels, "
        f"found {len(y_test)}"
    )


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\nTraining label distribution:")
print(y_train.value_counts().sort_index())

print("\nTesting label distribution:")
print(y_test.value_counts().sort_index())


# ============================================================
# CONVERT TO NUMPY
# ============================================================

print("\nConverting features to NumPy float32...")

X_train = X_train.to_numpy(dtype=np.float32)
X_test = X_test.to_numpy(dtype=np.float32)

y_train = y_train.to_numpy(dtype=np.int8)
y_test = y_test.to_numpy(dtype=np.int8)


# ============================================================
# CLEAN INVALID VALUES
# ============================================================

print("Checking feature values...")

X_train = np.nan_to_num(
    X_train,
    nan=0.0,
    posinf=0.0,
    neginf=0.0
)

X_test = np.nan_to_num(
    X_test,
    nan=0.0,
    posinf=0.0,
    neginf=0.0
)

print("Feature cleaning completed.")


# ============================================================
# RESULTS STORAGE
# ============================================================

results = []


# ============================================================
# EXTRA TREES
# ============================================================

print("\n")
print("=" * 70)
print("TRAINING EXTRA TREES")
print("=" * 70)

extra_trees = ExtraTreesClassifier(
    n_estimators=100,
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print("\nCreating Extra Trees model...")
print("Number of trees: 100")
print("Training samples:", len(X_train))
print("Features:", X_train.shape[1])

print("\nTraining Extra Trees...")
print("Please wait...")

start_time = time.perf_counter()

extra_trees.fit(
    X_train,
    y_train
)

extra_trees_train_time = (
    time.perf_counter() - start_time
)

print("\nExtra Trees training completed!")
print(
    f"Training Time: "
    f"{extra_trees_train_time:.2f} seconds"
)


# ============================================================
# EXTRA TREES PREDICTION
# ============================================================

print("\nRunning Extra Trees predictions...")

start_time = time.perf_counter()

et_predictions = extra_trees.predict(X_test)

et_probabilities = extra_trees.predict_proba(
    X_test
)[:, 1]

et_prediction_time = (
    time.perf_counter() - start_time
)


# ============================================================
# EXTRA TREES METRICS
# ============================================================

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


# ============================================================
# EXTRA TREES OUTPUT
# ============================================================

print("\n")
print("=" * 70)
print("EXTRA TREES RESULTS")
print("=" * 70)

print(f"Accuracy     : {et_accuracy:.4f}")
print(f"Precision    : {et_precision:.4f}")
print(f"Recall       : {et_recall:.4f}")
print(f"F1 Score     : {et_f1:.4f}")
print(f"ROC-AUC      : {et_auc:.4f}")
print(f"Training Time: {extra_trees_train_time:.2f}s")
print(f"Prediction Time: {et_prediction_time:.2f}s")

print("\nConfusion Matrix:")
print(et_cm)


# ============================================================
# SAVE EXTRA TREES
# ============================================================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

print("\nSaving Extra Trees model...")

joblib.dump(
    extra_trees,
    EXTRA_TREES_PATH
)

print(
    "Saved:",
    EXTRA_TREES_PATH
)


results.append({
    "Model": "Extra Trees",
    "Accuracy": et_accuracy,
    "Precision": et_precision,
    "Recall": et_recall,
    "F1": et_f1,
    "ROC-AUC": et_auc,
    "Train Time": extra_trees_train_time,
    "Prediction Time": et_prediction_time
})


# ============================================================
# XGBOOST
# ============================================================

print("\n")
print("=" * 70)
print("TRAINING XGBOOST")
print("=" * 70)

xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    tree_method="hist",
    random_state=RANDOM_STATE,
    n_jobs=-1
)

print("\nCreating XGBoost model...")
print("Number of boosting rounds: 100")
print("Max depth: 6")
print("Learning rate: 0.1")
print("Training samples:", len(X_train))
print("Features:", X_train.shape[1])

print("\nTraining XGBoost...")
print("Please wait...")

start_time = time.perf_counter()

xgb_model.fit(
    X_train,
    y_train
)

xgb_train_time = (
    time.perf_counter() - start_time
)

print("\nXGBoost training completed!")
print(
    f"Training Time: "
    f"{xgb_train_time:.2f} seconds"
)


# ============================================================
# XGBOOST PREDICTION
# ============================================================

print("\nRunning XGBoost predictions...")

start_time = time.perf_counter()

xgb_predictions = xgb_model.predict(
    X_test
)

xgb_probabilities = xgb_model.predict_proba(
    X_test
)[:, 1]

xgb_prediction_time = (
    time.perf_counter() - start_time
)


# ============================================================
# XGBOOST METRICS
# ============================================================

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


# ============================================================
# XGBOOST OUTPUT
# ============================================================

print("\n")
print("=" * 70)
print("XGBOOST RESULTS")
print("=" * 70)

print(f"Accuracy     : {xgb_accuracy:.4f}")
print(f"Precision    : {xgb_precision:.4f}")
print(f"Recall       : {xgb_recall:.4f}")
print(f"F1 Score     : {xgb_f1:.4f}")
print(f"ROC-AUC      : {xgb_auc:.4f}")
print(f"Training Time: {xgb_train_time:.2f}s")
print(f"Prediction Time: {xgb_prediction_time:.2f}s")

print("\nConfusion Matrix:")
print(xgb_cm)


# ============================================================
# SAVE XGBOOST
# ============================================================

print("\nSaving XGBoost model...")

xgb_model.save_model(
    XGBOOST_PATH
)

print(
    "Saved:",
    XGBOOST_PATH
)


results.append({
    "Model": "XGBoost",
    "Accuracy": xgb_accuracy,
    "Precision": xgb_precision,
    "Recall": xgb_recall,
    "F1": xgb_f1,
    "ROC-AUC": xgb_auc,
    "Train Time": xgb_train_time,
    "Prediction Time": xgb_prediction_time
})


# ============================================================
# FINAL MODEL COMPARISON
# ============================================================

print("\n")
print("=" * 70)
print("FINAL MODEL COMPARISON")
print("=" * 70)

print(
    f"{'Model':<15}"
    f"{'Accuracy':>10}"
    f"{'Precision':>11}"
    f"{'Recall':>9}"
    f"{'F1':>8}"
    f"{'ROC-AUC':>10}"
    f"{'Train Time':>13}"
    f"{'Prediction Time':>18}"
)

print(
    f"{'Extra Trees':<15}"
    f"{et_accuracy * 100:>10.2f}"
    f"{et_precision * 100:>11.2f}"
    f"{et_recall * 100:>9.2f}"
    f"{et_f1 * 100:>8.2f}"
    f"{et_auc * 100:>10.2f}"
    f"{extra_trees_train_time:>13.2f}"
    f"{et_prediction_time:>18.2f}"
)

print(
    f"{'XGBoost':<15}"
    f"{xgb_accuracy * 100:>10.2f}"
    f"{xgb_precision * 100:>11.2f}"
    f"{xgb_recall * 100:>9.2f}"
    f"{xgb_f1 * 100:>8.2f}"
    f"{xgb_auc * 100:>10.2f}"
    f"{xgb_train_time:>13.2f}"
    f"{xgb_prediction_time:>18.2f}"
)


# ============================================================
# BEST MODEL
# ============================================================

if et_f1 >= xgb_f1:

    best_model = "Extra Trees"
    best_f1 = et_f1

else:

    best_model = "XGBoost"
    best_f1 = xgb_f1


print("\n")
print("=" * 70)
print("BEST MODEL")
print("=" * 70)

print(f"Model: {best_model}")
print(f"F1 Score: {best_f1 * 100:.2f}%")


# ============================================================
# SAVE RESULTS CSV
# ============================================================

results_df = pd.DataFrame(results)

results_df.to_csv(
    RESULT_PATH,
    index=False
)

print("\nResults saved to:")
print(RESULT_PATH)


# ============================================================
# FINAL MESSAGE
# ============================================================

print("\n")
print("=" * 70)
print("FINAL 80:20 BENCHMARK COMPLETED")
print("=" * 70)

print("\nDataset: 200,000 balanced samples")
print("Split: 160,000 training / 40,000 testing")
print("Features: 2,381")
print("Both models evaluated on the SAME test set.")

print("\nDONE!")