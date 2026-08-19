import os
import joblib
from xgboost import XGBClassifier

EXTRA_TREES_PATH = "ml_model/saved_model/extra_trees_ember.pkl"
XGBOOST_PATH = "ml_model/saved_model/xgboost_ember.json"

print("=" * 60)
print("CHECKING SAVED MODELS")
print("=" * 60)

# Extra Trees
print("\nChecking Extra Trees...")

if os.path.exists(EXTRA_TREES_PATH):
    extra_trees = joblib.load(EXTRA_TREES_PATH)

    print("✅ Extra Trees file exists")
    print("✅ Extra Trees loaded successfully")
    print("Number of trees:", len(extra_trees.estimators_))
    print("Number of features:", extra_trees.n_features_in_)

else:
    print("❌ Extra Trees model NOT FOUND")


# XGBoost
print("\nChecking XGBoost...")

if os.path.exists(XGBOOST_PATH):
    xgb_model = XGBClassifier()
    xgb_model.load_model(XGBOOST_PATH)

    print("✅ XGBoost file exists")
    print("✅ XGBoost loaded successfully")
    print("Number of features:", xgb_model.n_features_in_)

else:
    print("❌ XGBoost model NOT FOUND")


print("\n" + "=" * 60)
print("MODEL CHECK COMPLETED")
print("=" * 60)