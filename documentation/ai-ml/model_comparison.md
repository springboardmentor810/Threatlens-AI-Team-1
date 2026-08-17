# Model Comparison

The following five machine learning models were selected for malware classification.

| Model | Type | Role |
|---|---|---|
| **Random Forest** | Ensemble | Robust baseline |
| **Extra Trees** | Ensemble | Tree-based comparison |
| **XGBoost** | Boosting | High-performance model |
| **LightGBM** | Boosting | Efficient large-scale model |
| **HistGradientBoosting** | Boosting | Efficient boosting alternative |

## Why These Models Were Selected

### 1. Random Forest

Random Forest is selected as a strong tree-based baseline. It can capture nonlinear relationships between malware features and is generally robust for structured/tabular datasets.

### 2. Extra Trees

Extra Trees is selected to compare with Random Forest using a more randomized tree-building approach. It can provide strong performance while offering a different ensemble strategy.

### 3. XGBoost

XGBoost is selected because gradient boosting is effective for complex tabular classification problems. It can capture nonlinear relationships and interactions between features and is therefore a strong candidate for malware classification.

### 4. LightGBM

LightGBM is selected because the EMBER dataset contains a large number of samples and features. It is designed for efficient gradient boosting and allows us to evaluate the trade-off between model performance and training efficiency.

### 5. HistGradientBoosting

HistGradientBoosting is included as an efficient gradient-boosting alternative available within scikit-learn. It uses histogram-based training and provides another approach for comparing boosting performance.



The final model will be selected based on both **classification performance and computational efficiency**. Since ThreatLens is a malware detection system, particular importance will be given to **Recall and F1-Score**, while training and prediction time will also be considered.