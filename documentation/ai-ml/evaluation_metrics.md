## Evaluation Metrics

### 1. Accuracy

**Definition:**
Accuracy measures the overall percentage of correctly classified samples.

**Why it is used:**
Provides an overall performance score of the model.

---

### 2. Precision

**Definition:**
Precision measures how many files predicted as malware are actually malware.

**Why it is used:**
A high precision reduces false alarms (False Positives).

---

### 3. Recall

**Definition:**
Recall measures how many actual malware samples are correctly detected.

**Why it is used:**
Recall is one of the most important metrics in malware detection because missing malicious files (False Negatives) can lead to serious security risks.

---

### 4. F1-Score

**Definition:**
F1-Score is the harmonic mean of Precision and Recall.

**Why it is used:**
It provides a balanced evaluation when both Precision and Recall are important.

---

### 5. ROC-AUC Score

**Definition:**
ROC-AUC measures the model's ability to distinguish between malware and benign files.

**Why it is used:**
A higher ROC-AUC value indicates better classification performance across different thresholds.

---

### 6. Confusion Matrix

The confusion matrix provides a detailed breakdown of prediction results.

It consists of:

- True Positives (TP)
- True Negatives (TN)
- False Positives (FP)
- False Negatives (FN)

This helps identify the types of errors made by the model.

---

### 7. Training Time

Measures the time required to train each machine learning model.

This is important because the EMBER dataset contains a large number of samples and features.

---

### 8. Prediction Time

Measures how quickly the trained model can classify new executable files.

Fast prediction is important for real-time malware detection systems.

---

# Model Selection Criteria

The final machine learning model will be selected based on the following criteria:

- High Accuracy
- High Precision
- High Recall
- High F1-Score
- High ROC-AUC Score
- Reasonable Training Time
- Fast Prediction Time