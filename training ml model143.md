# 🤖 Training ML Model — NIDS
### `training ml model143`

A complete step-by-step guide to training the Network Intrusion Detection System (NIDS) machine learning models using **offline datasets** and a **local database/file store**.

---

## 📋 Table of Contents

1. [Overview](#1-overview)
2. [Supported Datasets](#2-supported-datasets)
3. [Project Folder Structure](#3-project-folder-structure)
4. [Step-by-Step: Download & Prepare the Dataset](#4-step-by-step-download--prepare-the-dataset)
5. [Step-by-Step: Train the Models](#5-step-by-step-train-the-models)
6. [Understanding the Training Pipeline](#6-understanding-the-training-pipeline)
7. [Model Configuration (Hyperparameters)](#7-model-configuration-hyperparameters)
8. [Using a Custom / Offline Dataset](#8-using-a-custom--offline-dataset)
9. [Evaluating Model Results](#9-evaluating-model-results)
10. [Where Models Are Saved](#10-where-models-are-saved)
11. [Loading the Trained Model in the Dashboard](#11-loading-the-trained-model-in-the-dashboard)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Overview

This NIDS uses an **ensemble of two ML models**:

| Model | Library | Purpose |
|---|---|---|
| **Random Forest** | `scikit-learn` | Primary classifier — high accuracy, robust |
| **XGBoost** | `xgboost` | Secondary classifier — handles complex patterns |

The **best-performing model** (by accuracy on the test set) is automatically saved as `best_model.pkl` and used by the real-time dashboard.

**Training data:** NSL-KDD dataset — the gold standard benchmark for intrusion detection.  
**Classes detected:** `normal`, `DoS`, `Probe`, `R2L`, `U2R`

---

## 2. Supported Datasets

| Dataset | Description | Format | Download |
|---|---|---|---|
| **NSL-KDD** ✅ (default) | Improved version of KDD Cup '99. 125,973 records, 41 features | `.txt` (CSV-like) | Auto-downloaded by script |
| **CICIDS2017** | Canadian Institute for Cybersecurity. Real traffic captures | `.csv` | [cicids.ca](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **UNSW-NB15** | Modern hybrid dataset with 49 features | `.csv` | [unsw.edu.au](https://research.unsw.edu.au/projects/unsw-nb15-dataset) |
| **Custom CSV** | Your own labeled network traffic data | `.csv` | Local file |

---

## 3. Project Folder Structure

```
major project/
├── data/                        ← 📂 Place your dataset files HERE
│   ├── KDDTrain+.txt            ← NSL-KDD training set
│   └── KDDTest+.txt             ← NSL-KDD test set
│
├── models/                      ← 📂 Trained models are saved here
│   ├── best_model.pkl           ← Best model (used by dashboard)
│   ├── random_forest.pkl        ← Random Forest model
│   ├── xgboost.pkl              ← XGBoost model
│   ├── scaler.pkl               ← Feature scaler
│   └── encoder.pkl              ← Label encoder
│
├── results/                     ← 📂 Evaluation reports saved here
│   ├── RandomForest_report.txt
│   ├── XGBoost_report.txt
│   └── confusion_matrix_*.png
│
├── logs/                        ← 📂 Log files
│   ├── system.log
│   └── alerts.log
│
├── train_models.py              ← 🚀 Main training script (run this!)
├── download_dataset.py          ← Auto-downloads NSL-KDD
├── data_handler.py              ← Data loading & preprocessing
├── config.py                    ← ⚙️ All configuration settings
├── evaluator.py                 ← Accuracy reports & confusion matrix
└── models/
    ├── random_forest_model.py   ← RF model class
    └── xgboost_model.py         ← XGBoost model class
```

---

## 4. Step-by-Step: Download & Prepare the Dataset

### Option A — Auto-Download NSL-KDD (Recommended)

The training script automatically downloads the dataset. Just run:

```bash
# Activate your virtual environment first
.\venv\Scripts\activate        # Windows
source venv/bin/activate       # Linux/Mac

# Run training (downloads + trains automatically)
python train_models.py
```

### Option B — Manual Download of NSL-KDD

1. Go to: https://www.unb.ca/cic/datasets/nsl.html
2. Download these two files:
   - `KDDTrain+.txt`
   - `KDDTest+.txt`
3. Place both files in the `data/` folder:
   ```
   major project/data/KDDTrain+.txt
   major project/data/KDDTest+.txt
   ```
4. Verify placement:
   ```bash
   dir data\
   # Should show: KDDTrain+.txt  KDDTest+.txt
   ```

### Option C — Use a Custom Offline CSV Dataset

If you have your own traffic capture (e.g., from Wireshark exported to CSV):

1. Your CSV must have the following **41 columns** matching NSL-KDD format:

   ```
   duration, protocol_type, service, flag, src_bytes, dst_bytes,
   land, wrong_fragment, urgent, hot, num_failed_logins, logged_in,
   num_compromised, root_shell, su_attempted, num_root, num_file_creations,
   num_shells, num_access_files, num_outbound_cmds, is_host_login,
   is_guest_login, count, srv_count, serror_rate, srv_serror_rate,
   rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate,
   srv_diff_host_rate, dst_host_count, dst_host_srv_count,
   dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate,
   dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate,
   dst_host_rerror_rate, dst_host_srv_rerror_rate, label, difficulty_level
   ```

2. Place in `data/` folder as `KDDTrain+.txt` and `KDDTest+.txt`  
3. Edit `config.py` to point to your files:
   ```python
   TRAIN_FILE = os.path.join(DATA_DIR, 'your_train_file.csv')
   TEST_FILE  = os.path.join(DATA_DIR, 'your_test_file.csv')
   ```

---

## 5. Step-by-Step: Train the Models

### Prerequisites

Make sure all packages are installed:

```bash
.\venv\Scripts\activate
pip install -r requirements.txt
```

Key packages needed:
```
scikit-learn >= 1.0
xgboost >= 1.6
pandas >= 1.3
numpy >= 1.21
imbalanced-learn >= 0.9   ← For SMOTE class balancing
joblib >= 1.0             ← For saving models
```

### Run Training

```bash
# Step 1: Activate virtual environment
.\venv\Scripts\activate

# Step 2: Run the training script
python train_models.py
```

### Expected Output

```
============================================================
NETWORK INTRUSION DETECTION SYSTEM - MODEL TRAINING
============================================================

Step 1: Downloading NSL-KDD Dataset...
  ✔ Dataset downloaded successfully

Step 2: Loading and Preprocessing Data...
  Training samples: 125,973
  Test samples:     22,544
  Features:         41
  Classes:          ['DoS', 'Probe', 'R2L', 'U2R', 'normal']

Step 3: Training Random Forest Model...
  Cross-validation score: 0.9823 ± 0.0015

Step 4: Training XGBoost Model...
  Cross-validation score: 0.9871 ± 0.0012

Step 5: Model Comparison...
  Random Forest Accuracy: 0.9823
  XGBoost Accuracy:       0.9871
  ✔ XGBoost is the best model!

============================================================
TRAINING COMPLETE!
============================================================
Models saved to: models/
Best model:      models/best_model.pkl
Results saved:   results/
```

---

## 6. Understanding the Training Pipeline

```
Raw Dataset (.txt)
      │
      ▼
[data_handler.py]
  ├─ Load CSV with column names
  ├─ Encode categorical features (protocol_type, service, flag)
  ├─ Normalize numerical features (StandardScaler)
  ├─ Map attack labels → 5 classes (normal, DoS, Probe, R2L, U2R)
  └─ Apply SMOTE to balance minority classes
      │
      ▼
[random_forest_model.py]          [xgboost_model.py]
  ├─ 5-fold Cross-validation        ├─ 5-fold Cross-validation
  ├─ Train on balanced data         ├─ Train on balanced data
  └─ Evaluate on test set           └─ Evaluate on test set
      │                                  │
      └─────────────┬────────────────────┘
                    ▼
            [evaluator.py]
              ├─ Accuracy, Precision, Recall, F1-Score
              ├─ Confusion Matrix (saved as PNG)
              └─ Classification Report (saved as .txt)
                    │
                    ▼
            [Best model saved]
              models/best_model.pkl  ← Used by dashboard
              models/scaler.pkl      ← Feature scaler
              models/encoder.pkl     ← Label encoder
```

---

## 7. Model Configuration (Hyperparameters)

All settings are in **`config.py`**. Edit this file to tune the models:

```python
# ── Random Forest ─────────────────────────────────
RANDOM_FOREST_PARAMS = {
    'n_estimators':    100,    # Number of trees (more = better but slower)
    'max_depth':       20,     # Tree depth (None = unlimited)
    'min_samples_split': 5,    # Min samples to split a node
    'min_samples_leaf':  2,    # Min samples at a leaf
    'random_state':    42,
    'n_jobs':          -1      # Use all CPU cores
}

# ── XGBoost ───────────────────────────────────────
XGBOOST_PARAMS = {
    'n_estimators':    100,    # Number of boosting rounds
    'max_depth':       10,     # Max tree depth
    'learning_rate':   0.1,    # Step size shrinkage
    'subsample':       0.8,    # Fraction of samples per tree
    'colsample_bytree': 0.8,   # Fraction of features per tree
    'random_state':    42,
    'n_jobs':          -1
}

# ── Training Split ────────────────────────────────
TEST_SIZE             = 0.2   # 80% train, 20% test
CROSS_VALIDATION_FOLDS = 5    # K-fold CV folds
HANDLE_IMBALANCE      = True  # Apply SMOTE (recommended: True)
ALERT_THRESHOLD       = 0.7   # Min confidence to raise alert (0.0–1.0)
```

### Recommended Tuning Tips

| Goal | Setting to Change |
|---|---|
| More accuracy | Increase `n_estimators` to 200–500 |
| Faster training | Decrease `n_estimators` to 50 |
| Detect more attacks (fewer false negatives) | Lower `ALERT_THRESHOLD` to 0.5 |
| Fewer false alarms | Raise `ALERT_THRESHOLD` to 0.8–0.9 |
| Deep patterns | Increase `max_depth` (XGBoost: 15–20) |

---

## 8. Using a Custom / Offline Dataset

### From a Database (SQLite / PostgreSQL)

If your traffic data is in a database, export it first:

**SQLite:**
```python
import sqlite3, pandas as pd

conn = sqlite3.connect('your_database.db')
df = pd.read_sql('SELECT * FROM network_traffic', conn)
df.to_csv('data/KDDTrain+.txt', index=False)
conn.close()
```

**PostgreSQL:**
```python
import pandas as pd
from sqlalchemy import create_engine

engine = create_engine('postgresql://user:password@localhost/dbname')
df = pd.read_sql('SELECT * FROM network_traffic WHERE label IS NOT NULL', engine)
df.to_csv('data/KDDTrain+.txt', index=False)
```

### From Wireshark PCAP

1. Open Wireshark → Export → as CSV
2. You will need to map Wireshark columns to NSL-KDD feature names
3. Use CICFlowMeter (free tool) to automatically extract NSL-KDD compatible features from PCAP:
   - Download: https://www.unb.ca/cic/research/applications.html
   - Run: `CICFlowMeter.bat <pcap_file> <output_folder>`
   - Place output CSV in `data/`

### From CICIDS2017 Dataset

```python
# In data_handler.py, the load_cicids2017() method can be used:
handler = DataHandler()
train_df, test_df = handler.load_cicids2017('data/Friday-WorkingHours.pcap_ISCX.csv')
```

---

## 9. Evaluating Model Results

After training, results are saved in the `results/` folder:

```bash
dir results\
# RandomForest_report.txt
# XGBoost_report.txt
# confusion_matrix_RandomForest.png
# confusion_matrix_XGBoost.png
```

### Sample Report (`results/XGBoost_report.txt`)

```
Classification Report — XGBoost
================================
              precision  recall  f1-score  support
    DoS           0.99    0.98      0.99     7458
    Probe         0.97    0.96      0.97     2421
    R2L           0.91    0.88      0.89      209
    U2R           0.85    0.72      0.78       67
    normal        0.99    0.99      0.99    9711

    accuracy                         0.982   22544
   macro avg      0.94    0.91      0.92    22544
weighted avg      0.98    0.98      0.98    22544
```

### Confusion Matrix

The confusion matrix PNG is saved in `results/` and shows exactly which attack types are being misclassified.

---

## 10. Where Models Are Saved

| File | Description |
|---|---|
| `models/best_model.pkl` | ⭐ The winner model — used by dashboard |
| `models/random_forest.pkl` | Saved Random Forest |
| `models/xgboost.pkl` | Saved XGBoost |
| `models/scaler.pkl` | StandardScaler fitted on training data |
| `models/encoder.pkl` | LabelEncoder for attack categories |

> ⚠️ **Important:** The `scaler.pkl` and `encoder.pkl` must always match the model being used. If you retrain, all three files are regenerated together automatically.

---

## 11. Loading the Trained Model in the Dashboard

Once training is complete, the dashboard automatically uses `models/best_model.pkl`.

```bash
# Start the dashboard (after training)
python app.py
```

Then go to: `http://localhost:14094`

The dashboard will show `Model Loaded: ✔` in the status panel. Start monitoring via the dashboard button — the trained model will classify all live traffic.

### Manually Switch Models

To use a specific model instead of the best:

```python
# In config.py
BEST_MODEL_PATH = os.path.join(MODELS_DIR, 'random_forest.pkl')  # Force RF
# or
BEST_MODEL_PATH = os.path.join(MODELS_DIR, 'xgboost.pkl')        # Force XGBoost
```

---

## 12. Troubleshooting

### ❌ `FileNotFoundError: KDDTrain+.txt not found`
```bash
# Run the dataset downloader manually
python download_dataset.py
# Or manually place files in data/ folder
```

### ❌ `ModuleNotFoundError: No module named 'xgboost'`
```bash
.\venv\Scripts\activate
pip install xgboost lightgbm imbalanced-learn
```

### ❌ `MemoryError during SMOTE`
```python
# In config.py — disable SMOTE for large datasets
HANDLE_IMBALANCE = False
```

### ❌ Training is very slow
```python
# In config.py — reduce estimators for faster training
RANDOM_FOREST_PARAMS = { 'n_estimators': 50, ... }
XGBOOST_PARAMS       = { 'n_estimators': 50, ... }
```

### ❌ Low accuracy on custom dataset
- Ensure your CSV columns exactly match NSL-KDD column names
- Check that `label` column values match: `normal`, `dos`, `probe`, `r2l`, `u2r` (lowercase)
- Ensure no null/NaN values: `df.dropna(inplace=True)`
- Try increasing `n_estimators` to 200+

### ❌ `best_model.pkl` not found when running dashboard
```bash
# Train models first
python train_models.py
# Then start dashboard
python app.py
```

---

## 🚀 Quick Start Summary

```bash
# 1. Activate env
.\venv\Scripts\activate

# 2. Install requirements
pip install -r requirements.txt

# 3. Train (downloads dataset + trains + saves model)
python train_models.py

# 4. Launch dashboard
python app.py

# 5. Open browser
# http://localhost:14094
```

---

*NIDS — Network Intrusion Detection System | ML Training Guide*  
*Models: Random Forest + XGBoost | Dataset: NSL-KDD (41 features, 5 classes)*
