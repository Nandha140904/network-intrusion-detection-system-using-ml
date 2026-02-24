"""
Configuration file for Network Traffic Classification and Intrusion Detection System
"""

import os

# Project Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

# Dataset Configuration
DATASET_NAME = 'NSL-KDD'  # Options: 'NSL-KDD', 'CICIDS2017', 'UNSW-NB15'
TRAIN_FILE = os.path.join(DATA_DIR, 'KDDTrain+.txt')
TEST_FILE = os.path.join(DATA_DIR, 'KDDTest+.txt')

# Feature Engineering
SELECTED_FEATURES = None  # None = use all features, or list of feature names
FEATURE_SCALING = True
HANDLE_IMBALANCE = True  # Use SMOTE for imbalanced classes

# Model Parameters
RANDOM_FOREST_PARAMS = {
    'n_estimators': 100,
    'max_depth': 20,
    'min_samples_split': 5,
    'min_samples_leaf': 2,
    'random_state': 42,
    'n_jobs': -1
}

XGBOOST_PARAMS = {
    'n_estimators': 100,
    'max_depth': 10,
    'learning_rate': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'random_state': 42,
    'n_jobs': -1
}

# Training Configuration
TEST_SIZE = 0.2
CROSS_VALIDATION_FOLDS = 5
RANDOM_STATE = 42

# Real-time Packet Capture
# NETWORK_INTERFACE = None  # None = auto-detect default interface
NETWORK_INTERFACE = r'\Device\NPF_{7088574F-FC9C-4AD6-AEF3-DAFE3FE3C4C1}'
PACKET_BUFFER_SIZE = 20   # Process a flow every 20 packets (faster detection)
FLOW_TIMEOUT = 10          # seconds — flush idle flows quickly
CAPTURE_FILTER = None# Capture traffic to/from Google

# Alert System
ALERT_THRESHOLD = 0.7  # Confidence threshold for raising alerts
ALERT_LOG_FILE = os.path.join(LOGS_DIR, 'alerts.log')
MAX_ALERTS_DISPLAY = 50

# Known Hosts Tracking
KNOWN_HOSTS_FILE = os.path.join(LOGS_DIR, 'known_hosts.json')

# Dashboard Configuration (Remote Access Enabled)
FLASK_HOST = '0.0.0.0'  # Allows remote access from any IP
FLASK_PORT = 14094
FLASK_DEBUG = True
UPDATE_INTERVAL = 2  # seconds for real-time updates

# Attack Categories (NSL-KDD)
ATTACK_CATEGORIES = {
    'normal': 'Normal',
    'DoS': 'Denial of Service',
    'Probe': 'Probing/Scanning',
    'R2L': 'Remote to Local',
    'U2R': 'User to Root'
}

# Logging Configuration
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = os.path.join(LOGS_DIR, 'system.log')

# Model Persistence
BEST_MODEL_PATH = os.path.join(MODELS_DIR, 'best_model.pkl')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')
ENCODER_PATH = os.path.join(MODELS_DIR, 'encoder.pkl')

# Create directories if they don't exist
for directory in [DATA_DIR, MODELS_DIR, LOGS_DIR, RESULTS_DIR]:
    os.makedirs(directory, exist_ok=True)
