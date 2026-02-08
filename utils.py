"""
Utility functions for the Network Traffic Classification and Intrusion Detection System
"""

import os
import logging
import pickle
import json
from datetime import datetime
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from config import LOG_LEVEL, LOG_FORMAT, LOG_FILE, LOGS_DIR

def setup_logging(name=__name__, log_file=None):
    """
    Set up logging configuration
    
    Args:
        name: Logger name
        log_file: Optional log file path
    
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(LOG_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file is None:
        log_file = LOG_FILE
    
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

def save_model(model, filepath):
    """
    Save a trained model to disk
    
    Args:
        model: Trained model object
        filepath: Path to save the model
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved to {filepath}")

def load_model(filepath):
    """
    Load a trained model from disk
    
    Args:
        filepath: Path to the saved model
    
    Returns:
        Loaded model object
    """
    with open(filepath, 'rb') as f:
        model = pickle.load(f)
    print(f"Model loaded from {filepath}")
    return model

def save_json(data, filepath):
    """
    Save data as JSON file
    
    Args:
        data: Data to save (dict or list)
        filepath: Path to save the JSON file
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def load_json(filepath):
    """
    Load data from JSON file
    
    Args:
        filepath: Path to the JSON file
    
    Returns:
        Loaded data
    """
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data

def plot_confusion_matrix(cm, classes, filepath=None, title='Confusion Matrix'):
    """
    Plot confusion matrix
    
    Args:
        cm: Confusion matrix array
        classes: List of class names
        filepath: Optional path to save the plot
        title: Plot title
    """
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=classes, yticklabels=classes)
    plt.title(title, fontsize=16, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    
    if filepath:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"Confusion matrix saved to {filepath}")
    
    plt.close()

def plot_roc_curve(fpr, tpr, auc_score, filepath=None, title='ROC Curve'):
    """
    Plot ROC curve
    
    Args:
        fpr: False positive rate
        tpr: True positive rate
        auc_score: AUC score
        filepath: Optional path to save the plot
        title: Plot title
    """
    plt.figure(figsize=(10, 8))
    plt.plot(fpr, tpr, color='darkorange', lw=2, 
             label=f'ROC curve (AUC = {auc_score:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title(title, fontsize=16, fontweight='bold')
    plt.legend(loc="lower right", fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    
    if filepath:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"ROC curve saved to {filepath}")
    
    plt.close()

def plot_feature_importance(feature_names, importances, filepath=None, top_n=20):
    """
    Plot feature importance
    
    Args:
        feature_names: List of feature names
        importances: Feature importance values
        filepath: Optional path to save the plot
        top_n: Number of top features to display
    """
    # Sort features by importance
    indices = np.argsort(importances)[::-1][:top_n]
    
    plt.figure(figsize=(12, 8))
    plt.barh(range(top_n), importances[indices], color='steelblue')
    plt.yticks(range(top_n), [feature_names[i] for i in indices])
    plt.xlabel('Importance', fontsize=12)
    plt.title(f'Top {top_n} Feature Importances', fontsize=16, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    
    if filepath:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"Feature importance plot saved to {filepath}")
    
    plt.close()

def get_timestamp():
    """
    Get current timestamp as string
    
    Returns:
        Formatted timestamp string
    """
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def format_alert(attack_type, confidence, source_ip=None, dest_ip=None, protocol=None):
    """
    Format alert message
    
    Args:
        attack_type: Type of attack detected
        confidence: Confidence score
        source_ip: Source IP address
        dest_ip: Destination IP address
        protocol: Protocol type
    
    Returns:
        Formatted alert message
    """
    alert = {
        'timestamp': get_timestamp(),
        'attack_type': attack_type,
        'confidence': f"{confidence:.2%}",
        'source_ip': source_ip or 'N/A',
        'dest_ip': dest_ip or 'N/A',
        'protocol': protocol or 'N/A'
    }
    return alert

def print_metrics(metrics_dict):
    """
    Pretty print evaluation metrics
    
    Args:
        metrics_dict: Dictionary of metrics
    """
    print("\n" + "="*60)
    print("PERFORMANCE METRICS")
    print("="*60)
    for key, value in metrics_dict.items():
        if isinstance(value, float):
            print(f"{key:.<40} {value:.4f}")
        else:
            print(f"{key:.<40} {value}")
    print("="*60 + "\n")
