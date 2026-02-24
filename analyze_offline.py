"""
Offline Analysis Script
Analyze a test dataset using a trained model
"""

import argparse
import pandas as pd
import numpy as np
import os
import sys
from data_handler import DataHandler
from evaluator import ModelEvaluator
from utils import setup_logging, load_model
from config import BEST_MODEL_PATH, TRAIN_FILE, TEST_FILE

logger = setup_logging(__name__)

def analyze_offline(model_path, dataset_path=None):
    """
    Perform offline analysis on a dataset
    
    Args:
        model_path: Path to the trained model file
        dataset_path: Path to the dataset file (optional, defaults to test set)
    """
    logger.info("="*60)
    logger.info("OFFLINE ANALYSIS")
    logger.info("="*60)
    
    # 1. Load Model
    if not os.path.exists(model_path):
        logger.error(f"Model file not found: {model_path}")
        return
        
    try:
        model = load_model(model_path)
        logger.info(f"Model loaded from {model_path}")
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return

    # 2. Load Data
    handler = DataHandler()
    
    try:
        # Load test data
        # If dataset_path is provided, use it. Otherwise use the default test file.
        test_file = dataset_path if dataset_path else TEST_FILE
        
        if not os.path.exists(test_file):
             logger.error(f"Dataset file not found: {test_file}")
             print(f"Please use --dataset to specify a valid dataset file or ensure {TEST_FILE} exists.")
             return

        logger.info(f"Loading dataset from: {test_file}")
        
        # We need the training data structure to ensure consistent preprocessing
        # In a real scenario, we'd save the scaler/encoder and load them, 
        # which DataHandler does implicitly if they exist, but we still need the column structure.
        # For simplicity, we'll reload the train file structure just to get column names correct if passing a raw CSV without headers
        # However, NSL-KDD files usually don't have headers.
        
        # Determine if we are loading the standard NSL-KDD test set or a custom CSV
        # If custom CSV, we assume it has the same structure as NSL-KDD
        
        # We'll use the handler's load method which handles the column names
        # We pass the same file as both train and test to trick it into loading just that file for processing
        # effectively, or we can just use the preprocess method carefully.
        
        # Let's load standard train data to fit the scaler/encoder if they aren't already fitted
        # But wait, we should rely on the saved scaler/encoder from training.
        # The DataHandler.preprocess_data method refits the scaler if we pass both train/test.
        
        # A better approach for this script is to load the saved scaler/encoder manually or modify DataHandler
        # to support "transform only" mode.
        # For now, let's just load the train/test pair as usual to ensure compatibility, 
        # but replace the 'test' portion with our target dataset.
        
        train_df, _ = handler.load_nsl_kdd(train_file=TRAIN_FILE, test_file=test_file)
        
        # Preprocess
        # This will re-fit the scaler on TRAIN_FILE and transform our target dataset
        # This ensures the features are scaled exactly as the model expects
        _, X_test, _, y_test = handler.preprocess_data(
            train_df, 
            pd.read_csv(test_file, names=handler.nsl_kdd_columns, header=None), # Load the target file as test_df
            binary_classification=False
        )
        
    except Exception as e:
        logger.error(f"Error preprocessing data: {e}")
        return

    # 3. Analyze
    logger.info("Running predictions...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    # 4. Evaluate
    class_names = handler.get_class_names()
    feature_names = handler.get_feature_names()
    
    evaluator = ModelEvaluator(model_name=os.path.basename(model_path))
    evaluator.generate_report(
        y_test, y_pred, y_pred_proba,
        model, class_names, feature_names
    )
    
    logger.info("Analysis complete. Check results/ directory for reports.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze offline dataset')
    parser.add_argument('--model', type=str, default=BEST_MODEL_PATH, help='Path to trained model')
    parser.add_argument('--dataset', type=str, default=None, help='Path to dataset to analyze')
    
    args = parser.parse_args()
    
    analyze_offline(args.model, args.dataset)
