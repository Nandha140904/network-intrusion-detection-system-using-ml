"""
Main Training Script
Downloads dataset, trains models, and generates evaluation reports
"""

import sys
from download_dataset import download_nsl_kdd
from data_handler import DataHandler
from models.random_forest_model import RandomForestModel
from models.xgboost_model import XGBoostModel
from evaluator import ModelEvaluator
from utils import setup_logging, save_model
from config import MODELS_DIR, BEST_MODEL_PATH

logger = setup_logging(__name__)

def main():
    """
    Main training pipeline
    """
    logger.info("="*60)
    logger.info("NETWORK INTRUSION DETECTION SYSTEM - MODEL TRAINING")
    logger.info("="*60)
    
    # Step 1: Download dataset
    logger.info("\nStep 1: Downloading NSL-KDD Dataset...")
    if not download_nsl_kdd():
        logger.error("Failed to download dataset. Exiting.")
        return
    
    # Step 2: Load and preprocess data
    logger.info("\nStep 2: Loading and Preprocessing Data...")
    handler = DataHandler()
    
    try:
        train_df, test_df = handler.load_nsl_kdd()
    except FileNotFoundError:
        logger.error("Dataset files not found. Please run download_dataset.py first.")
        return
    
    X_train, X_test, y_train, y_test = handler.preprocess_data(
        train_df, test_df, binary_classification=False
    )
    
    # Handle class imbalance
    X_train, y_train = handler.handle_imbalance(X_train, y_train)
    
    class_names = handler.get_class_names()
    feature_names = handler.get_feature_names()
    
    logger.info(f"Training samples: {X_train.shape[0]}")
    logger.info(f"Test samples: {X_test.shape[0]}")
    logger.info(f"Features: {X_train.shape[1]}")
    logger.info(f"Classes: {class_names}")
    
    # Step 3: Train Random Forest
    logger.info("\nStep 3: Training Random Forest Model...")
    rf_model = RandomForestModel()
    rf_model.train(X_train, y_train, cross_validate=True)
    
    # Evaluate Random Forest
    y_pred_rf = rf_model.predict(X_test)
    y_pred_proba_rf = rf_model.predict_proba(X_test)
    
    evaluator_rf = ModelEvaluator('RandomForest')
    evaluator_rf.generate_report(
        y_test, y_pred_rf, y_pred_proba_rf,
        rf_model.model, class_names, feature_names
    )
    
    # Save Random Forest model
    rf_model.save(f"{MODELS_DIR}/random_forest.pkl")
    
    # Step 4: Train XGBoost
    logger.info("\nStep 4: Training XGBoost Model...")
    xgb_model = XGBoostModel()
    xgb_model.train(X_train, y_train, cross_validate=True)
    
    # Evaluate XGBoost
    y_pred_xgb = xgb_model.predict(X_test)
    y_pred_proba_xgb = xgb_model.predict_proba(X_test)
    
    evaluator_xgb = ModelEvaluator('XGBoost')
    evaluator_xgb.generate_report(
        y_test, y_pred_xgb, y_pred_proba_xgb,
        xgb_model.model, class_names, feature_names
    )
    
    # Save XGBoost model
    xgb_model.save(f"{MODELS_DIR}/xgboost.pkl")
    
    # Step 5: Compare and save best model
    logger.info("\nStep 5: Model Comparison...")
    
    rf_accuracy = evaluator_rf.results['accuracy']
    xgb_accuracy = evaluator_xgb.results['accuracy']
    
    logger.info(f"Random Forest Accuracy: {rf_accuracy:.4f}")
    logger.info(f"XGBoost Accuracy: {xgb_accuracy:.4f}")
    
    if xgb_accuracy > rf_accuracy:
        logger.info("XGBoost is the best model!")
        save_model(xgb_model.model, BEST_MODEL_PATH)
    else:
        logger.info("Random Forest is the best model!")
        save_model(rf_model.model, BEST_MODEL_PATH)
    
    logger.info("\n" + "="*60)
    logger.info("TRAINING COMPLETE!")
    logger.info("="*60)
    logger.info(f"Models saved to: {MODELS_DIR}")
    logger.info(f"Best model: {BEST_MODEL_PATH}")
    logger.info(f"Results saved to: results/")
    logger.info("\nYou can now run the dashboard: python app.py")

if __name__ == "__main__":
    main()
