"""
Random Forest Model for Network Traffic Classification
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import numpy as np
from utils import setup_logging, save_model
from config import RANDOM_FOREST_PARAMS, CROSS_VALIDATION_FOLDS

logger = setup_logging(__name__)

class RandomForestModel:
    """
    Random Forest classifier for intrusion detection
    """
    
    def __init__(self, **kwargs):
        """
        Initialize Random Forest model
        
        Args:
            **kwargs: Additional parameters for RandomForestClassifier
        """
        params = RANDOM_FOREST_PARAMS.copy()
        params.update(kwargs)
        
        self.model = RandomForestClassifier(**params)
        self.is_trained = False
        
        logger.info(f"Random Forest model initialized with params: {params}")
    
    def train(self, X_train, y_train, cross_validate=True):
        """
        Train the Random Forest model
        
        Args:
            X_train: Training features
            y_train: Training labels
            cross_validate: Whether to perform cross-validation
        
        Returns:
            Trained model
        """
        logger.info("Training Random Forest model...")
        
        # Cross-validation
        if cross_validate:
            logger.info(f"Performing {CROSS_VALIDATION_FOLDS}-fold cross-validation...")
            cv_scores = cross_val_score(
                self.model, X_train, y_train,
                cv=CROSS_VALIDATION_FOLDS,
                scoring='accuracy',
                n_jobs=-1
            )
            logger.info(f"Cross-validation scores: {cv_scores}")
            logger.info(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Train on full training set
        self.model.fit(X_train, y_train)
        self.is_trained = True
        
        logger.info("Random Forest training complete")
        
        return self.model
    
    def predict(self, X):
        """
        Make predictions
        
        Args:
            X: Features to predict
        
        Returns:
            Predicted labels
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """
        Predict class probabilities
        
        Args:
            X: Features to predict
        
        Returns:
            Class probabilities
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        return self.model.predict_proba(X)
    
    def get_feature_importance(self):
        """
        Get feature importances
        
        Returns:
            Feature importance array
        """
        if not self.is_trained:
            raise ValueError("Model must be trained first")
        
        return self.model.feature_importances_
    
    def save(self, filepath):
        """
        Save the trained model
        
        Args:
            filepath: Path to save the model
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        save_model(self.model, filepath)
        logger.info(f"Random Forest model saved to {filepath}")

if __name__ == "__main__":
    print("Random Forest model module ready.")
