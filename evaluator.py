"""
Model Evaluation Module
Calculates performance metrics and generates visualizations
"""

import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_curve, auc,
    roc_auc_score
)
from sklearn.preprocessing import label_binarize
import os
from utils import (
    setup_logging, plot_confusion_matrix, plot_roc_curve,
    plot_feature_importance, print_metrics, save_json
)
from config import RESULTS_DIR

logger = setup_logging(__name__)

class ModelEvaluator:
    """
    Evaluates machine learning models and generates performance reports
    """
    
    def __init__(self, model_name='Model'):
        """
        Initialize evaluator
        
        Args:
            model_name: Name of the model being evaluated
        """
        self.model_name = model_name
        self.results = {}
        logger.info(f"ModelEvaluator initialized for {model_name}")
    
    def evaluate(self, y_true, y_pred, y_pred_proba=None, class_names=None):
        """
        Comprehensive model evaluation
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_pred_proba: Prediction probabilities (optional)
            class_names: List of class names
        
        Returns:
            Dictionary of evaluation metrics
        """
        logger.info(f"Evaluating {self.model_name}...")
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        
        # Multi-class metrics
        precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        
        # Per-class metrics
        precision_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
        recall_per_class = recall_score(y_true, y_pred, average=None, zero_division=0)
        f1_per_class = f1_score(y_true, y_pred, average=None, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        # Store results
        self.results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'precision_per_class': precision_per_class.tolist(),
            'recall_per_class': recall_per_class.tolist(),
            'f1_per_class': f1_per_class.tolist(),
            'confusion_matrix': cm.tolist()
        }
        
        # ROC-AUC for multi-class (if probabilities provided)
        if y_pred_proba is not None and len(np.unique(y_true)) > 2:
            try:
                # Binarize labels for multi-class ROC
                n_classes = len(np.unique(y_true))
                y_true_bin = label_binarize(y_true, classes=range(n_classes))
                
                # Calculate ROC-AUC
                roc_auc = roc_auc_score(y_true_bin, y_pred_proba, average='weighted', multi_class='ovr')
                self.results['roc_auc'] = roc_auc
            except Exception as e:
                logger.warning(f"Could not calculate ROC-AUC: {e}")
        
        # Binary classification ROC-AUC
        elif y_pred_proba is not None and len(np.unique(y_true)) == 2:
            roc_auc = roc_auc_score(y_true, y_pred_proba[:, 1])
            self.results['roc_auc'] = roc_auc
        
        # Classification report
        if class_names is None:
            class_names = [f"Class_{i}" for i in range(len(np.unique(y_true)))]
        
        report = classification_report(y_true, y_pred, target_names=class_names, zero_division=0)
        self.results['classification_report'] = report
        
        # Print metrics
        print_metrics({
            'Model': self.model_name,
            'Accuracy': accuracy,
            'Precision (weighted)': precision,
            'Recall (weighted)': recall,
            'F1-Score (weighted)': f1,
            'ROC-AUC': self.results.get('roc_auc', 'N/A')
        })
        
        print("\nClassification Report:")
        print(report)
        
        return self.results
    
    def plot_confusion_matrix(self, y_true, y_pred, class_names, save_path=None):
        """
        Generate and save confusion matrix plot
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            class_names: List of class names
            save_path: Path to save the plot
        """
        cm = confusion_matrix(y_true, y_pred)
        
        if save_path is None:
            save_path = os.path.join(RESULTS_DIR, f'{self.model_name}_confusion_matrix.png')
        
        plot_confusion_matrix(
            cm, 
            class_names, 
            filepath=save_path,
            title=f'{self.model_name} - Confusion Matrix'
        )
    
    def plot_roc_curves(self, y_true, y_pred_proba, class_names, save_path=None):
        """
        Generate and save ROC curves
        
        Args:
            y_true: True labels
            y_pred_proba: Prediction probabilities
            class_names: List of class names
            save_path: Path to save the plot
        """
        if save_path is None:
            save_path = os.path.join(RESULTS_DIR, f'{self.model_name}_roc_curves.png')
        
        n_classes = len(class_names)
        
        # Binary classification
        if n_classes == 2:
            fpr, tpr, _ = roc_curve(y_true, y_pred_proba[:, 1])
            auc_score = auc(fpr, tpr)
            plot_roc_curve(fpr, tpr, auc_score, filepath=save_path,
                          title=f'{self.model_name} - ROC Curve')
        
        # Multi-class classification
        else:
            import matplotlib.pyplot as plt
            
            # Binarize labels
            y_true_bin = label_binarize(y_true, classes=range(n_classes))
            
            plt.figure(figsize=(12, 8))
            
            # Plot ROC curve for each class
            for i in range(n_classes):
                fpr, tpr, _ = roc_curve(y_true_bin[:, i], y_pred_proba[:, i])
                auc_score = auc(fpr, tpr)
                plt.plot(fpr, tpr, lw=2, label=f'{class_names[i]} (AUC = {auc_score:.2f})')
            
            plt.plot([0, 1], [0, 1], 'k--', lw=2, label='Random Classifier')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate', fontsize=12)
            plt.ylabel('True Positive Rate', fontsize=12)
            plt.title(f'{self.model_name} - ROC Curves (Multi-class)', fontsize=16, fontweight='bold')
            plt.legend(loc="lower right", fontsize=9)
            plt.grid(alpha=0.3)
            plt.tight_layout()
            
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"ROC curves saved to {save_path}")
            plt.close()
    
    def plot_feature_importance(self, model, feature_names, save_path=None, top_n=20):
        """
        Plot feature importance for tree-based models
        
        Args:
            model: Trained model with feature_importances_ attribute
            feature_names: List of feature names
            save_path: Path to save the plot
            top_n: Number of top features to display
        """
        if not hasattr(model, 'feature_importances_'):
            logger.warning("Model does not have feature_importances_ attribute")
            return
        
        if save_path is None:
            save_path = os.path.join(RESULTS_DIR, f'{self.model_name}_feature_importance.png')
        
        plot_feature_importance(
            feature_names,
            model.feature_importances_,
            filepath=save_path,
            top_n=top_n
        )
    
    def save_results(self, filepath=None):
        """
        Save evaluation results to JSON
        
        Args:
            filepath: Path to save results
        """
        if filepath is None:
            filepath = os.path.join(RESULTS_DIR, f'{self.model_name}_results.json')
        
        save_json(self.results, filepath)
        logger.info(f"Results saved to {filepath}")
    
    def generate_report(self, y_true, y_pred, y_pred_proba, model, 
                       class_names, feature_names):
        """
        Generate complete evaluation report with all visualizations
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_pred_proba: Prediction probabilities
            model: Trained model
            class_names: List of class names
            feature_names: List of feature names
        """
        logger.info(f"Generating complete evaluation report for {self.model_name}...")
        
        # Evaluate metrics
        self.evaluate(y_true, y_pred, y_pred_proba, class_names)
        
        # Generate visualizations
        self.plot_confusion_matrix(y_true, y_pred, class_names)
        
        if y_pred_proba is not None:
            self.plot_roc_curves(y_true, y_pred_proba, class_names)
        
        if hasattr(model, 'feature_importances_'):
            self.plot_feature_importance(model, feature_names)
        
        # Save results
        self.save_results()
        
        logger.info(f"Evaluation report complete. Results saved to {RESULTS_DIR}")

if __name__ == "__main__":
    print("ModelEvaluator module ready.")
