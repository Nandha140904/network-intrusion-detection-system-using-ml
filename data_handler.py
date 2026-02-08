"""
Data Handler for Network Traffic Classification
Handles dataset loading, preprocessing, and feature engineering
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import os
from utils import setup_logging, save_model, load_model
from config import *

logger = setup_logging(__name__)

class DataHandler:
    """
    Handles all data-related operations including loading, preprocessing, and feature engineering
    """
    
    def __init__(self, dataset_name='NSL-KDD'):
        """
        Initialize DataHandler
        
        Args:
            dataset_name: Name of the dataset to use
        """
        self.dataset_name = dataset_name
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = None
        self.categorical_columns = []
        self.numerical_columns = []
        
        # NSL-KDD column names
        self.nsl_kdd_columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        logger.info(f"DataHandler initialized for {dataset_name}")
    
    def load_nsl_kdd(self, train_file=None, test_file=None):
        """
        Load NSL-KDD dataset
        
        Args:
            train_file: Path to training file
            test_file: Path to test file
        
        Returns:
            train_df, test_df: Training and testing DataFrames
        """
        logger.info("Loading NSL-KDD dataset...")
        
        train_file = train_file or TRAIN_FILE
        test_file = test_file or TEST_FILE
        
        try:
            # Load training data
            train_df = pd.read_csv(train_file, names=self.nsl_kdd_columns, header=None)
            logger.info(f"Training data loaded: {train_df.shape}")
            
            # Load test data
            test_df = pd.read_csv(test_file, names=self.nsl_kdd_columns, header=None)
            logger.info(f"Test data loaded: {test_df.shape}")
            
            # Remove difficulty column
            train_df = train_df.drop('difficulty', axis=1)
            test_df = test_df.drop('difficulty', axis=1)
            
            return train_df, test_df
            
        except FileNotFoundError:
            logger.error(f"Dataset files not found. Please download NSL-KDD dataset.")
            logger.info("Download from: https://www.unb.ca/cic/datasets/nsl.html")
            logger.info(f"Place files in: {DATA_DIR}")
            raise
    
    def categorize_attacks(self, df):
        """
        Categorize attacks into main categories
        
        Args:
            df: DataFrame with 'label' column
        
        Returns:
            DataFrame with categorized labels
        """
        # Attack type mappings
        dos_attacks = ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 
                       'mailbomb', 'apache2', 'processtable', 'udpstorm']
        probe_attacks = ['satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint']
        r2l_attacks = ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop',
                       'warezmaster', 'warezclient', 'spy', 'xlock', 'xsnoop',
                       'snmpguess', 'snmpgetattack', 'httptunnel', 'sendmail', 'named']
        u2r_attacks = ['buffer_overflow', 'loadmodule', 'rootkit', 'perl',
                       'sqlattack', 'xterm', 'ps']
        
        def categorize(label):
            label = label.strip().lower()
            if label == 'normal':
                return 'normal'
            elif label in dos_attacks:
                return 'DoS'
            elif label in probe_attacks:
                return 'Probe'
            elif label in r2l_attacks:
                return 'R2L'
            elif label in u2r_attacks:
                return 'U2R'
            else:
                return 'DoS'  # Default for unknown attacks
        
        df['label'] = df['label'].apply(categorize)
        return df
    
    def preprocess_data(self, train_df, test_df, binary_classification=False):
        """
        Preprocess the dataset
        
        Args:
            train_df: Training DataFrame
            test_df: Test DataFrame
            binary_classification: If True, convert to binary (normal vs attack)
        
        Returns:
            X_train, X_test, y_train, y_test
        """
        logger.info("Preprocessing data...")
        
        # Categorize attacks
        train_df = self.categorize_attacks(train_df)
        test_df = self.categorize_attacks(test_df)
        
        # Binary classification: normal vs attack
        if binary_classification:
            train_df['label'] = train_df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
            test_df['label'] = test_df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
        
        # Identify categorical and numerical columns
        self.categorical_columns = ['protocol_type', 'service', 'flag']
        self.numerical_columns = [col for col in train_df.columns 
                                 if col not in self.categorical_columns + ['label']]
        
        # Encode categorical features
        for col in self.categorical_columns:
            le = LabelEncoder()
            train_df[col] = le.fit_transform(train_df[col].astype(str))
            # Handle unseen categories in test set
            test_df[col] = test_df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
            test_df[col] = le.transform(test_df[col].astype(str))
        
        # Separate features and labels
        X_train = train_df.drop('label', axis=1)
        y_train = train_df['label']
        X_test = test_df.drop('label', axis=1)
        y_test = test_df['label']
        
        # Store feature names
        self.feature_names = X_train.columns.tolist()
        
        # Encode labels
        y_train = self.label_encoder.fit_transform(y_train)
        y_test = self.label_encoder.transform(y_test)
        
        # Scale features
        if FEATURE_SCALING:
            X_train = self.scaler.fit_transform(X_train)
            X_test = self.scaler.transform(X_test)
            
            # Save scaler
            save_model(self.scaler, SCALER_PATH)
        
        # Save label encoder
        save_model(self.label_encoder, ENCODER_PATH)
        
        logger.info(f"Preprocessing complete. Train: {X_train.shape}, Test: {X_test.shape}")
        logger.info(f"Classes: {self.label_encoder.classes_}")
        
        return X_train, X_test, y_train, y_test
    
    def handle_imbalance(self, X_train, y_train):
        """
        Handle class imbalance using SMOTE
        
        Args:
            X_train: Training features
            y_train: Training labels
        
        Returns:
            X_resampled, y_resampled
        """
        if not HANDLE_IMBALANCE:
            return X_train, y_train
        
        logger.info("Handling class imbalance with SMOTE...")
        logger.info(f"Original distribution: {np.bincount(y_train)}")
        
        smote = SMOTE(random_state=RANDOM_STATE)
        X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
        
        logger.info(f"Resampled distribution: {np.bincount(y_resampled)}")
        
        return X_resampled, y_resampled
    
    def get_class_names(self):
        """
        Get class names
        
        Returns:
            List of class names
        """
        return self.label_encoder.classes_.tolist()
    
    def get_feature_names(self):
        """
        Get feature names
        
        Returns:
            List of feature names
        """
        return self.feature_names

if __name__ == "__main__":
    # Test data loading
    handler = DataHandler()
    
    # Note: You need to download NSL-KDD dataset first
    # Download from: https://www.unb.ca/cic/datasets/nsl.html
    # Place KDDTrain+.txt and KDDTest+.txt in the data/ directory
    
    print("DataHandler module ready.")
    print(f"Please download NSL-KDD dataset and place in: {DATA_DIR}")
