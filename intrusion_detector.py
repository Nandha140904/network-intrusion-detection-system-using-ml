"""
Real-time Intrusion Detection Engine
Integrates packet capture, feature extraction, and ML classification
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from packet_capture import PacketCapture
from feature_extractor import FeatureExtractor
from alert_system import AlertSystem
from host_tracker import HostTracker
from utils import setup_logging, load_model
from config import BEST_MODEL_PATH, SCALER_PATH, ENCODER_PATH, NETWORK_INTERFACE

logger = setup_logging(__name__)

class IntrusionDetector:
    """
    Real-time intrusion detection system
    """
    
    def __init__(self, model_path=None, interface=None):
        """
        Initialize IntrusionDetector
        
        Args:
            model_path: Path to trained model
            interface: Network interface to monitor
        """
        self.model_path = model_path or BEST_MODEL_PATH
        self.interface = interface or NETWORK_INTERFACE
        
        # Load model and preprocessors
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self._load_model()
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.alert_system = AlertSystem()
        self.host_tracker = HostTracker()
        self.packet_capture = PacketCapture(
            interface=self.interface,
            packet_callback=None  # We'll process in batches
        )
        
        # Statistics
        self.total_packets = 0
        self.total_attacks = 0
        self.total_normal = 0
        
        logger.info("IntrusionDetector initialized")
    
    def _load_model(self):
        """
        Load trained model and preprocessors
        """
        try:
            logger.info(f"Loading model from {self.model_path}...")
            self.model = load_model(self.model_path)
            
            logger.info(f"Loading scaler from {SCALER_PATH}...")
            self.scaler = load_model(SCALER_PATH)
            
            logger.info(f"Loading label encoder from {ENCODER_PATH}...")
            self.label_encoder = load_model(ENCODER_PATH)
            
            logger.info("Model and preprocessors loaded successfully")
        
        except FileNotFoundError as e:
            logger.error(f"Model files not found: {e}")
            logger.error("Please train the model first using train_models.py")
            raise
    
    def preprocess_features(self, flow_features):
        """
        Preprocess flow features for model prediction
        
        Args:
            flow_features: Dictionary of flow features
        
        Returns:
            Preprocessed feature array
        """
        try:
            # Convert to DataFrame
            df = pd.DataFrame([flow_features])
            
            # Encode categorical features
            categorical_columns = ['protocol_type', 'service', 'flag']
            for col in categorical_columns:
                if col in df.columns:
                    # Simple encoding for real-time (use first character hash)
                    df[col] = df[col].apply(lambda x: hash(str(x)) % 100)
            
            # Ensure all required features are present (41 features for NSL-KDD)
            required_features = [
                'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
                'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
                'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
                'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
            ]
            
            # Reorder columns
            df = df[required_features]
            
            # Scale features
            features_scaled = self.scaler.transform(df)
            
            return features_scaled
        
        except Exception as e:
            logger.error(f"Error preprocessing features: {e}")
            return None
    
    def classify_traffic(self, flow_features, packet_info=None):
        """
        Classify network traffic
        
        Args:
            flow_features: Dictionary of flow features
            packet_info: Optional packet information for alerts
        
        Returns:
            Tuple of (prediction, confidence)
        """
        try:
            # Preprocess features
            features = self.preprocess_features(flow_features)
            
            if features is None:
                return None, 0.0
            
            # Predict
            prediction_encoded = self.model.predict(features)[0]
            prediction_proba = self.model.predict_proba(features)[0]
            
            # Decode prediction
            prediction = self.label_encoder.inverse_transform([prediction_encoded])[0]
            confidence = prediction_proba[prediction_encoded]
            
            # Update statistics
            self.total_packets += 1
            if prediction == 'normal':
                self.total_normal += 1
            else:
                self.total_attacks += 1
            
            # Check for alerts
            self.alert_system.check_and_alert(prediction, confidence, packet_info)
            
            # Update known hosts
            src_ip = None
            if packet_info and 'src_ip' in packet_info:
                src_ip = packet_info.get('src_ip')
            elif isinstance(flow_features, dict) and 'src_ip' in flow_features:
                src_ip = flow_features.get('src_ip')
            
            if src_ip and src_ip != 'unknown':
                is_malicious = (prediction != 'normal')
                packet_count = flow_features.get('count', 1) if isinstance(flow_features, dict) else 1
                self.host_tracker.update_host(src_ip, packet_count=packet_count, is_malicious=is_malicious)
                
                # Periodically save hosts (e.g. every 100 packets or on stop)
                if self.total_packets % 100 == 0:
                     self.host_tracker.save_hosts()
            
            return prediction, confidence
        
        except Exception as e:
            logger.error(f"Error classifying traffic: {e}")
            return None, 0.0
    
    def start_monitoring(self, duration=None):
        """
        Start real-time network monitoring
        
        Args:
            duration: Monitoring duration in seconds (None = infinite)
        """
        logger.info("="*60)
        logger.info("STARTING REAL-TIME INTRUSION DETECTION")
        logger.info("="*60)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Duration: {duration if duration else 'infinite'}")
        logger.info("="*60)
        
        try:
            # Start packet capture in async mode
            self.packet_capture.start_capture_async(timeout=duration)
            
            # Monitor and classify traffic periodically
            import time
            # Monitor and classify traffic periodically
            import time
            while self.packet_capture.is_capturing:
                time.sleep(1)  # Process every 1 second
                
                # Get flow features (potentially list of flows)
                flow_features_list = self.packet_capture.get_flow_features()
                
                # If get_flow_features returns a single dict (legacy), make it a list
                if isinstance(flow_features_list, dict):
                    flow_features_list = [flow_features_list]
                    
                if flow_features_list:
                    for flow_features in flow_features_list:
                        # Classify traffic
                        prediction, confidence = self.classify_traffic(flow_features)
                        
                        if prediction:
                            logger.info(f"Classification: {prediction} (confidence: {confidence:.2%})")
            
            logger.info("Monitoring stopped")
            self.host_tracker.save_hosts()
            self.print_statistics()
        
        except KeyboardInterrupt:
            logger.info("\nMonitoring interrupted by user")
            self.packet_capture.stop_capture()
            self.print_statistics()
        
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
            self.packet_capture.stop_capture()
    
    def print_statistics(self):
        """
        Print detection statistics
        """
        print("\n" + "="*60)
        print("DETECTION STATISTICS")
        print("="*60)
        print(f"Total Packets Analyzed: {self.total_packets}")
        print(f"Normal Traffic:         {self.total_normal}")
        print(f"Attacks Detected:       {self.total_attacks}")
        
        if self.total_packets > 0:
            attack_rate = (self.total_attacks / self.total_packets) * 100
            print(f"Attack Rate:            {attack_rate:.2f}%")
        
        print("\nAlert Statistics:")
        alert_stats = self.alert_system.get_alert_stats()
        print(f"Total Alerts:           {alert_stats['total_alerts']}")
        print("\nAttack Distribution:")
        for attack_type, count in alert_stats['attack_distribution'].items():
            if count > 0:
                print(f"  {attack_type:.<20} {count}")
        print("="*60 + "\n")

if __name__ == "__main__":
    print("IntrusionDetector module ready.")
    print("\nNote: Real-time detection requires:")
    print("1. Trained model (run train_models.py first)")
    print("2. Administrator/root privileges for packet capture")
