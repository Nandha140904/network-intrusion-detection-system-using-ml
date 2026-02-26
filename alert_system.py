"""
Alert System for Intrusion Detection
Manages alerts and notifications for detected attacks
"""

import os
import json
from datetime import datetime
from collections import deque
from utils import setup_logging, format_alert
from config import ALERT_THRESHOLD, ALERT_LOG_FILE, MAX_ALERTS_DISPLAY, ATTACK_CATEGORIES

logger = setup_logging(__name__)

class AlertSystem:
    """
    Manages intrusion detection alerts
    """
    
    def __init__(self, threshold=None, max_alerts=None):
        """
        Initialize AlertSystem
        
        Args:
            threshold: Confidence threshold for raising alerts
            max_alerts: Maximum number of alerts to keep in memory
        """
        self.threshold = threshold or ALERT_THRESHOLD
        self.max_alerts = max_alerts or MAX_ALERTS_DISPLAY
        
        self.alerts = deque(maxlen=self.max_alerts)
        self.alert_count = 0
        self.attack_stats = {category: 0 for category in ATTACK_CATEGORIES.keys()}
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(ALERT_LOG_FILE), exist_ok=True)
        
        logger.info(f"AlertSystem initialized (threshold: {self.threshold})")
    
    def check_and_alert(self, prediction, confidence, packet_info=None):
        """
        Check if an alert should be raised
        
        Args:
            prediction: Predicted attack type
            confidence: Prediction confidence (0-1)
            packet_info: Optional packet information dict
        
        Returns:
            Alert dictionary if raised, None otherwise
        """
        # Only alert if not normal traffic and confidence exceeds threshold
        if prediction != 'normal' and confidence >= self.threshold:
            return self.raise_alert(prediction, confidence, packet_info)
        
        return None
    
    def raise_alert(self, attack_type, confidence, packet_info=None):
        """
        Raise an intrusion detection alert
        
        Args:
            attack_type: Type of attack detected
            confidence: Confidence score (0-1)
            packet_info: Optional packet information dict
        
        Returns:
            Alert dictionary
        """
        # Extract packet information
        source_ip = packet_info.get('src_ip') if packet_info else None
        dest_ip = packet_info.get('dst_ip') if packet_info else None
        protocol = packet_info.get('protocol_type') if packet_info else None
        
        # Format alert
        alert = format_alert(
            attack_type=ATTACK_CATEGORIES.get(attack_type, attack_type),
            confidence=confidence,
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol
        )
        
        # Add alert to queue
        self.alerts.append(alert)
        self.alert_count += 1
        
        # Update statistics
        if attack_type in self.attack_stats:
            self.attack_stats[attack_type] += 1
        
        # Log alert
        self._log_alert(alert)
        
        # Print alert
        self._print_alert(alert)
        
        return alert
    
    def _log_alert(self, alert):
        """
        Log alert to file
        
        Args:
            alert: Alert dictionary
        """
        try:
            with open(ALERT_LOG_FILE, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            logger.error(f"Error logging alert: {e}")
    
    # Rate limiting for alert sound to avoid thread spam during heavy attacks
    _last_sound_time = 0

    def _print_alert(self, alert):
        """
        Print alert to console
        
        Args:
            alert: Alert dictionary
        """
        print("\n" + "="*60)
        print("🚨 INTRUSION ALERT")
        print("="*60)
        print(f"Timestamp:    {alert['timestamp']}")
        print(f"Attack Type:  {alert['attack_type']}")
        print(f"Confidence:   {alert['confidence']}")
        print(f"Source IP:    {alert['source_ip']}")
        print(f"Dest IP:      {alert['dest_ip']}")
        print(f"Protocol:     {alert['protocol']}")
        print("="*60 + "\n")
        
        # Play an audible alert sound in a separate thread to avoid blocking packet capture
        import time
        current_time = time.time()
        
        # Rate limit: only play sound max once every 3 seconds
        if current_time - getattr(self.__class__, '_last_sound_time', 0) > 3.0:
            self.__class__._last_sound_time = current_time
            def play_sound():
                try:
                    import platform
                    if platform.system() == 'Windows':
                        import winsound
                        # Play 3 quick alert beeps
                        for _ in range(3):
                            winsound.Beep(2500, 200)
                            time.sleep(0.1)
                except Exception as e:
                    logger.error(f"Could not play alert sound: {e}")
                    
            import threading
            threading.Thread(target=play_sound, daemon=True).start()
    
    def get_recent_alerts(self, count=None):
        """
        Get recent alerts
        
        Args:
            count: Number of alerts to retrieve (None = all)
        
        Returns:
            List of alert dictionaries
        """
        if count is None:
            return list(self.alerts)
        else:
            return list(self.alerts)[-count:]
    
    def get_alert_stats(self):
        """
        Get alert statistics
        
        Returns:
            Dictionary of statistics
        """
        return {
            'total_alerts': self.alert_count,
            'attack_distribution': self.attack_stats.copy(),
            'recent_alerts_count': len(self.alerts)
        }
    
    def clear_alerts(self):
        """
        Clear all alerts from memory (not from log file)
        """
        self.alerts.clear()
        logger.info("Alerts cleared from memory")
    
    def reset_stats(self):
        """
        Reset alert statistics
        """
        self.alert_count = 0
        self.attack_stats = {category: 0 for category in ATTACK_CATEGORIES.keys()}
        logger.info("Alert statistics reset")
    
    def load_alerts_from_log(self, max_count=None):
        """
        Load alerts from log file
        
        Args:
            max_count: Maximum number of alerts to load
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        try:
            if os.path.exists(ALERT_LOG_FILE):
                with open(ALERT_LOG_FILE, 'r') as f:
                    for line in f:
                        try:
                            alert = json.loads(line.strip())
                            alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
                
                # Return most recent alerts
                if max_count:
                    alerts = alerts[-max_count:]
                
                logger.info(f"Loaded {len(alerts)} alerts from log file")
        
        except Exception as e:
            logger.error(f"Error loading alerts from log: {e}")
        
        return alerts

if __name__ == "__main__":
    print("AlertSystem module ready.")
