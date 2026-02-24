"""
Real-time Detection Runner
Script to launch the real-time intrusion detection system
"""

import argparse
import sys
import os
import time
from intrusion_detector import IntrusionDetector
from utils import setup_logging
from config import NETWORK_INTERFACE

logger = setup_logging(__name__)

def run_realtime(interface=None, duration=None):
    """
    Run real-time detection
    """
    try:
        # Check for admin privileges
        if os.name == 'nt':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
            
        if not is_admin:
            logger.warning("="*60)
            logger.warning("WARNING: Not running with administrator/root privileges!")
            logger.warning("Packet capture may fail or be limited.")
            logger.warning("Please run this script as Administrator (Windows) or with sudo (Linux/macOS).")
            logger.warning("="*60)
            time.sleep(2) # Give user time to read
            
        # Initialize detector
        detector = IntrusionDetector(interface=interface)
        
        # Start monitoring
        detector.start_monitoring(duration=duration)
        
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as e:
        logger.error(f"Error running real-time detection: {e}")
        if "Permission" in str(e) or "Access denied" in str(e):
             logger.error("Please run as Administrator/root!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run real-time intrusion detection')
    parser.add_argument('--interface', type=str, default=NETWORK_INTERFACE, help='Network interface to monitor')
    parser.add_argument('--duration', type=int, default=None, help='Monitoring duration in seconds (default: infinite)')
    
    args = parser.parse_args()
    
    run_realtime(args.interface, args.duration)
