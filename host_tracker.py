
import json
import os
import time
from datetime import datetime
from collections import defaultdict
from utils import setup_logging
from config import KNOWN_HOSTS_FILE

logger = setup_logging(__name__)

class HostTracker:
    """
    Tracks known hosts (IP addresses) seen by the system.
    Persists data to a JSON file.
    """
    
    def __init__(self, storage_file=None):
        self.storage_file = storage_file or KNOWN_HOSTS_FILE
        self.hosts = {}  # Dictionary of IP -> host metrics
        self._load_hosts()
        
    def _load_hosts(self):
        """Load known hosts from storage file."""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    self.hosts = json.load(f)
                logger.info(f"Loaded {len(self.hosts)} known hosts.")
            else:
                self.hosts = {}
        except Exception as e:
            logger.error(f"Error loading known hosts: {e}")
            self.hosts = {}

    def save_hosts(self):
        """Save known hosts to storage file."""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(self.hosts, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving known hosts: {e}")

    def update_host(self, ip_address, packet_count=1, is_malicious=False):
        """
        Update tracking information for a host.
        
        Args:
            ip_address: Source IP address
            packet_count: Number of packets seen in this update
            is_malicious: Whether traffic was flagged as malicious
        """
        if not ip_address:
            return

        current_time = datetime.now().isoformat()
        
        if ip_address not in self.hosts:
            self.hosts[ip_address] = {
                'ip': ip_address,
                'first_seen': current_time,
                'last_seen': current_time,
                'packet_count': 0,
                'alert_count': 0,
                'status': 'neutral' # neutral, suspicious, malicious
            }
        
        host = self.hosts[ip_address]
        host['last_seen'] = current_time
        host['packet_count'] += packet_count
        
        if is_malicious:
            host['alert_count'] += 1
            host['status'] = 'malicious'
            
        # Save periodically could be an improvement, but for now we might rely on manual save or save on stop
        # Or save every N updates to avoid I/O bottleneck. 
        # For simplicity, let's not save on every packet, but provide a method to save.

    def get_all_hosts(self):
        """Return list of all known hosts."""
        return list(self.hosts.values())

    def get_host(self, ip_address):
        """Return details for a specific host."""
        return self.hosts.get(ip_address)
