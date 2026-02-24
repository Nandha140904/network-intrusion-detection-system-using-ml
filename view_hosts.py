
import json
import os
import sys
from config import KNOWN_HOSTS_FILE

def view_hosts():
    """
    Read and display known hosts from the JSON file.
    """
    if not os.path.exists(KNOWN_HOSTS_FILE):
        print(f"\nNo known hosts file found at: {KNOWN_HOSTS_FILE}")
        print("Run the intrusion detector (app.py) first to generate data.")
        return

    try:
        with open(KNOWN_HOSTS_FILE, 'r') as f:
            hosts = json.load(f)
        
        if not hosts:
            print("\nKnown hosts file is empty.")
            return

        print("\n" + "="*100)
        print(f"{'IP ADDRESS':<20} {'STATUS':<15} {'PACKETS':<10} {'ALERTS':<10} {'LAST SEEN':<30}")
        print("="*100)
        
        # Sort by last seen (descending)
        sorted_hosts = sorted(hosts.values(), key=lambda x: x.get('last_seen', ''), reverse=True)
        
        for host in sorted_hosts:
            ip = host.get('ip', 'Unknown')
            status = host.get('status', 'neutral').upper()
            packets = host.get('packet_count', 0)
            alerts = host.get('alert_count', 0)
            last_seen = host.get('last_seen', 'Unknown')
            
            # Simple color coding for terminal (if supported, otherwise just text)
            row = f"{ip:<20} {status:<15} {packets:<10} {alerts:<10} {last_seen:<30}"
            print(row)
            
        print("="*100)
        print(f"Total Hosts: {len(hosts)}")
        print("\n")
        
    except Exception as e:
        print(f"Error reading known hosts file: {e}")

if __name__ == "__main__":
    view_hosts()
