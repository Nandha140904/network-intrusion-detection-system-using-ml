
from scapy.all import get_if_list, sniff
import threading
import time

def check_interface(iface_name):
    print(f"Checking {iface_name}...", end='', flush=True)
    packets = sniff(iface=iface_name, count=5, timeout=2)
    if packets:
        print(f" ACTIVE ({len(packets)} packets captured)")
        return True
    else:
        print(" No traffic")
        return False

if __name__ == "__main__":
    print(" scanning for active interfaces...")
    interfaces = get_if_list()
    active_interfaces = []
    
    for iface in interfaces:
        try:
            if check_interface(iface):
                active_interfaces.append(iface)
        except Exception as e:
            print(f" Error: {e}")

    print("\nRecommended Interfaces:")
    for i, iface in enumerate(active_interfaces):
        print(f"{i+1}. {iface}")

    if not active_interfaces:
        print("\nNo active interfaces found. Make sure you are connected to a network.")
