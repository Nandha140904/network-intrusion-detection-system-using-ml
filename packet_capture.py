"""
Real-time Packet Capture Module
Captures network traffic using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import time
from feature_extractor import FeatureExtractor
from utils import setup_logging
from config import NETWORK_INTERFACE, PACKET_BUFFER_SIZE, FLOW_TIMEOUT, CAPTURE_FILTER

logger = setup_logging(__name__)

class PacketCapture:
    """
    Captures and processes network packets in real-time
    """
    
    def __init__(self, interface=None, packet_callback=None):
        """
        Initialize PacketCapture
        
        Args:
            interface: Network interface to capture from
            packet_callback: Callback function for processed packets
        """
        self.interface = interface or NETWORK_INTERFACE
        self.packet_callback = packet_callback
        self.feature_extractor = FeatureExtractor()
        
        self.is_capturing = False
        self.packet_buffer = []
        self.packet_count = 0
        self.capture_thread = None
        
        logger.info(f"PacketCapture initialized on interface: {self.interface}")
    
    def start_capture(self, packet_count=0, timeout=None):
        """
        Start capturing packets
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds (None = no timeout)
        """
        logger.info(f"Starting packet capture on {self.interface}...")
        logger.info(f"Packet count: {packet_count if packet_count > 0 else 'infinite'}")
        logger.info(f"Timeout: {timeout if timeout else 'none'}")
        
        self.is_capturing = True
        
        try:
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=CAPTURE_FILTER,
                count=packet_count,
                timeout=timeout,
                store=False
            )
        except PermissionError:
            logger.error("Permission denied. Please run with administrator/root privileges.")
            raise
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            raise
        finally:
            self.is_capturing = False
            logger.info("Packet capture stopped")
    
    def start_capture_async(self, packet_count=0, timeout=None):
        """
        Start capturing packets in a separate thread
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds (None = no timeout)
        """
        if self.is_capturing:
            logger.warning("Capture already in progress")
            return
        
        self.capture_thread = threading.Thread(
            target=self.start_capture,
            args=(packet_count, timeout),
            daemon=True
        )
        self.capture_thread.start()
        logger.info("Packet capture started in background thread")
    
    def stop_capture(self):
        """
        Stop packet capture
        """
        logger.info("Stopping packet capture...")
        self.is_capturing = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
    
    def _process_packet(self, packet):
        """
        Process a captured packet
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_packet_features(packet)
            
            # Add to buffer
            self.packet_buffer.append(features)
            self.packet_count += 1
            
            # Process buffer when it reaches the size limit
            if len(self.packet_buffer) >= PACKET_BUFFER_SIZE:
                self._process_buffer()
            
            # Call callback if provided
            if self.packet_callback:
                self.packet_callback(features)
            
            # Log progress
            if self.packet_count % 100 == 0:
                logger.info(f"Captured {self.packet_count} packets")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_buffer(self):
        """
        Process the packet buffer and extract flow features
        """
        if not self.packet_buffer:
            return
        
        try:
            # Extract flow features from buffer
            flow_features = self.feature_extractor.extract_flow_features(
                self.packet_buffer,
                flow_timeout=FLOW_TIMEOUT
            )
            
            # Clear buffer
            self.packet_buffer = []
            
            return flow_features
        
        except Exception as e:
            logger.error(f"Error processing buffer: {e}")
            return None
    
    def get_flow_features(self):
        """
        Get flow features from current buffer
        
        Returns:
            Dictionary of flow features
        """
        return self._process_buffer()
    
    def get_packet_count(self):
        """
        Get total number of captured packets
        
        Returns:
            Packet count
        """
        return self.packet_count
    
    def reset(self):
        """
        Reset packet capture state
        """
        self.packet_buffer = []
        self.packet_count = 0
        logger.info("Packet capture state reset")

def list_interfaces():
    """
    List available network interfaces
    
    Returns:
        List of interface names
    """
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        
        print("\nAvailable Network Interfaces:")
        print("-" * 40)
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        print("-" * 40)
        
        return interfaces
    
    except Exception as e:
        logger.error(f"Error listing interfaces: {e}")
        return []

if __name__ == "__main__":
    print("PacketCapture module ready.")
    print("\nNote: Packet capture requires administrator/root privileges")
    print("\nListing available network interfaces...")
    list_interfaces()
