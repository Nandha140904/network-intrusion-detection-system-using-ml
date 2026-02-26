"""
Feature Extraction from Network Packets
Extracts meaningful features from network traffic for ML classification
"""

import numpy as np
from collections import defaultdict
from datetime import datetime
from utils import setup_logging

logger = setup_logging(__name__)

class FeatureExtractor:
    """
    Extracts features from network packets for intrusion detection
    """
    
    def __init__(self):
        """
        Initialize FeatureExtractor
        """
        self.flow_cache = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'last_time': None,
            'src_bytes': 0,
            'dst_bytes': 0,
            'packet_count': 0
        })
        
        logger.info("FeatureExtractor initialized")
    
    def extract_packet_features(self, packet):
        """
        Extract features from a single packet
        
        Args:
            packet: Scapy packet object
        
        Returns:
            Dictionary of features
        """
        features = {}
        
        try:
            # Basic packet information
            features['packet_length'] = len(packet)
            features['timestamp'] = float(packet.time) if hasattr(packet, 'time') else 0.0
            
            # Protocol information
            if packet.haslayer('IP'):
                ip_layer = packet['IP']
                features['src_ip'] = ip_layer.src
                features['dst_ip'] = ip_layer.dst
                features['protocol'] = ip_layer.proto
                features['ttl'] = ip_layer.ttl
                features['ip_len'] = ip_layer.len
            else:
                features['src_ip'] = None
                features['dst_ip'] = None
                features['protocol'] = 0
                features['ttl'] = 0
                features['ip_len'] = 0
            
            # TCP features
            if packet.haslayer('TCP'):
                tcp_layer = packet['TCP']
                features['src_port'] = tcp_layer.sport
                features['dst_port'] = tcp_layer.dport
                features['tcp_flags'] = int(tcp_layer.flags)
                features['tcp_window'] = tcp_layer.window
                features['tcp_seq'] = tcp_layer.seq
                features['tcp_ack'] = tcp_layer.ack
                features['protocol_type'] = 'tcp'
            
            # UDP features
            elif packet.haslayer('UDP'):
                udp_layer = packet['UDP']
                features['src_port'] = udp_layer.sport
                features['dst_port'] = udp_layer.dport
                features['tcp_flags'] = 0
                features['tcp_window'] = 0
                features['tcp_seq'] = 0
                features['tcp_ack'] = 0
                features['protocol_type'] = 'udp'
            
            # ICMP features
            elif packet.haslayer('ICMP'):
                features['src_port'] = 0
                features['dst_port'] = 0
                features['tcp_flags'] = 0
                features['tcp_window'] = 0
                features['tcp_seq'] = 0
                features['tcp_ack'] = 0
                features['protocol_type'] = 'icmp'
            
            else:
                features['src_port'] = 0
                features['dst_port'] = 0
                features['tcp_flags'] = 0
                features['tcp_window'] = 0
                features['tcp_seq'] = 0
                features['tcp_ack'] = 0
                features['protocol_type'] = 'other'
            
            # Payload information
            if packet.haslayer('Raw'):
                features['payload_length'] = len(packet['Raw'].load)
            else:
                features['payload_length'] = 0
            
        except Exception as e:
            logger.error(f"Error extracting packet features: {e}")
            features = self._get_default_features()
        
        return features
    
    def extract_flow_features(self, packets, flow_timeout=60):
        """
        Extract flow-based features from a sequence of packets
        compatible with NSL-KDD 41-feature format.
        """
        if not packets:
            return self._get_default_nsl_kdd_features()

        features = {}

        try:
            # Duration
            if len(packets) > 1:
                duration = packets[-1]['timestamp'] - packets[0]['timestamp']
            else:
                duration = 0
            features['duration'] = max(0, duration)

            # IPs
            src_ip, dst_ip = None, None
            for p in packets:
                if not src_ip and p.get('src_ip') and p.get('src_ip') not in (None, 'unknown', ''):
                    src_ip = p.get('src_ip')
                if not dst_ip and p.get('dst_ip') and p.get('dst_ip') not in (None, 'unknown', ''):
                    dst_ip = p.get('dst_ip')
                if src_ip and dst_ip:
                    break
            features['src_ip'] = src_ip or 'unknown'
            features['dst_ip'] = dst_ip or 'unknown'

            # Protocol type (most common)
            protocol_types = [p.get('protocol_type', 'other') for p in packets]
            features['protocol_type'] = max(set(protocol_types), key=protocol_types.count)

            # Service (based on destination port)
            dst_ports = [p.get('dst_port', 0) for p in packets if p.get('dst_port', 0) > 0]
            src_ports = [p.get('src_port', 0) for p in packets if p.get('src_port', 0) > 0]
            if dst_ports:
                common_port = max(set(dst_ports), key=dst_ports.count)
                features['service'] = self._port_to_service(common_port)
            else:
                features['service'] = 'other'

            # Flag: use TCP flags to determine connection state
            tcp_flags_list = [p.get('tcp_flags', 0) for p in packets]
            syn_count  = sum(1 for f in tcp_flags_list if f & 0x02)   # SYN
            rst_count  = sum(1 for f in tcp_flags_list if f & 0x04)   # RST
            fin_count  = sum(1 for f in tcp_flags_list if f & 0x01)   # FIN
            ack_count  = sum(1 for f in tcp_flags_list if f & 0x10)   # ACK
            n = len(packets)
            if rst_count > 0 and ack_count == 0:
                features['flag'] = 'REJ'
            elif syn_count > 0 and rst_count > 0:
                features['flag'] = 'RSTO'
            elif fin_count > 0 and ack_count > 0:
                features['flag'] = 'SF'
            else:
                features['flag'] = 'S0' if syn_count > 0 else 'SF'

            # Bytes transferred
            features['src_bytes'] = sum(p.get('packet_length', 0) for p in packets)
            features['dst_bytes'] = 0

            # Binary features
            features['land'] = 0
            features['wrong_fragment'] = 0
            features['urgent'] = sum(1 for p in packets if p.get('tcp_flags', 0) & 0x20)

            # Content features (can't be computed from raw packets without deep inspection)
            features['hot'] = 0
            features['num_failed_logins'] = 0
            features['logged_in'] = 1 if features['service'] in ('http', 'ftp', 'ssh', 'telnet') else 0
            features['num_compromised'] = 0
            features['root_shell'] = 0
            features['su_attempted'] = 0
            features['num_root'] = 0
            features['num_file_creations'] = 0
            features['num_shells'] = 0
            features['num_access_files'] = 0
            features['num_outbound_cmds'] = 0
            features['is_host_login'] = 0
            features['is_guest_login'] = 0

            # Traffic statistical features (key for attack detection)
            features['count'] = n
            features['srv_count'] = n

            # SYN error rate: proportion of connections with SYN but no response
            serror_rate = syn_count / n if n > 0 else 0.0
            rst_rate    = rst_count / n if n > 0 else 0.0
            features['serror_rate']      = round(serror_rate, 4)
            features['srv_serror_rate']  = round(serror_rate, 4)
            features['rerror_rate']      = round(rst_rate, 4)
            features['srv_rerror_rate']  = round(rst_rate, 4)

            # Service diversity
            unique_dst_ports = len(set(dst_ports)) if dst_ports else 1
            unique_src_ports = len(set(src_ports)) if src_ports else 1
            same_srv_rate = 1.0 - min(unique_dst_ports / max(n, 1), 1.0)
            diff_srv_rate = min(unique_dst_ports / max(n, 1), 1.0)
            features['same_srv_rate']    = round(same_srv_rate, 4)
            features['diff_srv_rate']    = round(diff_srv_rate, 4)
            features['srv_diff_host_rate'] = round(unique_src_ports / max(n, 1), 4)

            # Host-based features
            features['dst_host_count']               = min(n * 2, 255)
            features['dst_host_srv_count']           = min(n, 255)
            features['dst_host_same_srv_rate']       = round(same_srv_rate, 4)
            features['dst_host_diff_srv_rate']       = round(diff_srv_rate, 4)
            features['dst_host_same_src_port_rate']  = round(1.0 - diff_srv_rate, 4)
            features['dst_host_srv_diff_host_rate']  = round(unique_src_ports / max(n, 1), 4)
            features['dst_host_serror_rate']         = round(serror_rate, 4)
            features['dst_host_srv_serror_rate']     = round(serror_rate, 4)
            features['dst_host_rerror_rate']         = round(rst_rate, 4)
            features['dst_host_srv_rerror_rate']     = round(rst_rate, 4)

        except Exception as e:
            logger.error(f"Error extracting flow features: {e}")
            features = self._get_default_nsl_kdd_features()

        return features
    
    def _port_to_service(self, port):
        """
        Map port number to service name
        
        Args:
            port: Port number
        
        Returns:
            Service name
        """
        service_map = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 3306: 'mysql', 5432: 'postgresql',
            6379: 'redis', 27017: 'mongodb'
        }
        return service_map.get(port, 'other')
    
    def _get_default_features(self):
        """
        Get default packet features
        
        Returns:
            Dictionary of default features
        """
        return {
            'packet_length': 0,
            'timestamp': 0.0,
            'src_ip': None,
            'dst_ip': None,
            'protocol': 0,
            'ttl': 0,
            'ip_len': 0,
            'src_port': 0,
            'dst_port': 0,
            'tcp_flags': 0,
            'tcp_window': 0,
            'tcp_seq': 0,
            'tcp_ack': 0,
            'protocol_type': 'other',
            'payload_length': 0
        }
    
    def _get_default_nsl_kdd_features(self):
        """
        Get default NSL-KDD features
        
        Returns:
            Dictionary of default NSL-KDD features
        """
        return {
            'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
            'src_bytes': 0, 'dst_bytes': 0, 'land': 0, 'wrong_fragment': 0,
            'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
            'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
            'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
            'count': 1, 'srv_count': 1, 'serror_rate': 0.0, 'srv_serror_rate': 0.0,
            'rerror_rate': 0.0, 'srv_rerror_rate': 0.0, 'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0, 'dst_host_count': 1,
            'dst_host_srv_count': 1, 'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0, 'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0.0, 'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0, 'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

if __name__ == "__main__":
    print("FeatureExtractor module ready.")
