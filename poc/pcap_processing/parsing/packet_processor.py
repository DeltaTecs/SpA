from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

# Add project root to sys.path to enable importing from util
sys.path.append(str(Path(__file__).resolve().parent.parent))

from util.ssl_decryptor import SSLKeylogDecryptor

try:
    from scapy.all import TCP, UDP
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")

def is_local_ip(ip_addr: str) -> bool:
    """
    Check if an IP address is local/private.
    
    Args:
        ip_addr (str): IP address string.
        
    Returns:
        bool: True if local/private, False otherwise.
    """
    if not ip_addr:
        return False
    try:
        ip = ipaddress.ip_address(ip_addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


class PacketProcessor:
    """Process packets from PCAP and extract relevant information."""
    
    def __init__(self, tshark_path: str, keylog_file: Optional[str] = None):
        """
        Initialize the PacketProcessor.

        Args:
            tshark_path (str): Path to the tshark executable.
            keylog_file (Optional[str]): Path to the SSLKEYLOGFILE for decryption.
        """
        self.decryptor = SSLKeylogDecryptor(tshark_path, keylog_file)
        self.conversations = {}  # (proto, src_ip, src_port, dst_ip, dst_port) -> conversation_id
        self.packet_payload_map = {}  # packet_id -> decrypted_payload
        self.next_conversation_id = 1
    
    def get_or_create_conversation_id(self, proto: str, src_ip: str, src_port: int,
                                      dst_ip: str, dst_port: int) -> int:
        """
        Get or create a conversation ID for a flow.

        Args:
            proto (str): Protocol name (e.g., 'TCP', 'UDP').
            src_ip (str): Source IP address.
            src_port (int): Source port.
            dst_ip (str): Destination IP address.
            dst_port (int): Destination port.

        Returns:
            int: The conversation ID.
        """
        # Normalize flow to bidirectional
        pair1 = (src_ip, src_port)
        pair2 = (dst_ip, dst_port)
        if pair1 > pair2:
            pair1, pair2 = pair2, pair1
        
        key = (proto, pair1[0], pair1[1], pair2[0], pair2[1])
        if key not in self.conversations:
            self.conversations[key] = self.next_conversation_id
            self.next_conversation_id += 1
        
        return self.conversations[key]
    
    def _add_application_protocols(self, info: Dict, tshark_protos: Set[str]):
        """Add application layer protocols to info based on tshark protocols."""
        if 'icmp' in tshark_protos or 'icmpv6' in tshark_protos:
            info['protocols'].append('ICMP')

        if 'dns' in tshark_protos:
            info['protocols'].append('DNS')
        
        if 'quic' in tshark_protos:
            info['protocols'].append('QUIC')
                    
        if 'tls' in tshark_protos:
            info['protocols'].append('TLS')

        if 'dtls' in tshark_protos:
            info['protocols'].append('DTLS')

        if 'stun' in tshark_protos:
            info['protocols'].append('STUN')

        if 'turn' in tshark_protos:
            info['protocols'].append('TURN')
        
        if any(p in tshark_protos for p in ['http', 'http2', 'http3']):
            info['protocols'].append('HTTP')

        if 'websocket' in tshark_protos:
            info['protocols'].append('Websocket')

    def extract_packet_info(self, pkt, pkt_number: int, 
                           timestamp: float) -> Optional[Dict]:
        """
        Extract basic packet information: Protocol stack, frame number, timestamp, 
        
        Args:
            pkt: The Scapy packet object.
            pkt_number (int): The packet number in the capture.
            timestamp (float): The timestamp of the packet.

        Returns:
            Optional[Dict]: A dictionary containing packet metadata, or None if not processable.
        """
        stack_info = self.decryptor.get_packet_stack(pkt_number)
        if not stack_info:
            return None

        # Extract transport payload for raw_bytes
        raw_bytes = b""
        if pkt.haslayer(TCP):
            raw_bytes = bytes(pkt[TCP].payload)
        elif pkt.haslayer(UDP):
            raw_bytes = bytes(pkt[UDP].payload)

        info = {
            'number': pkt_number,
            'timestamp': int(timestamp * 1000),  # Convert to milliseconds
            'raw_bytes': raw_bytes, # transport protocol payload bytes f.e. TCP payload
            'protocols': [],
            'conversation_id': None,
            'from_local': None,
            'headers': [] # transport headers only (IP, TCP/UDP)
        }
        
        tshark_protos = set(stack_info.get('protocols', []))
        
        # Extract IP layer
        src_ip = stack_info.get('ip_src')
        dst_ip = stack_info.get('ip_dst')
        ip_version = stack_info.get('ip_version')
        
        if ip_version:
            info['protocols'].append(ip_version)
            info['from_local'] = is_local_ip(src_ip)
            info['headers'].append({
                'type': 'ip',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'version': ip_version
            })
        
        # Extract transport layer
        src_port = stack_info.get('src_port')
        dst_port = stack_info.get('dst_port')
        
        if 'tcp' in tshark_protos:
            info['protocols'].append('TCP')
            
            if src_ip and src_port is not None:
                conv_id = self.get_or_create_conversation_id('TCP', src_ip, src_port,
                                                             dst_ip, dst_port)
                info['conversation_id'] = conv_id
            
            info['headers'].append({
                'type': 'tcp',
                'src_port': src_port,
                'dst_port': dst_port,
                'length': stack_info.get('tcp_len', 0)
            })
        
        elif 'udp' in tshark_protos:
            info['protocols'].append('UDP')
            
            if src_ip and src_port is not None:
                conv_id = self.get_or_create_conversation_id('UDP', src_ip, src_port,
                                                             dst_ip, dst_port)
                info['conversation_id'] = conv_id
            
            info['headers'].append({
                'type': 'udp',
                'src_port': src_port,
                'dst_port': dst_port,
                'length': stack_info.get('udp_len', 0)
            })
        
        self._add_application_protocols(info, tshark_protos)
                
        return info if info['protocols'] else None
    
    def get_protocol_ids_for_names(self, conn, protocol_names: List[str]) -> List[int]:
        """
        Get protocol IDs from names.

        Args:
            conn: The database connection object.
            protocol_names (List[str]): List of protocol names.

        Returns:
            List[int]: List of corresponding protocol IDs.
        """
        if not protocol_names:
            return []
        
        protocol_ids = []
        cursor = conn.cursor()
        
        try:
            placeholders = ','.join(['%s'] * len(protocol_names))
            cursor.execute(
                f"SELECT protocol_id, name FROM protocol WHERE name IN ({placeholders})",
                protocol_names
            )
            result_map = {row[1]: row[0] for row in cursor.fetchall()}
            protocol_ids = [result_map[name] for name in protocol_names if name in result_map]
        finally:
            cursor.close()
        
        return protocol_ids
