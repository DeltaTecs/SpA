#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcap_to_db.py

Read a PCAP file and populate a PostgreSQL database with:
- Recording metadata
- Packets with decrypted payloads
- Conversation grouping
- Header information for TCP/UDP/HTTP

Supports TLS/QUIC decryption using an SSLKEYLOGFILE.

Usage:
    python pcap_to_db.py -i recording.pcap -n "Recording Name" \
        --db-host localhost --db-port 5432 --db-name main \
        --db-user dbuser --db-password dbuser \
        [--sslkeylog keylog.txt]

"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import struct
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Add project root to sys.path to enable importing from util
sys.path.append(str(Path(__file__).resolve().parent.parent))

from util.ssl_decryptor import SSLKeylogDecryptor
from packet_processor import PacketProcessor

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from psycopg2.extras import execute_values
except ImportError:
    raise ImportError("psycopg2-binary is required. Install with: pip install psycopg2-binary")

try:
    from scapy.all import (
        PcapReader, TCP, UDP, IP, IPv6, Raw, ICMP, DNS
    )
    # Suppress Scapy warnings about unknown cipher suites
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")


## TODO replace with tshark and make sure tshark is in path
PATH_TO_TSHARK = "tshark"



# Optional/extension layers — import if available, otherwise fall back to None.
TLS = None
QUIC = None
HTTP = None
try:
    # TLS support may live in scapy.layers.tls
    try:
        from scapy.layers.tls.all import TLS as _TLS  # newer layout
    except Exception:
        from scapy.layers.tls import TLS as _TLS  # older layout
    TLS = _TLS
except Exception:
    TLS = None

try:
    from scapy.layers.quic import QUIC as _QUIC
    QUIC = _QUIC
except Exception:
    QUIC = None

try:
    # scapy.http exposes HTTPRequest/HTTPResponse; we keep a generic HTTP marker if present
    from scapy.layers.http import HTTP as _HTTP
    HTTP = _HTTP
except Exception:
    # HTTP layer may not provide a single `HTTP` symbol; leave as None if not present
    HTTP = None



# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)




class DatabaseManager:
    """Manage database connections and operations."""
    
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        """
        Initialize the DatabaseManager.

        Args:
            host (str): Database host.
            port (int): Database port.
            database (str): Database name.
            user (str): Database user.
            password (str): Database password.
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.conn = None
    
    def connect(self):
        """
        Establish database connection.

        Raises:
            psycopg2.Error: If connection fails.
        """
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            logger.info(f"Connected to database {self.database} on {self.host}:{self.port}")
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def disconnect(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Disconnected from database")
    
    def create_recording(self, name: str) -> int:
        """
        Create a new recording and return its ID.

        Args:
            name (str): Name of the recording.

        Returns:
            int: The ID of the created recording.
        """
        cursor = self.conn.cursor()
        try:
            timestamp = int(time.time() * 1000)  # milliseconds
            cursor.execute(
                "INSERT INTO recording (name, timestamp) VALUES (%s, %s) RETURNING recording_id",
                (name, timestamp)
            )
            recording_id = cursor.fetchone()[0]
            self.conn.commit()
            logger.info(f"Created recording {recording_id}: {name}")
            return recording_id
        finally:
            cursor.close()
    
    def create_conversation(self) -> int:
        """
        Create a new conversation and return its ID.

        Returns:
            int: The ID of the created conversation.
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute("INSERT INTO conversation DEFAULT VALUES RETURNING conversation_id")
            conversation_id = cursor.fetchone()[0]
            self.conn.commit()
            return conversation_id
        finally:
            cursor.close()
    
    def insert_packet(self, recording_id: int, conversation_id: Optional[int],
                     timestamp: int, packet_number: int, protocol_ids: List[int],
                     packet_bytes: bytes, clear_payload: Optional[bytes] = None,
                     from_local: Optional[bool] = None) -> int:
        """
        Insert packet into database and return packet_id.

        Args:
            recording_id (int): ID of the recording.
            conversation_id (Optional[int]): ID of the conversation.
            timestamp (int): Timestamp of the packet in milliseconds.
            packet_number (int): Packet number in the capture.
            protocol_ids (List[int]): List of protocol IDs associated with the packet.
            packet_bytes (bytes): Raw packet bytes.
            clear_payload (Optional[bytes]): Decrypted payload bytes.
            from_local (Optional[bool]): Whether the packet is from a local IP.

        Returns:
            int: The ID of the inserted packet.
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO packet 
                   (recording_id, conversation_id, timestamp, number, protocol_ids, 
                    packet_bytes, clear_application_payload, from_local)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING packet_id""",
                (recording_id, conversation_id, timestamp, packet_number,
                 protocol_ids, packet_bytes, clear_payload, from_local)
            )
            packet_id = cursor.fetchone()[0]
            self.conn.commit()
            return packet_id
        finally:
            cursor.close()

    def insert_packets_batch(self, packets_data: List[Tuple]) -> List[int]:
        """
        Insert multiple packets into database and return their IDs.
        
        Args:
            packets_data: List of tuples matching the arguments of insert_packet
                          (recording_id, conversation_id, timestamp, packet_number, 
                           protocol_ids, packet_bytes, clear_payload, from_local)
        
        Returns:
            List[int]: List of inserted packet IDs.
        """
        if not packets_data:
            return []
            
        cursor = self.conn.cursor()
        try:
            packet_ids = execute_values(
                cursor,
                """INSERT INTO packet 
                   (recording_id, conversation_id, timestamp, number, protocol_ids, 
                    packet_bytes, clear_application_payload, from_local)
                   VALUES %s
                   RETURNING packet_id""",
                packets_data,
                fetch=True
            )
            self.conn.commit()
            return [row[0] for row in packet_ids]
        finally:
            cursor.close()

    def insert_packet_header_links_batch(self, links: List[Tuple[int, int]]):
        """
        Insert multiple packet-header links.
        
        Args:
            links: List of (packet_id, header_information_id) tuples.
        """
        if not links:
            return

        cursor = self.conn.cursor()
        try:
            execute_values(
                cursor,
                """INSERT INTO packet_header_information 
                   (packet_id, header_information_id)
                   VALUES %s""",
                links
            )
            self.conn.commit()
        finally:
            cursor.close()

    def insert_headers_batch(self, headers_data: List[Dict]) -> List[int]:
        """
        Insert multiple headers and return their IDs.
        
        Args:
            headers_data: List of dicts containing:
                - protocol_id: int
                - type: str ('tcp', 'udp', 'http', 'ip')
                - fields: dict of specific fields
        
        Returns:
            List[int]: List of inserted header_information_ids.
        """
        if not headers_data:
            return []
            
        cursor = self.conn.cursor()
        try:
            # 1. Insert into parent table
            protocol_ids = [(h['protocol_id'],) for h in headers_data]
            header_ids_rows = execute_values(
                cursor,
                "INSERT INTO header_information (protocol_id) VALUES %s RETURNING header_information_id",
                protocol_ids,
                fetch=True
            )
            header_ids = [row[0] for row in header_ids_rows]
            
            # 2. Prepare child table inserts
            tcp_data = []
            udp_data = []
            http_data = []
            ip_data = []
            
            for h_id, h_data in zip(header_ids, headers_data):
                h_type = h_data['type']
                fields = h_data['fields']
                
                if h_type == 'tcp':
                    tcp_data.append((h_id, fields.get('src_port'), fields.get('dst_port'), fields.get('length')))
                elif h_type == 'udp':
                    udp_data.append((h_id, fields.get('src_port'), fields.get('dst_port'), fields.get('length')))
                elif h_type == 'http':
                    http_data.append((h_id, fields.get('text_header'), fields.get('stream_id'), fields.get('version')))
                elif h_type == 'ip':
                    ip_data.append((h_id, fields.get('src_ip'), fields.get('dst_ip')))
            
            # 3. Execute child table inserts
            if tcp_data:
                execute_values(
                    cursor,
                    """INSERT INTO tcp_header_information (header_information_id, src_port, dst_port, length) VALUES %s""",
                    tcp_data
                )
            if udp_data:
                execute_values(
                    cursor,
                    """INSERT INTO udp_header_information (header_information_id, src_port, dst_port, length) VALUES %s""",
                    udp_data
                )
            if http_data:
                execute_values(
                    cursor,
                    """INSERT INTO http_header_information (header_information_id, text_header, stream_id, version) VALUES %s""",
                    http_data
                )
            if ip_data:
                execute_values(
                    cursor,
                    """INSERT INTO ip_header_information (header_information_id, src_addr, dst_addr) VALUES %s""",
                    ip_data
                )
                
            self.conn.commit()
            return header_ids
        finally:
            cursor.close()

    
    def insert_header_information(self, protocol_id: int, header_type: str,
                                 packet_id: int, **header_fields) -> int:
        """
        Insert header information and link to packet.

        Args:
            protocol_id (int): ID of the protocol.
            header_type (str): Type of header ('tcp', 'udp', 'http', 'ip').
            packet_id (int): ID of the packet.
            **header_fields: Additional header fields (e.g., src_port, dst_port, length, text_header, src_ip, dst_ip).

        Returns:
            int: The ID of the inserted header information.
        """
        cursor = self.conn.cursor()
        try:
            # Insert into parent table
            cursor.execute(
                "INSERT INTO header_information (protocol_id) VALUES (%s) RETURNING header_information_id",
                (protocol_id,)
            )
            header_info_id = cursor.fetchone()[0]
            
            # Insert into child table based on type
            if header_type == 'tcp':
                cursor.execute(
                    """INSERT INTO tcp_header_information 
                       (header_information_id, src_port, dst_port, length)
                       VALUES (%s, %s, %s, %s)""",
                    (header_info_id, header_fields.get('src_port'),
                     header_fields.get('dst_port'), header_fields.get('length'))
                )
            elif header_type == 'udp':
                cursor.execute(
                    """INSERT INTO udp_header_information 
                       (header_information_id, src_port, dst_port, length)
                       VALUES (%s, %s, %s, %s)""",
                    (header_info_id, header_fields.get('src_port'),
                     header_fields.get('dst_port'), header_fields.get('length'))
                )
            elif header_type == 'http':
                cursor.execute(
                    """INSERT INTO http_header_information 
                       (header_information_id, text_header, stream_id, version)
                       VALUES (%s, %s, %s, %s)""",
                    (header_info_id, header_fields.get('text_header'), header_fields.get('stream_id'), header_fields.get('version'))
                )
            elif header_type == 'ip':
                cursor.execute(
                    """INSERT INTO ip_header_information 
                       (header_information_id, src_addr, dst_addr)
                       VALUES (%s, %s, %s)""",
                    (header_info_id, header_fields.get('src_ip'), header_fields.get('dst_ip'))
                )
            
            # Link to packet
            cursor.execute(
                """INSERT INTO packet_header_information 
                   (packet_id, header_information_id)
                   VALUES (%s, %s)""",
                (packet_id, header_info_id)
            )
            
            self.conn.commit()
            return header_info_id
        finally:
            cursor.close()

    def link_packet_to_header(self, packet_id: int, header_information_id: int):
        """
        Link an existing header information to a packet.

        Args:
            packet_id (int): ID of the packet.
            header_information_id (int): ID of the header information.
        """
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """INSERT INTO packet_header_information 
                   (packet_id, header_information_id)
                   VALUES (%s, %s)""",
                (packet_id, header_information_id)
            )
            self.conn.commit()
        finally:
            cursor.close()


def process_pcap_to_db(pcap_file: str, recording_name: str, db_manager: DatabaseManager,
                      keylog_file: Optional[str] = None, batch_size: int = 2000,
                      parse_segments: bool = False):
    """
    Read PCAP file and populate database.

    Args:
        pcap_file (str): Path to the PCAP file.
        recording_name (str): Name of the recording.
        db_manager (DatabaseManager): Database manager instance.
        keylog_file (Optional[str]): Path to the SSLKEYLOGFILE for decryption.
        batch_size (int): Number of packets to process before inserting into DB.
        parse_segments (bool): Prefer tls.segment.data over tls.reassembled.data when available.
    """
    if not os.path.exists(pcap_file):
        logger.error(f"PCAP file not found: {pcap_file}")
        return
    
    logger.info(f"Processing PCAP file: {pcap_file}")
    processor = PacketProcessor(PATH_TO_TSHARK, keylog_file, parse_segments=parse_segments)
    
    # Analyze PCAP with tshark (extracts stack info and decrypts if keylog provided)
    if processor.decryptor.can_process():
        logger.info("Analyzing PCAP with tshark...")
        processor.decryptor.decrypted_payloads = processor.decryptor.decrypt_pcap(pcap_file)
    
    # Create recording
    recording_id = db_manager.create_recording(recording_name)
    
    # Get protocol IDs mapping
    cursor = db_manager.conn.cursor()
    cursor.execute("SELECT protocol_id, name FROM protocol")
    protocol_map = {row[1]: row[0] for row in cursor.fetchall()}
    cursor.close()
    
    packet_count = 0
    skipped_count = 0
    # Map from processor conversation_id -> DB conversation_id
    conv_map = {}
    
    # Cache for HTTP header information
    # Key: (src_ip, src_port, dst_ip, dst_port, stream_id)
    # Value: header_information_id
    http_header_cache = {}
    
    # Batch buffers
    batch_packets = [] 
    batch_cached_header_links = [] 
    batch_packet_pending_indices = [] 
    batch_new_headers = [] 
    pending_headers_map = {} 
    
    def flush_batch():
        nonlocal batch_packets, batch_cached_header_links, batch_packet_pending_indices
        nonlocal batch_new_headers, pending_headers_map
        
        if not batch_packets:
            return

        # 1. Insert packets
        packet_ids = db_manager.insert_packets_batch(batch_packets)
        
        # 2. Insert new headers
        new_header_ids = db_manager.insert_headers_batch(batch_new_headers)
        
        # 3. Update cache
        for key, idx in pending_headers_map.items():
            if idx < len(new_header_ids):
                http_header_cache[key] = new_header_ids[idx]
                
        # 4. Prepare links
        all_links = []
        for i, pid in enumerate(packet_ids):
            # Cached links
            for hid in batch_cached_header_links[i]:
                all_links.append((pid, hid))
            
            # New header links
            for idx in batch_packet_pending_indices[i]:
                if idx < len(new_header_ids):
                    all_links.append((pid, new_header_ids[idx]))
                    
        # 5. Insert links
        db_manager.insert_packet_header_links_batch(all_links)
        
        # 6. Clear buffers
        batch_packets.clear()
        batch_cached_header_links.clear()
        batch_packet_pending_indices.clear()
        batch_new_headers.clear()
        pending_headers_map.clear()

    try:
        with PcapReader(pcap_file) as reader:
            for pkt_number, pkt in enumerate(reader, 1):
                try:
                    timestamp = pkt.time
                    
                    # Extract packet info
                    pkt_info = processor.extract_packet_info(pkt, pkt_number, timestamp)
                    
                    if not pkt_info:
                        skipped_count += 1
                        logger.debug(f"skipping packet {pkt_number}")
                        continue
                    
                    # Map processor conversation ID to an actual DB conversation_id
                    conv_id = None
                    if pkt_info['conversation_id']:
                        proc_conv_id = pkt_info['conversation_id']
                        if proc_conv_id in conv_map:
                            conv_id = conv_map[proc_conv_id]
                        else:
                            # Create a DB conversation and remember mapping
                            db_conv_id = db_manager.create_conversation()
                            conv_map[proc_conv_id] = db_conv_id
                            conv_id = db_conv_id
                    
                    # Get protocol IDs
                    protocol_ids = [protocol_map.get(proto, 0) for proto in pkt_info['protocols']]
                    protocol_ids = [pid for pid in protocol_ids if pid > 0]
                    
                    # Extract 5-tuple for cache key
                    src_ip, dst_ip = None, None
                    src_port, dst_port = None, None
                    
                    for h in pkt_info['headers']:
                        if h['type'] == 'ip':
                            src_ip = h['src_ip']
                            dst_ip = h['dst_ip']
                        elif h['type'] in ['tcp', 'udp']:
                            src_port = h['src_port']
                            dst_port = h['dst_port']

                    # Check if we have decrypted payload for this packet
                    decrypted_data_list = processor.decryptor.get_decrypted_payload(pkt_number)
                    
                    if not decrypted_data_list:
                        decrypted_data_list = [{
                            'header': None,
                            'payload': None,
                            'protocol': None,
                            'stream_id': None,
                            'version': None
                        }]
                    
                    for decrypted_data in decrypted_data_list:
                        clear_payload = None
                        header = decrypted_data.get('header')
                        payload = decrypted_data.get('payload')
                        protocol = decrypted_data.get('protocol')
                        stream_id = decrypted_data.get('stream_id')
                        version = decrypted_data.get('version')
                        
                        current_protocol_ids = list(protocol_ids)
                        current_headers = list(pkt_info['headers'])

                        if payload:
                            clear_payload = payload

                        # Update protocol IDs based on decrypted protocol
                        if protocol:
                            # Try to match protocol name (case-insensitive)
                            pid = 0
                            for pname, p_id in protocol_map.items():
                                if pname.lower() == protocol.lower():
                                    pid = p_id
                                    break
                            
                            if pid and pid not in current_protocol_ids:
                                current_protocol_ids.append(pid)
                        
                        # If HTTP, add header info
                        cached_header_id = None
                        should_create_header = False
                        cache_key = None
                        
                        if protocol in ['http', 'http3']:
                            text_header = None
                            if header:
                                try:
                                    text_header = header.decode('utf-8', errors='replace')
                                except Exception:
                                    pass
                            
                            if text_header:
                                # Has text header -> Create new header entry
                                should_create_header = True
                                # HTTP/1 check
                                if stream_id is None:
                                    first_line = text_header.split('\r\n')[0]
                                    if "HTTP/1" not in first_line:
                                        should_create_header = False
                                
                                if stream_id is not None and src_ip and dst_ip and src_port and dst_port:
                                     cache_key = (src_ip, src_port, dst_ip, dst_port, stream_id)
                            
                            elif stream_id is not None:
                                # No text header, but has stream_id.
                                # Check cache.
                                if src_ip and dst_ip and src_port and dst_port:
                                    cache_key = (src_ip, src_port, dst_ip, dst_port, stream_id)
                                    if cache_key in http_header_cache:
                                        cached_header_id = http_header_cache[cache_key]
                                    else:
                                        # Not in cache -> Create new header entry (placeholder/control)
                                        should_create_header = True
                            
                            elif stream_id is None:
                                # No text header, no stream_id (HTTP/1 data).
                                # Check cache.
                                if src_ip and dst_ip and src_port and dst_port:
                                    cache_key = (src_ip, src_port, dst_ip, dst_port, None)
                                    if cache_key in http_header_cache:
                                        cached_header_id = http_header_cache[cache_key]

                            if should_create_header:
                                current_headers.append({
                                    'type': 'http',
                                    'text_header': text_header,
                                    'stream_id': stream_id,
                                    'version': version,
                                    'cache_key': cache_key
                                })
                                
                        # Prepare packet data
                        batch_packets.append((
                            recording_id,
                            conv_id,
                            pkt_info['timestamp'],
                            pkt_info['number'],
                            current_protocol_ids,
                            pkt_info['raw_bytes'],
                            clear_payload,
                            pkt_info.get('from_local')
                        ))
                        
                        # Prepare header links
                        current_cached_links = []
                        current_pending_indices = []
                        
                        if cached_header_id:
                            current_cached_links.append(cached_header_id)
                            
                        # Process headers to create
                        for header_info in current_headers:
                            # Check if this header is already pending creation in this batch (for HTTP cache)
                            h_cache_key = header_info.get('cache_key')
                            if h_cache_key and h_cache_key in pending_headers_map:
                                current_pending_indices.append(pending_headers_map[h_cache_key])
                                continue
                                
                            # Prepare header dict for insert_headers_batch
                            header_type = header_info['type']
                            protocol_id = 0
                            fields = {}
                            
                            if header_type == 'tcp':
                                protocol_id = protocol_map.get('TCP', 0)
                                fields = {
                                    'src_port': header_info['src_port'],
                                    'dst_port': header_info['dst_port'],
                                    'length': header_info['length']
                                }
                            elif header_type == 'udp':
                                protocol_id = protocol_map.get('UDP', 0)
                                fields = {
                                    'src_port': header_info['src_port'],
                                    'dst_port': header_info['dst_port'],
                                    'length': header_info['length']
                                }
                            elif header_type == 'http':
                                protocol_id = protocol_map.get('HTTP', 0)
                                fields = {
                                    'text_header': header_info.get('text_header'),
                                    'stream_id': header_info.get('stream_id'),
                                    'version': header_info.get('version')
                                }
                            elif header_type == 'ip':
                                proto_name = header_info.get('version', 'IP')
                                protocol_id = protocol_map.get(proto_name, 0)
                                fields = {
                                    'src_ip': header_info.get('src_ip'),
                                    'dst_ip': header_info.get('dst_ip')
                                }
                            
                            if protocol_id:
                                # Add to batch_new_headers
                                new_idx = len(batch_new_headers)
                                batch_new_headers.append({
                                    'protocol_id': protocol_id,
                                    'type': header_type,
                                    'fields': fields
                                })
                                current_pending_indices.append(new_idx)
                                
                                if h_cache_key:
                                    pending_headers_map[h_cache_key] = new_idx
                        
                        batch_cached_header_links.append(current_cached_links)
                        batch_packet_pending_indices.append(current_pending_indices)
                    
                    packet_count += 1
                    
                    if packet_count % batch_size == 0:
                        flush_batch()
                        logger.info(f"Processed {packet_count} packets...")
                
                except Exception as e:
                    logger.warning(f"Error processing packet {pkt_number}: {e}")
                    continue
        
        # Flush remaining
        flush_batch()
        logger.info(f"Completed: {packet_count} packets inserted, {skipped_count} skipped")
    
    except Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        raise


def main():
    """
    Main entry point for the script.
    Parses arguments and initiates the PCAP processing.
    """
    parser = argparse.ArgumentParser(
        description="Read PCAP file and populate PostgreSQL database with packets"
    )
    parser.add_argument("-i", "--input", required=True, help="Input PCAP file")
    parser.add_argument("-n", "--name", required=True, help="Recording name")
    parser.add_argument("--db-host", default="localhost", help="Database host")
    parser.add_argument("--db-port", type=int, default=5432, help="Database port")
    parser.add_argument("--db-name", default="main", help="Database name")
    parser.add_argument("--db-user", default="dbuser", help="Database user")
    parser.add_argument("--db-password", default="dbuser", help="Database password")
    parser.add_argument("--sslkeylog", help="SSLKEYLOGFILE for TLS/QUIC decryption")
    parser.add_argument(
        "--parse-segments",
        action="store_true",
        help="Prefer tls.segment.data over tls.reassembled.data when available",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v for DEBUG, -vv for TRACE)")
    
    args = parser.parse_args()

    # Configure logging level based on verbosity
    if args.verbose == 1:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    elif args.verbose >= 2:
        # Define TRACE level
        TRACE_LEVEL_NUM = 5
        logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
        def trace(self, message, *args, **kws):
            if self.isEnabledFor(TRACE_LEVEL_NUM):
                self._log(TRACE_LEVEL_NUM, message, args, **kws)
        logging.Logger.trace = trace
        
        logging.getLogger().setLevel(TRACE_LEVEL_NUM)
        logger.setLevel(TRACE_LEVEL_NUM)
        logger.log(TRACE_LEVEL_NUM, "Trace logging enabled")
    else:
        logging.getLogger().setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
    
    # Create database manager
    db_manager = DatabaseManager(
        host=args.db_host,
        port=args.db_port,
        database=args.db_name,
        user=args.db_user,
        password=args.db_password
    )
    
    try:
        db_manager.connect()
        process_pcap_to_db(
            args.input,
            args.name,
            db_manager,
            args.sslkeylog,
            parse_segments=args.parse_segments,
        )
    except Exception as e:
        logger.error(f"Failed to process PCAP: {e}")
        sys.exit(1)
    finally:
        db_manager.disconnect()


if __name__ == "__main__":
    main()
