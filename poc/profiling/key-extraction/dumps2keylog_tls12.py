#!/usr/bin/env python3
"""
dumps2keylog_tls12.py - TLS 1.2 / DTLS 1.2 Master Secret Extractor

This script extracts TLS 1.2 and DTLS 1.2 master secrets from memory dumps by 
correlating network packet captures with process memory snapshots.

TLS 1.2 Key Derivation Overview:
    Unlike TLS 1.3 which uses per-direction traffic secrets, TLS 1.2 uses a single
    "master secret" that is derived from the pre-master secret using both the
    client random and server random. The master secret is then used to derive
    the actual encryption keys for both directions.

    In the Wireshark NSS Key Log format, TLS 1.2 secrets are logged as:
        CLIENT_RANDOM <client_random_hex> <master_secret_hex>

Workflow:
    1. Parses a pcapng file to identify TLS 1.2 sessions, extracting:
       - Client Random (32 bytes from ClientHello)
       - Server Random (32 bytes from ServerHello)  
       - Cipher suite (to determine algorithm)
       - The first application data record from each direction (Finished message)
    2. Reads a hints file containing timestamps and filenames of memory dumps taken
       during the TLS sessions.
    3. For each TLS 1.2 session, finds memory dumps that fall within the session's
       time range.
    4. Invokes voses with TLS 1.2 mode using client random, server random, and the
       Client Finished message (first encrypted application data from client).
    5. Outputs discovered master secrets to a key log file (NSS Key Log format).

Finished Message in TLS 1.2:
    The Finished message is the first message encrypted with the negotiated keys.
    It contains a verify_data field (12 bytes for most cipher suites) that is a
    PRF hash of all previous handshake messages. In the encrypted record, this
    appears as the first Handshake record (type 22) after ChangeCipherSpec (type 20),
    NOT as an Application Data record.

Supported cipher suites:
    - TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)
    - TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009D)
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)
    - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009E)
    - TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009F)

DTLS Support:
    DTLS (Datagram TLS) is supported for version 1.2. DTLS runs over UDP and has
    a different record layer format (13 bytes instead of 5 bytes for TLS):
        - 1 byte: content type
        - 2 bytes: version (0xFEFD for DTLS 1.2)
        - 2 bytes: epoch
        - 6 bytes: sequence number
        - 2 bytes: length
    
    DTLS handshake messages also have additional fields for fragmentation support.

Usage:
    python dumps2keylog_tls12.py --pcap <capture.pcapng> --hints <dump-hints.txt> \\
                                  --dumps <dumps_dir> --keylog <output.keylog> \\
                                  [--voses <path_to_voses>]

Arguments:
    --pcap              Path to the pcapng network capture file
    --hints             Path to the dump-hints.txt file with memory dump timestamps
    --dumps             Directory containing the memory dump files
    --keylog            Output path for the NSS key log file
    --voses             Path to the voses binary (default: ./voses)

Requirements:
    - scapy: For parsing pcap files and reassembling TCP streams
    - voses: External binary tool for searching memory dumps for TLS secrets
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, namedtuple

from scapy.all import PcapReader, TCP, UDP, IP, IPv6, Raw

# ==============================================================================
# Configuration Constants
# ==============================================================================

# Memory search parameters for voses
MEMORY_ALIGNMENT = 1
ENTROPY_THRESHOLD = 2.0

# TLS 1.2 GCM cipher suites mapped to voses algorithm names
# Format: cipher_suite_code -> (algorithm_name, key_size_bits)
TLS12_CIPHER_SUITES = {
    # RSA key exchange with AES-GCM
    0x009C: "gcm_128_sha_256",  # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009D: "gcm_256_sha_384",  # TLS_RSA_WITH_AES_256_GCM_SHA384
    
    # ECDHE-RSA key exchange with AES-GCM
    0xC02F: "gcm_128_sha_256",  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030: "gcm_256_sha_384",  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    
    # ECDHE-ECDSA key exchange with AES-GCM
    0xC02B: "gcm_128_sha_256",  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02C: "gcm_256_sha_384",  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    
    # DHE-RSA key exchange with AES-GCM
    0x009E: "gcm_128_sha_256",  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0x009F: "gcm_256_sha_384",  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
}

# Valid TLS/DTLS record content types
TLS_RECORD_TYPES = {20, 21, 22, 23}  # ChangeCipherSpec, Alert, Handshake, ApplicationData

# Valid TLS version bytes (in record layer)
TLS_VERSIONS = {0x0301, 0x0302, 0x0303}  # TLS 1.0, 1.1, 1.2

# Valid DTLS version bytes (in record layer) - note: DTLS uses inverted version numbers
DTLS_VERSIONS = {0xFEFF, 0xFEFD}  # DTLS 1.0, DTLS 1.2

# Combined TLS and DTLS versions for parsing
ALL_TLS_VERSIONS = TLS_VERSIONS | DTLS_VERSIONS

# Maximum allowed TLS/DTLS record length (2^14 + 2048 allowance for encryption overhead)
TLS_MAX_RECORD_LEN = 18432

# DTLS record header size (vs 5 bytes for TLS)
DTLS_RECORD_HEADER_SIZE = 13
TLS_RECORD_HEADER_SIZE = 5

# Named tuple for network endpoints (IP address and port)
Endpoint = namedtuple("Endpoint", ["ip", "port"])


# ==============================================================================
# Hints File Parsing
# ==============================================================================

def split_endpoint(text):
    """
    Parse an endpoint string in the format 'ip:port' or '[ipv6]:port'.
    
    Args:
        text: String containing IP:port, e.g., "192.168.1.1:443" or "[::1]:443"
        
    Returns:
        Tuple of (ip_string, port_int)
    """
    text = text.strip()
    ip, port_str = text.rsplit(":", 1)
    return ip, int(port_str)


def parse_hints(path):
    """
    Parse a dump hints file that maps memory dump files to timestamps and connections.
    
    The hints file format is:
        timestamp: <unix_ms> | file: <filename> | connection: <proto> <src> -> <dst>
    
    Example:
        timestamp: 1640000000000 | file: dump_001.bin | connection: TCP 192.168.1.2:54321 -> 192.168.1.1:443
    
    Args:
        path: Path to the hints file
        
    Returns:
        List of hint dictionaries containing:
            - timestamp_ms: Unix timestamp in milliseconds
            - file: Dump file path
            - proto: Protocol (TCP/UDP)
            - src: Source Endpoint
            - dst: Destination Endpoint
            - raw: Original line text
    """
    hints = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 3:
                continue
            try:
                # Parse timestamp field
                ts = int(parts[0].split(":", 1)[1].strip())
                # Parse filename field
                filename = parts[1].split(":", 1)[1].strip()
                # Parse connection field
                conn_part = parts[2].split(":", 1)[1].strip()
                proto, rest = conn_part.split(None, 1)
                src, dst = [chunk.strip() for chunk in rest.split("->", 1)]
                src_ip, src_port = split_endpoint(src)
                dst_ip, dst_port = split_endpoint(dst)
            except (ValueError, IndexError):
                continue
            hints.append(
                {
                    "timestamp_ms": ts,
                    "file": filename,
                    "proto": proto,
                    "src": Endpoint(src_ip, src_port),
                    "dst": Endpoint(dst_ip, dst_port),
                    "raw": line,
                }
            )
    return hints


# ==============================================================================
# TCP Stream Reassembly
# ==============================================================================

def reassemble_tcp_stream(segments):
    """
    Reassemble TCP segments into contiguous byte streams.
    
    Handles:
        - Out-of-order segments
        - Retransmissions (detected and skipped)
        - Gaps in sequence numbers (creates new chunks)
    
    Args:
        segments: List of (seq_num, timestamp, payload_bytes) tuples
        
    Returns:
        List of (start_seq, stream_bytes, markers) tuples where:
            - start_seq: TCP sequence number of first byte
            - stream_bytes: Reassembled byte stream
            - markers: List of (offset, timestamp) for packet boundaries
    """
    segments = sorted(segments, key=lambda item: item[0])
    chunks = []
    current = bytearray()
    markers = []
    start_seq = None
    expected_seq = None
    seen_ranges = []  # Track seen sequence ranges to detect retransmissions

    def is_retransmission(seq, payload_len):
        """Check if this segment is entirely within already-seen data."""
        end_seq = seq + payload_len
        for seen_start, seen_end in seen_ranges:
            if seq >= seen_start and end_seq <= seen_end:
                return True
        return False

    def mark_seen(seq, payload_len):
        """Mark a sequence range as seen, merging with existing ranges."""
        nonlocal seen_ranges
        new_start = seq
        new_end = seq + payload_len
        merged = []
        for seen_start, seen_end in seen_ranges:
            if new_end < seen_start or new_start > seen_end:
                merged.append((seen_start, seen_end))
            else:
                new_start = min(new_start, seen_start)
                new_end = max(new_end, seen_end)
        merged.append((new_start, new_end))
        seen_ranges = merged

    for seq, ts, payload in segments:
        if not payload:
            continue
        
        if is_retransmission(seq, len(payload)):
            continue
        
        if start_seq is None:
            start_seq = seq
            expected_seq = seq
            
        # Gap detected - start a new chunk
        if seq > expected_seq:
            if current:
                chunks.append((start_seq, bytes(current), markers))
            current = bytearray()
            markers = []
            start_seq = seq
            expected_seq = seq
            
        # Handle partial overlap with existing data
        if seq < expected_seq:
            overlap = expected_seq - seq
            if overlap >= len(payload):
                continue
            payload = payload[overlap:]
            seq = expected_seq
        
        markers.append((len(current), ts))
        current.extend(payload)
        mark_seen(seq, len(payload))
        expected_seq = seq + len(payload)

    if current:
        chunks.append((start_seq, bytes(current), markers))
    return chunks


def timestamp_for_offset(markers, offset):
    """
    Find the timestamp for a given byte offset in the stream.
    
    Args:
        markers: List of (offset, timestamp) tuples
        offset: Byte offset to look up
        
    Returns:
        Timestamp for the packet containing this offset
    """
    if not markers:
        return None
    ts = markers[0][1]
    for marker_offset, marker_ts in markers:
        if marker_offset > offset:
            break
        ts = marker_ts
    return ts


# ==============================================================================
# TLS Record Parsing
# ==============================================================================

def is_dtls_version(version):
    """Check if the version indicates DTLS."""
    return version in DTLS_VERSIONS


def parse_tls_records(stream, markers, is_dtls=False):
    """
    Parse TLS or DTLS records from a reassembled stream.
    
    TLS Record format (5 bytes header):
        - 1 byte: content type (20=CCS, 21=Alert, 22=Handshake, 23=AppData)
        - 2 bytes: version (0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2)
        - 2 bytes: length (big-endian)
        - N bytes: payload
    
    DTLS Record format (13 bytes header):
        - 1 byte: content type (20=CCS, 21=Alert, 22=Handshake, 23=AppData)
        - 2 bytes: version (0xFEFD=DTLS1.2, 0xFEFF=DTLS1.0)
        - 2 bytes: epoch
        - 6 bytes: sequence number
        - 2 bytes: length (big-endian)
        - N bytes: payload
    
    Args:
        stream: Raw stream bytes
        markers: Timestamp markers from reassembly
        is_dtls: If True, parse as DTLS format; if False, parse as TLS format
        
    Returns:
        List of record dictionaries with:
            - type: Content type (20, 21, 22, or 23)
            - version: TLS/DTLS version
            - data: Full record bytes (including header)
            - timestamp: When this record was sent
            - is_dtls: Boolean indicating DTLS record
            - epoch: (DTLS only) epoch value
            - seq_num: (DTLS only) sequence number
    """
    records = []
    offset = 0
    stream_len = len(stream)
    
    header_size = DTLS_RECORD_HEADER_SIZE if is_dtls else TLS_RECORD_HEADER_SIZE
    valid_versions = DTLS_VERSIONS if is_dtls else TLS_VERSIONS
    
    while offset + header_size <= stream_len:
        content_type = stream[offset]
        version = (stream[offset + 1] << 8) | stream[offset + 2]
        
        if is_dtls:
            # DTLS: epoch (2 bytes) + sequence number (6 bytes) + length (2 bytes)
            epoch = (stream[offset + 3] << 8) | stream[offset + 4]
            seq_num = int.from_bytes(stream[offset + 5 : offset + 11], 'big')
            length = (stream[offset + 11] << 8) | stream[offset + 12]
        else:
            # TLS: length (2 bytes)
            epoch = None
            seq_num = None
            length = (stream[offset + 3] << 8) | stream[offset + 4]
        
        record_len = header_size + length

        # Validate record header
        if content_type not in TLS_RECORD_TYPES or version not in valid_versions:
            offset += 1
            continue
        if record_len <= header_size or record_len > TLS_MAX_RECORD_LEN:
            offset += 1
            continue
        if offset + record_len > stream_len:
            break

        record = stream[offset : offset + record_len]
        record_dict = {
            "type": content_type,
            "version": version,
            "data": record,
            "timestamp": timestamp_for_offset(markers, offset),
            "is_dtls": is_dtls,
        }
        if is_dtls:
            record_dict["epoch"] = epoch
            record_dict["seq_num"] = seq_num
        records.append(record_dict)
        offset += record_len
    return records


# ==============================================================================
# TLS Handshake Parsing
# ==============================================================================

def parse_handshake_messages(buffer, is_dtls=False):
    """
    Parse TLS or DTLS handshake messages from a buffer.
    
    TLS Handshake message format (4 bytes header):
        - 1 byte: message type
        - 3 bytes: message length (big-endian)
        - N bytes: message data
    
    DTLS Handshake message format (12 bytes header):
        - 1 byte: message type
        - 3 bytes: message length (big-endian)
        - 2 bytes: message sequence
        - 3 bytes: fragment offset
        - 3 bytes: fragment length
        - N bytes: message data (fragment)
    
    Args:
        buffer: Bytes containing handshake messages
        is_dtls: If True, parse as DTLS format; if False, parse as TLS format
        
    Returns:
        Tuple of (messages_list, remaining_bytes)
        Each message is (type, data) tuple
    """
    messages = []
    offset = 0
    header_size = 12 if is_dtls else 4
    
    while offset + header_size <= len(buffer):
        msg_type = buffer[offset]
        msg_len = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]
        
        if is_dtls:
            # DTLS: additional fields after length
            # message_seq = (buffer[offset + 4] << 8) | buffer[offset + 5]
            # fragment_offset = (buffer[offset + 6] << 16) | (buffer[offset + 7] << 8) | buffer[offset + 8]
            fragment_len = (buffer[offset + 9] << 16) | (buffer[offset + 10] << 8) | buffer[offset + 11]
            # For now, we only handle non-fragmented messages (fragment_len == msg_len)
            total_len = header_size + fragment_len
            if offset + total_len > len(buffer):
                break
            msg_data = buffer[offset + header_size : offset + total_len]
        else:
            total_len = header_size + msg_len
            if offset + total_len > len(buffer):
                break
            msg_data = buffer[offset + header_size : offset + total_len]
        
        messages.append((msg_type, msg_data))
        offset += total_len
    return messages, buffer[offset:]


def parse_extensions(data):
    """
    Parse TLS extensions from extension data block.
    
    Extension format:
        - 2 bytes: extension type
        - 2 bytes: extension length
        - N bytes: extension data
    
    Args:
        data: Raw extension bytes
        
    Returns:
        Dictionary mapping extension_type -> extension_data
    """
    extensions = {}
    idx = 0
    while idx + 4 <= len(data):
        ext_type = (data[idx] << 8) | data[idx + 1]
        ext_len = (data[idx + 2] << 8) | data[idx + 3]
        idx += 4
        if idx + ext_len > len(data):
            break
        extensions[ext_type] = data[idx : idx + ext_len]
        idx += ext_len
    return extensions


def parse_client_hello(data):
    """
    Parse a TLS ClientHello message to extract the client random.
    
    ClientHello structure:
        - 2 bytes: client version
        - 32 bytes: client random (what we need!)
        - 1 byte: session ID length
        - N bytes: session ID
        - 2 bytes: cipher suites length
        - N bytes: cipher suites
        - 1 byte: compression methods length
        - N bytes: compression methods
        - (optional) 2 bytes: extensions length
        - N bytes: extensions
    
    Args:
        data: Raw ClientHello message bytes (after handshake header)
        
    Returns:
        Tuple of (client_random_hex, supported_versions) or None on parse error
    """
    if len(data) < 34:
        return None
    
    # Client random is at bytes 2-34 (after 2-byte version)
    random = data[2:34]
    idx = 34
    
    # Skip session ID
    if idx >= len(data):
        return None
    session_id_len = data[idx]
    idx += 1 + session_id_len
    
    # Skip cipher suites
    if idx + 2 > len(data):
        return None
    cipher_len = (data[idx] << 8) | data[idx + 1]
    idx += 2 + cipher_len
    
    # Skip compression methods
    if idx >= len(data):
        return None
    compression_len = data[idx]
    idx += 1 + compression_len
    
    # Parse extensions (optional)
    supported_versions = []
    if idx + 2 <= len(data):
        extensions_len = (data[idx] << 8) | data[idx + 1]
        idx += 2
        if idx + extensions_len <= len(data):
            extensions = parse_extensions(data[idx : idx + extensions_len])
            # Check for supported_versions extension (indicates TLS 1.3)
            ext_data = extensions.get(0x002B)
            if ext_data and len(ext_data) >= 1:
                list_len = ext_data[0]
                for i in range(1, min(len(ext_data), 1 + list_len), 2):
                    if i + 1 < len(ext_data):
                        supported_versions.append((ext_data[i] << 8) | ext_data[i + 1])
    
    return random.hex(), supported_versions


def parse_server_hello(data):
    """
    Parse a TLS ServerHello message to extract the server random and cipher suite.
    
    ServerHello structure:
        - 2 bytes: server version
        - 32 bytes: server random (what we need!)
        - 1 byte: session ID length
        - N bytes: session ID
        - 2 bytes: cipher suite (what we need!)
        - 1 byte: compression method
        - (optional) 2 bytes: extensions length
        - N bytes: extensions
    
    Args:
        data: Raw ServerHello message bytes (after handshake header)
        
    Returns:
        Tuple of (server_random_hex, cipher_suite, supported_version) or None
    """
    if len(data) < 38:
        return None
    
    # Server random is at bytes 2-34 (after 2-byte version)
    server_random = data[2:34]
    idx = 34
    
    # Skip session ID
    if idx >= len(data):
        return None
    session_id_len = data[idx]
    idx += 1 + session_id_len
    
    # Read cipher suite (2 bytes)
    if idx + 3 > len(data):
        return None
    cipher_suite = (data[idx] << 8) | data[idx + 1]
    idx += 3  # cipher suite (2) + compression (1)
    
    # Parse extensions to check for TLS 1.3 (supported_versions)
    supported_version = None
    if idx + 2 <= len(data):
        extensions_len = (data[idx] << 8) | data[idx + 1]
        idx += 2
        if idx + extensions_len <= len(data):
            extensions = parse_extensions(data[idx : idx + extensions_len])
            ext_data = extensions.get(0x002B)  # supported_versions extension
            if ext_data and len(ext_data) >= 2:
                supported_version = (ext_data[0] << 8) | ext_data[1]
    
    return server_random.hex(), cipher_suite, supported_version


def reverse_dir(dir_key):
    """Reverse a direction key (swap source and destination)."""
    return (dir_key[1], dir_key[0])


# ==============================================================================
# Flow Construction and Analysis
# ==============================================================================

def build_flows(pcap_path):
    """
    Build TCP and UDP flows from a pcap file, extracting TLS/DTLS records.
    
    A flow is identified by the tuple of (min_endpoint, max_endpoint, protocol) where
    endpoints are sorted to ensure the same flow is identified regardless
    of packet direction.
    
    Args:
        pcap_path: Path to the pcapng file
        
    Returns:
        Dictionary mapping flow keys to flow state dictionaries
    """
    flows = {}
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            # Check for TCP or UDP
            is_tcp = pkt.haslayer(TCP)
            is_udp = pkt.haslayer(UDP)
            
            if not (is_tcp or is_udp) or not pkt.haslayer(Raw):
                continue
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue
            payload = bytes(pkt[Raw].load)
            if not payload:
                continue
            
            if is_tcp:
                transport = pkt[TCP]
                proto = "TCP"
            else:
                transport = pkt[UDP]
                proto = "UDP"
            
            src = Endpoint(ip_layer.src, transport.sport)
            dst = Endpoint(ip_layer.dst, transport.dport)
            ts = float(pkt.time)
            
            # Create a canonical connection key (sorted endpoints + protocol)
            conn_key = (tuple(sorted((src, dst), key=lambda e: (e.ip, e.port))), proto)
            
            flow = flows.get(conn_key)
            if not flow:
                flow = {
                    "segments": defaultdict(list),
                    "records": {},
                    "client_dir": None,
                    "server_dir": None,
                    "client_random": None,
                    "server_random": None,
                    "cipher_suite": None,
                    "tls12": False,
                    "tls13": False,
                    "dtls": False,
                    "client_hello_ts": None,
                    "server_hello_ts": None,
                    "first_seen": ts,
                    "protocol": proto,
                }
                flows[conn_key] = flow
            
            if ts < flow["first_seen"]:
                flow["first_seen"] = ts
            
            dir_key = (src, dst)
            if is_tcp:
                flow["segments"][dir_key].append((transport.seq, ts, payload))
            else:
                # For UDP, we don't have sequence numbers, use timestamp for ordering
                # We use a pseudo-sequence based on order of arrival
                existing = flow["segments"][dir_key]
                pseudo_seq = len(existing)
                flow["segments"][dir_key].append((pseudo_seq, ts, payload))

    # Process flows - reassemble TCP streams or concatenate UDP datagrams
    for flow in flows.values():
        is_udp = flow["protocol"] == "UDP"
        
        for dir_key, segments in flow["segments"].items():
            records = []
            
            if is_udp:
                # For UDP/DTLS, each datagram may contain one or more DTLS records
                # Sort by timestamp, then parse each datagram individually
                sorted_segments = sorted(segments, key=lambda x: (x[1], x[0]))  # Sort by ts, then pseudo-seq
                for _pseudo_seq, ts, payload in sorted_segments:
                    # Try parsing as DTLS first
                    dtls_records = parse_tls_records(payload, [(0, ts)], is_dtls=True)
                    if dtls_records:
                        records.extend(dtls_records)
                        flow["dtls"] = True
                    else:
                        # Fall back to TLS parsing (shouldn't happen for UDP, but just in case)
                        tls_records = parse_tls_records(payload, [(0, ts)], is_dtls=False)
                        records.extend(tls_records)
            else:
                # TCP: reassemble stream then parse TLS records
                chunks = reassemble_tcp_stream(segments)
                for _start_seq, stream, markers in chunks:
                    records.extend(parse_tls_records(stream, markers, is_dtls=False))
            
            flow["records"][dir_key] = records

    return flows


def extract_handshake_info(flow):
    """
    Extract TLS/DTLS handshake information from a flow.
    
    Parses ClientHello and ServerHello messages to extract:
        - Client Random (from ClientHello)
        - Server Random (from ServerHello)
        - Cipher Suite (from ServerHello)
        - Whether this is TLS 1.2, TLS 1.3, or DTLS 1.2
    
    Args:
        flow: Flow dictionary to update with handshake info
    """
    is_dtls = flow.get("dtls", False) or flow.get("protocol") == "UDP"
    header_size = DTLS_RECORD_HEADER_SIZE if is_dtls else TLS_RECORD_HEADER_SIZE
    
    for dir_key, records in flow["records"].items():
        handshake_buffer = bytearray()
        for record in records:
            # Only process Handshake records (type 22)
            if record["type"] != 22:
                continue
            
            # Check if this record indicates DTLS
            record_is_dtls = record.get("is_dtls", False)
            if record_is_dtls:
                flow["dtls"] = True
                is_dtls = True
                header_size = DTLS_RECORD_HEADER_SIZE
            
            # Append handshake payload (skip record header)
            record_header_size = DTLS_RECORD_HEADER_SIZE if record_is_dtls else TLS_RECORD_HEADER_SIZE
            handshake_buffer.extend(record["data"][record_header_size:])
            messages, remaining = parse_handshake_messages(handshake_buffer, is_dtls=record_is_dtls)
            handshake_buffer = bytearray(remaining)
            
            for msg_type, msg_data in messages:
                # ClientHello (type 1)
                if msg_type == 1 and flow["client_random"] is None:
                    parsed = parse_client_hello(msg_data)
                    if parsed:
                        client_random, supported_versions = parsed
                        flow["client_random"] = client_random
                        flow["client_dir"] = dir_key
                        if flow["client_hello_ts"] is None:
                            flow["client_hello_ts"] = record["timestamp"]
                        # Check if TLS 1.3 is in supported versions
                        if 0x0304 in supported_versions:
                            flow["tls13"] = True
                
                # ServerHello (type 2)
                elif msg_type == 2 and flow["cipher_suite"] is None:
                    parsed = parse_server_hello(msg_data)
                    if parsed:
                        server_random, cipher_suite, supported_version = parsed
                        flow["server_random"] = server_random
                        flow["cipher_suite"] = cipher_suite
                        flow["server_dir"] = dir_key
                        if flow["server_hello_ts"] is None:
                            flow["server_hello_ts"] = record["timestamp"]
                        
                        # Determine TLS/DTLS version
                        if supported_version == 0x0304:
                            flow["tls13"] = True
                        elif cipher_suite in TLS12_CIPHER_SUITES:
                            flow["tls12"] = True
                            # If this is a UDP flow, mark as DTLS
                            if flow.get("protocol") == "UDP" or record_is_dtls:
                                flow["dtls"] = True

    # Infer missing direction info
    if flow["client_dir"] and not flow["server_dir"]:
        flow["server_dir"] = reverse_dir(flow["client_dir"])
    if flow["server_dir"] and not flow["client_dir"]:
        flow["client_dir"] = reverse_dir(flow["server_dir"])


def get_finished_record(records):
    """
    Get the encrypted Finished message record from a list of TLS/DTLS records.
    
    In TLS 1.2, the Finished message is sent as the first encrypted Handshake
    record (content type 22) after the ChangeCipherSpec message (content type 20).
    This is NOT an Application Data record (type 23).
    
    The sequence is:
        1. ChangeCipherSpec (type 20) - signals switch to encrypted mode
        2. Finished (type 22) - first encrypted handshake message
    
    Args:
        records: List of TLS record dictionaries
        
    Returns:
        The encrypted Finished record dictionary, or None if not found
    """
    seen_ccs = False
    for record in records:
        if record["type"] == 20:  # ChangeCipherSpec
            seen_ccs = True
        elif record["type"] == 22 and seen_ccs:  # Handshake after CCS = encrypted Finished
            return record
    return None


# ==============================================================================
# Time Range and Dump Selection
# ==============================================================================

def get_session_time_range(flow):
    """
    Get the start and end timestamps of a TLS session.
    
    Args:
        flow: Flow dictionary
        
    Returns:
        Tuple of (start_time, end_time) as float timestamps
    """
    start_time = flow.get("client_hello_ts") or flow.get("server_hello_ts") or flow.get("first_seen")
    
    # Find the last timestamp across all records
    end_time = start_time
    for dir_key, records in flow["records"].items():
        for record in records:
            if record["timestamp"] is not None:
                if end_time is None or record["timestamp"] > end_time:
                    end_time = record["timestamp"]
    
    return start_time, end_time


def find_dumps_in_timeframe(hints, start_time, end_time, dumps_dir):
    """
    Find memory dump files whose timestamps fall within a given time range.
    
    Args:
        hints: List of hint dictionaries from parse_hints()
        start_time: Start of time range (Unix timestamp)
        end_time: End of time range (Unix timestamp)
        dumps_dir: Directory containing dump files
        
    Returns:
        List of (dump_path, timestamp) tuples, sorted by timestamp descending
    """
    matching_dumps = []
    for hint in hints:
        hint_ts = hint["timestamp_ms"] / 1000.0
        if start_time is not None and end_time is not None:
            if start_time <= hint_ts <= end_time:
                dump_path = hint["file"]
                if not os.path.isabs(dump_path):
                    dump_path = os.path.join(dumps_dir, dump_path)
                if os.path.exists(dump_path) and dump_path not in [d[0] for d in matching_dumps]:
                    matching_dumps.append((dump_path, hint_ts))
    # Sort by timestamp descending (use latest dump first)
    matching_dumps.sort(key=lambda x: x[1], reverse=True)
    return matching_dumps


def find_first_dump_after_timeframe(hints, start_time, end_time, dumps_dir):
    """Find the existing dump with the earliest timestamp after a session window."""
    if end_time is None:
        return None

    first_after = None
    for hint in hints:
        hint_ts = hint["timestamp_ms"] / 1000.0
        if hint_ts <= end_time:
            continue

        dump_path = hint["file"]
        if not os.path.isabs(dump_path):
            dump_path = os.path.join(dumps_dir, dump_path)
        if not os.path.exists(dump_path):
            continue

        distance = hint_ts - end_time

        if first_after is None or hint_ts < first_after[1]:
            first_after = (dump_path, hint_ts, distance)

    return first_after


# ==============================================================================
# VOSES Integration for TLS 1.2
# ==============================================================================

def run_voses_tls12(voses_path, dump_path, client_finished_data, client_random, 
                    server_random, algorithm, keylog_path, is_dtls=False):
    """
    Run voses in TLS 1.2 / DTLS 1.2 mode to search for the master secret.
    
    voses TLS 1.2 command format:
        voses.exe --tls12 
            --client_random|-cr <32-byte hex>
            --server_random|-sr <32-byte hex>
            --client_finished|-cf <hex, max 61 bytes>
            --algorithm|-a <gcm_256_sha_384|gcm_128_sha_256>
            --haystack|-h <path>
            [--key-log <path>]
            [--memory-alignment|-ma <int>]
            [--entropy|-e <float>]
    
    The Client Finished message is extracted from the first encrypted Handshake
    record (after ChangeCipherSpec) from the client. We pass the full record 
    including the header to voses (voses expects byte 0 to be 0x16 = Handshake type).
    
    Args:
        voses_path: Path to the voses executable
        dump_path: Path to the memory dump file
        client_finished_data: Full TLS/DTLS Handshake record bytes (including header)
        client_random: Client random as hex string (64 chars)
        server_random: Server random as hex string (64 chars)
        algorithm: Algorithm name for voses (gcm_128_sha_256 or gcm_256_sha_384)
        keylog_path: Path to output keylog file
        is_dtls: If True, treat as DTLS record (13-byte header); otherwise TLS (5-byte header)
        
    Returns:
        Tuple of (success, output, return_code, elapsed_time)
    """
    # Pass the full TLS/DTLS record to voses (including the record header).
    # voses expects the first byte to be 0x16 (Handshake content type).
    # The record structure is:
    #   TLS:  5-byte header (type, version, length) + encrypted payload
    #   DTLS: 13-byte header (type, version, epoch, seq_num, length) + encrypted payload
    #
    # Limit to 61 bytes as per voses specification
    client_finished_record = client_finished_data[:61]
    
    client_finished_hex = client_finished_record.hex()
    
    pre_size = os.path.getsize(keylog_path) if os.path.exists(keylog_path) else 0
    
    args = [
        voses_path,
        "--tls12",
        "--client_random", client_random,
        "--server_random", server_random,
        "--client_finished", client_finished_hex,
        "--algorithm", algorithm,
        "--haystack", dump_path,
        "--memory-alignment", str(MEMORY_ALIGNMENT),
        "--entropy", str(ENTROPY_THRESHOLD),
        "--key-log", keylog_path,
    ]

    try:
        start_time = time.perf_counter()
        result = subprocess.run(args, capture_output=True, text=True)
        elapsed = time.perf_counter() - start_time
    except Exception as e:
        return False, str(e), -1, 0.0

    post_size = os.path.getsize(keylog_path) if os.path.exists(keylog_path) else 0
    output = (result.stdout or "") + (result.stderr or "")
    success = post_size > pre_size
    return success, output, result.returncode, elapsed


def attempt_master_secret_extraction(flow, dump_path, keylog_path):
    """
    Attempt to extract the TLS 1.2 / DTLS 1.2 master secret from a memory dump.
    
    This function:
    1. Gets the first Application Data record from the client direction
       (this contains the encrypted Client Finished message)
    2. Invokes voses with TLS 1.2 mode using the client/server randoms
       and the encrypted Finished message
    
    Args:
        flow: Flow dictionary with TLS/DTLS handshake info
        dump_path: Path to memory dump file
        keylog_path: Path to keylog output file
        
    Returns:
        True if master secret was found, False otherwise
    """
    # Get client-side records to find the Client Finished message
    client_records = flow["records"].get(flow["client_dir"], [])
    
    # The Finished message is the first encrypted Handshake record after ChangeCipherSpec
    client_finished_record = get_finished_record(client_records)
    
    if client_finished_record is None:
        print(f"[!] No Client Finished message (encrypted Handshake after CCS) found")
        return False
    
    is_dtls = flow.get("dtls", False)
    proto_name = "DTLS 1.2" if is_dtls else "TLS 1.2"
    
    src, dst = flow["client_dir"]
    print(f"[*] {proto_name} session: {src.ip}:{src.port} -> {dst.ip}:{dst.port}")
    print(f"    Protocol: {flow.get('protocol', 'TCP')}")
    print(f"    Algorithm: {flow['algorithm']}")
    print(f"    Client Random: {flow['client_random']}")
    print(f"    Server Random: {flow['server_random']}")
    print(f"    Client Finished record length: {len(client_finished_record['data'])} bytes")
    print(f"    Using dump: {os.path.basename(dump_path)}")
    
    success, output, code, elapsed = run_voses_tls12(
        flow["voses_path"],
        dump_path,
        client_finished_record["data"],
        flow["client_random"],
        flow["server_random"],
        flow["algorithm"],
        keylog_path,
        is_dtls=is_dtls,
    )
    
    if success:
        print(f"[+] Master secret found! (took {elapsed:.2f}s)")
        return True
    else:
        print(f"[!] Master secret not found (voses exit code: {code}, took {elapsed:.2f}s)")
        if output.strip():
            # Print first few lines of output for debugging
            lines = output.strip().split('\n')[:5]
            for line in lines:
                print(f"    {line}")
        return False


# ==============================================================================
# Command Line Interface
# ==============================================================================

def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract TLS 1.2 master secrets from memory dumps using voses."
    )
    parser.add_argument(
        "--pcap", 
        required=True, 
        help="Path to pcapng capture file."
    )
    parser.add_argument(
        "--hints", 
        required=True, 
        help="Path to dump-hints.txt file."
    )
    parser.add_argument(
        "--dumps", 
        required=True, 
        help="Directory containing memory dumps."
    )
    parser.add_argument(
        "--keylog", 
        required=True, 
        help="Output key log file path."
    )
    parser.add_argument(
        "--voses",
        default=os.path.join(os.getcwd(), "voses"),
        help="Path to voses binary (default: ./voses).",
    )
    parser.add_argument(
        "--use-closest-dump",
        action="store_true",
        help=(
            "If no dump falls inside a session timeframe, search the first "
            "existing dump after that session ends."
        ),
    )
    return parser.parse_args()


# ==============================================================================
# Main Entry Point
# ==============================================================================

def main():
    """
    Main entry point for TLS 1.2 master secret extraction.
    
    Workflow:
        1. Parse command line arguments and validate inputs
        2. Parse hints file to get memory dump timestamps
        3. Parse pcap file to extract TLS 1.2 flows
        4. For each TLS 1.2 session:
           a. Find memory dumps within the session timeframe
           b. Attempt master secret extraction using each dump
        5. Report results and write keylog file
    """
    args = get_args()
    
    # Validate inputs
    if not os.path.exists(args.pcap):
        print(f"Error: pcap file not found: {args.pcap}", file=sys.stderr)
        return 1
    if not os.path.exists(args.hints):
        print(f"Error: hints file not found: {args.hints}", file=sys.stderr)
        return 1
    if not os.path.isdir(args.dumps):
        print(f"Error: dumps directory not found: {args.dumps}", file=sys.stderr)
        return 1
    if not os.path.isfile(args.voses) or not os.access(args.voses, os.X_OK):
        # On Windows, also check for .exe extension
        voses_exe = args.voses if args.voses.endswith('.exe') else args.voses + '.exe'
        if os.path.isfile(voses_exe):
            args.voses = voses_exe
        else:
            print(f"Error: voses binary not found or not executable: {args.voses}", file=sys.stderr)
            return 1
    
    # Create output directory if needed
    keylog_dir = os.path.dirname(args.keylog)
    if keylog_dir and not os.path.exists(keylog_dir):
        os.makedirs(keylog_dir)

    overall_start_time = time.time()

    # Parse hints file
    hints = parse_hints(args.hints)
    if not hints:
        print("Error: no usable hints found.", file=sys.stderr)
        return 1
    print(f"Loaded {len(hints)} memory dump hints.")

    # Build and analyze flows from pcap
    print(f"Parsing pcap file: {args.pcap}")
    flows = build_flows(args.pcap)
    for flow in flows.values():
        extract_handshake_info(flow)

    # Filter for TLS 1.2 / DTLS 1.2 sessions only (exclude TLS 1.3)
    tls12_flows = [
        flow for flow in flows.values() 
        if flow["tls12"] and not flow["tls13"]
    ]
    
    # Count TLS vs DTLS sessions
    dtls_count = sum(1 for f in tls12_flows if f.get("dtls", False))
    tls_count = len(tls12_flows) - dtls_count
    
    if not tls12_flows:
        print("No TLS 1.2 / DTLS 1.2 sessions found in capture.")
        print("(Note: TLS 1.3 sessions are handled by dumps2keylog.py)")
        return 0

    print(f"\nFound {len(tls12_flows)} TLS 1.2 / DTLS 1.2 sessions in capture.")
    if dtls_count > 0:
        print(f"  - {tls_count} TLS 1.2 (TCP) sessions")
        print(f"  - {dtls_count} DTLS 1.2 (UDP) sessions")
    print()

    # Collect valid sessions with all required info
    sessions = []
    for flow in tls12_flows:
        # Validate required fields
        if flow["client_random"] is None:
            print(f"[!] Skipping session without client random")
            continue
        if flow["server_random"] is None:
            print(f"[!] Skipping session without server random")
            continue
        
        algorithm = TLS12_CIPHER_SUITES.get(flow["cipher_suite"])
        if not algorithm:
            cipher_hex = f"0x{flow['cipher_suite']:04X}" if flow['cipher_suite'] else "None"
            print(f"[!] Skipping session with unsupported cipher suite: {cipher_hex}")
            continue
        
        if not flow.get("client_dir") or not flow.get("server_dir"):
            print(f"[!] Skipping session without direction info")
            continue
        
        start_time, end_time = get_session_time_range(flow)
        client_src, client_dst = flow["client_dir"]
        conn_str = f"{client_src.ip}:{client_src.port} -> {client_dst.ip}:{client_dst.port}"
        
        sessions.append({
            "flow": flow,
            "start_time": start_time,
            "end_time": end_time,
            "conn_str": conn_str,
            "algorithm": algorithm,
        })
        
        print(f"[*] Session: {conn_str}")
        cipher_hex = f"0x{flow['cipher_suite']:04X}"
        print(f"    Cipher: {cipher_hex} ({algorithm})")
        print(f"    Time range: {start_time:.3f} - {end_time:.3f} ({end_time - start_time:.3f}s)")

    if not sessions:
        print("\nNo valid TLS 1.2 sessions to process.")
        return 0

    print(f"\n{'='*60}")
    print(f"Processing {len(sessions)} TLS 1.2 / DTLS 1.2 sessions")
    print(f"{'='*60}\n")

    successful_extractions = []
    failed_extractions = []
    skipped_sessions = []

    for idx, session in enumerate(sessions):
        flow = session["flow"]
        conn_str = session["conn_str"]
        
        print(f"\n[Session {idx+1}/{len(sessions)}] {conn_str}")
        print(f"  Time range: {session['start_time']:.3f} - {session['end_time']:.3f}")
        
        # Find dumps within session timeframe
        dumps = find_dumps_in_timeframe(hints, session["start_time"], session["end_time"], args.dumps)
        using_closest_dump = False
        
        if not dumps:
            if args.use_closest_dump:
                first_after = find_first_dump_after_timeframe(
                    hints,
                    session["start_time"],
                    session["end_time"],
                    args.dumps,
                )
                if first_after:
                    dump_path, dump_ts, distance = first_after
                    dumps = [(dump_path, dump_ts)]
                    using_closest_dump = True
                    print(
                        "  [WARNING] No dumps found within session timeframe; "
                        f"using first dump after session end ({distance:.3f}s later)"
                    )

            if not dumps:
                print(f"  [WARNING] No dumps found within session timeframe - skipping")
                skipped_sessions.append(conn_str)
                continue
        
        if using_closest_dump:
            print("  Found 1 dump after the session timeframe")
        else:
            print(f"  Found {len(dumps)} dump(s) in timeframe")
        
        # Store algorithm and voses path in flow for the extraction function
        flow["algorithm"] = session["algorithm"]
        flow["voses_path"] = args.voses
        
        # Try each dump until we find the master secret
        secret_found = False
        for dump_path, dump_ts in dumps:
            print(f"\n  Trying dump: {os.path.basename(dump_path)} (ts: {dump_ts:.3f})")
            
            if attempt_master_secret_extraction(flow, dump_path, args.keylog):
                secret_found = True
                break
        
        if secret_found:
            successful_extractions.append(conn_str)
        else:
            failed_extractions.append(conn_str)

    # Print summary
    print("\n" + "=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)

    if successful_extractions:
        print(f"\n[+] Successful extractions ({len(successful_extractions)}):")
        for conn in successful_extractions:
            print(f"    {conn}")
    else:
        print("\n[!] No successful extractions.")

    if failed_extractions:
        print(f"\n[-] Failed extractions ({len(failed_extractions)}):")
        for conn in failed_extractions:
            print(f"    {conn}")
    else:
        print("\n[+] No failed extractions.")

    if skipped_sessions:
        print(f"\n[!] Skipped sessions (no dumps in timeframe) ({len(skipped_sessions)}):")
        for conn in skipped_sessions:
            print(f"    {conn}")

    elapsed_time = time.time() - overall_start_time
    print(f"\nTotal runtime: {elapsed_time:.2f} seconds")
    
    if os.path.exists(args.keylog):
        print(f"Key log written to: {args.keylog}")
    
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
