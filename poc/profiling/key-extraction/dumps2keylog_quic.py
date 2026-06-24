#!/usr/bin/env python3
"""
Extract QUIC TLS 1.3 traffic secrets from memory dumps using voses.

This script parses QUIC UDP packets from a pcap file, extracts connection
information (including client random from the TLS ClientHello embedded in
QUIC Initial packets), and uses voses to search for traffic secrets in
memory dumps.
"""
import argparse
import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, namedtuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from scapy.all import PcapReader, UDP, IP, IPv6, Raw

MEMORY_ALIGNMENT = 1
ENTROPY_THRESHOLD = 3.0

# TLS 1.3 cipher suites used in QUIC
QUIC_CIPHER_SUITES = {
    0x1301: "gcm_128_sha_256",  # TLS_AES_128_GCM_SHA256
    0x1302: "gcm_256_sha_384",  # TLS_AES_256_GCM_SHA384
}

# QUIC long header packet types
QUIC_LONG_HEADER_INITIAL = 0x00
QUIC_LONG_HEADER_0RTT = 0x01
QUIC_LONG_HEADER_HANDSHAKE = 0x02
QUIC_LONG_HEADER_RETRY = 0x03

# QUIC v1 Initial salt (RFC 9001)
QUIC_V1_INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

Endpoint = namedtuple("Endpoint", ["ip", "port"])


def hkdf_extract(salt, ikm):
    """HKDF-Extract using SHA-256 (RFC 5869)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret, label, context, length):
    """
    HKDF-Expand-Label as defined in TLS 1.3 / QUIC.
    """
    # Build the HkdfLabel structure
    label_bytes = b"tls13 " + label
    hkdf_label = (
        length.to_bytes(2, "big")
        + len(label_bytes).to_bytes(1, "big")
        + label_bytes
        + len(context).to_bytes(1, "big")
        + context
    )
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=hkdf_label,
        backend=default_backend(),
    ).derive(secret)


def derive_initial_secrets(dcid):
    """
    Derive QUIC Initial secrets from the Destination Connection ID.
    Returns (client_initial_secret, server_initial_secret).
    """
    initial_secret = hkdf_extract(QUIC_V1_INITIAL_SALT, dcid)
    client_initial_secret = hkdf_expand_label(initial_secret, b"client in", b"", 32)
    server_initial_secret = hkdf_expand_label(initial_secret, b"server in", b"", 32)
    return client_initial_secret, server_initial_secret


def derive_key_iv_hp(secret):
    """
    Derive key, IV, and header protection key from a secret.
    Returns (key, iv, hp_key) for AES-128-GCM.
    """
    key = hkdf_expand_label(secret, b"quic key", b"", 16)
    iv = hkdf_expand_label(secret, b"quic iv", b"", 12)
    hp = hkdf_expand_label(secret, b"quic hp", b"", 16)
    return key, iv, hp


def remove_header_protection(packet, hp_key, pn_offset):
    """
    Remove header protection from a QUIC packet.
    Returns (unprotected_header, packet_number, pn_length, payload_start).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Sample starts 4 bytes after the packet number offset
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(packet):
        return None

    sample = packet[sample_offset : sample_offset + 16]

    # Generate mask using AES-ECB
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    # Unprotect the first byte
    first_byte = packet[0]
    if first_byte & 0x80:  # Long header
        first_byte ^= mask[0] & 0x0F
    else:  # Short header
        first_byte ^= mask[0] & 0x1F

    pn_length = (first_byte & 0x03) + 1

    # Unprotect the packet number
    pn_bytes = bytearray(packet[pn_offset : pn_offset + pn_length])
    for i in range(pn_length):
        pn_bytes[i] ^= mask[1 + i]

    packet_number = int.from_bytes(pn_bytes, "big")

    # Build unprotected header
    unprotected = bytearray(packet[:pn_offset + pn_length])
    unprotected[0] = first_byte
    unprotected[pn_offset : pn_offset + pn_length] = pn_bytes

    return bytes(unprotected), packet_number, pn_length, pn_offset + pn_length


def decrypt_initial_payload(packet, dcid, is_client=True):
    """
    Decrypt a QUIC Initial packet payload.
    Returns the decrypted CRYPTO frame data or None on failure.
    """
    client_secret, server_secret = derive_initial_secrets(dcid)
    secret = client_secret if is_client else server_secret
    key, iv, hp_key = derive_key_iv_hp(secret)

    # Parse the header to get pn_offset
    header = parse_quic_long_header(packet)
    if header is None or header["type"] != QUIC_LONG_HEADER_INITIAL:
        return None

    pn_offset = header["pn_offset"]

    # Remove header protection
    result = remove_header_protection(packet, hp_key, pn_offset)
    if result is None:
        return None

    unprotected_header, packet_number, pn_length, payload_start = result

    # Calculate the nonce
    nonce = bytearray(iv)
    pn_bytes = packet_number.to_bytes(len(iv), "big")
    for i in range(len(iv)):
        nonce[i] ^= pn_bytes[i]
    nonce = bytes(nonce)

    # Decrypt the payload
    # The encrypted payload includes a 16-byte auth tag
    encrypted_payload = packet[payload_start:]
    if len(encrypted_payload) < 16:
        return None

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, encrypted_payload, unprotected_header)
        return plaintext
    except Exception:
        return None


def split_endpoint(text):
    """Parse an endpoint string like '192.168.1.1:443' into (ip, port)."""
    text = text.strip()
    ip, port_str = text.rsplit(":", 1)
    return ip, int(port_str)


def parse_hints(path):
    """Parse the dump-hints.txt file to get memory dump associations."""
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
                ts = int(parts[0].split(":", 1)[1].strip())
                filename = parts[1].split(":", 1)[1].strip()
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


def parse_quic_varint(data, offset):
    """
    Parse a QUIC variable-length integer.
    Returns (value, bytes_consumed) or (None, 0) on failure.
    """
    if offset >= len(data):
        return None, 0
    first = data[offset]
    length = 1 << (first >> 6)
    if offset + length > len(data):
        return None, 0
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[offset + i]
    return value, length


def parse_quic_long_header(packet):
    """
    Parse a QUIC long header packet.
    Returns dict with header info or None on failure.
    """
    if len(packet) < 6:
        return None

    first = packet[0]
    if (first & 0x80) == 0:
        return None  # Not a long header
    if (first & 0x40) == 0:
        return None  # Fixed bit not set

    long_type = (first >> 4) & 0x03
    version = (packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4]

    if version == 0:
        return None  # Version negotiation

    pos = 5
    if pos >= len(packet):
        return None

    dcid_len = packet[pos]
    pos += 1
    if dcid_len > 20 or pos + dcid_len > len(packet):
        return None
    dcid = packet[pos : pos + dcid_len]
    pos += dcid_len

    if pos >= len(packet):
        return None
    scid_len = packet[pos]
    pos += 1
    if scid_len > 20 or pos + scid_len > len(packet):
        return None
    scid = packet[pos : pos + scid_len]
    pos += scid_len

    # For Initial packets, parse token
    token = b""
    if long_type == QUIC_LONG_HEADER_INITIAL:
        token_len, consumed = parse_quic_varint(packet, pos)
        if token_len is None:
            return None
        pos += consumed
        if pos + token_len > len(packet):
            return None
        token = packet[pos : pos + token_len]
        pos += token_len

    # Parse payload length
    payload_len, consumed = parse_quic_varint(packet, pos)
    if payload_len is None:
        return None
    pn_offset = pos + consumed

    return {
        "type": long_type,
        "version": version,
        "dcid": dcid,
        "scid": scid,
        "dcid_len": dcid_len,
        "scid_len": scid_len,
        "token": token,
        "pn_offset": pn_offset,
        "payload_len": payload_len,
    }


def parse_quic_short_header(packet, dcid_len):
    """
    Parse a QUIC short header packet.
    Returns dict with header info or None on failure.
    """
    if len(packet) < 1:
        return None

    first = packet[0]
    if (first & 0x80) != 0:
        return None  # Not a short header
    if (first & 0x40) == 0:
        return None  # Fixed bit not set

    if dcid_len < 0 or dcid_len > 20:
        return None
    if 1 + dcid_len > len(packet):
        return None

    dcid = packet[1 : 1 + dcid_len]
    pn_offset = 1 + dcid_len

    return {
        "type": "short",
        "dcid": dcid,
        "dcid_len": dcid_len,
        "pn_offset": pn_offset,
    }


def parse_tls_extensions(data):
    """Parse TLS extensions from extension data."""
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


def parse_tls_client_hello(data):
    """
    Parse TLS ClientHello message.
    Returns (client_random_hex, cipher_suites) or None.
    """
    if len(data) < 34:
        return None
    # Skip version (2 bytes)
    random = data[2:34]
    idx = 34

    if idx >= len(data):
        return None
    session_id_len = data[idx]
    idx += 1 + session_id_len

    if idx + 2 > len(data):
        return None
    cipher_len = (data[idx] << 8) | data[idx + 1]
    idx += 2

    # Parse cipher suites
    cipher_suites = []
    cipher_end = idx + cipher_len
    if cipher_end > len(data):
        return None
    while idx + 2 <= cipher_end:
        suite = (data[idx] << 8) | data[idx + 1]
        cipher_suites.append(suite)
        idx += 2
    idx = cipher_end

    if idx >= len(data):
        return None
    compression_len = data[idx]
    idx += 1 + compression_len

    return random.hex(), cipher_suites


def parse_tls_server_hello(data):
    """
    Parse TLS ServerHello message.
    Returns (cipher_suite, supported_version) or None.
    """
    if len(data) < 38:
        return None
    idx = 34

    if idx >= len(data):
        return None
    session_id_len = data[idx]
    idx += 1 + session_id_len

    if idx + 3 > len(data):
        return None
    cipher_suite = (data[idx] << 8) | data[idx + 1]
    idx += 3  # cipher suite (2) + compression (1)

    if idx + 2 > len(data):
        return None
    extensions_len = (data[idx] << 8) | data[idx + 1]
    idx += 2
    if idx + extensions_len > len(data):
        return None

    extensions = parse_tls_extensions(data[idx : idx + extensions_len])
    supported_version = None
    ext_data = extensions.get(0x002B)
    if ext_data and len(ext_data) >= 2:
        supported_version = (ext_data[0] << 8) | ext_data[1]

    return cipher_suite, supported_version


def extract_crypto_frames(payload):
    """
    Extract CRYPTO frame data from decrypted QUIC payload.
    Returns list of (offset, data) tuples for reassembly.
    """
    frames = []
    offset = 0
    while offset < len(payload):
        frame_type = payload[offset]
        
        if frame_type == 0x06:  # CRYPTO frame
            offset += 1
            # Parse stream offset varint
            crypto_offset, consumed = parse_quic_varint(payload, offset)
            if crypto_offset is None:
                break
            offset += consumed
            # Parse length varint
            crypto_len, consumed = parse_quic_varint(payload, offset)
            if crypto_len is None:
                break
            offset += consumed
            if offset + crypto_len > len(payload):
                break
            frames.append((crypto_offset, payload[offset : offset + crypto_len]))
            offset += crypto_len
        elif frame_type == 0x00:  # PADDING
            offset += 1
        elif frame_type == 0x01:  # PING
            offset += 1
        elif frame_type == 0x02 or frame_type == 0x03:  # ACK
            # Skip ACK frames - they have complex structure
            break
        else:
            break  # Unknown frame type
    return frames


def reassemble_crypto_stream(crypto_frames):
    """
    Reassemble CRYPTO frames into a contiguous stream.
    crypto_frames is a list of (offset, data) tuples.
    Returns bytes of the reassembled stream.
    """
    if not crypto_frames:
        return b""
    
    # Sort by offset and remove duplicates
    sorted_frames = sorted(crypto_frames, key=lambda x: x[0])
    
    stream = bytearray()
    for offset, data in sorted_frames:
        if offset == len(stream):
            stream.extend(data)
        elif offset < len(stream):
            # Overlap - check if it extends
            end = offset + len(data)
            if end > len(stream):
                stream.extend(data[len(stream) - offset:])
        else:
            # Gap in stream - stop
            break
    
    return bytes(stream)


def scan_for_client_hello_pattern(data):
    """
    Scan raw packet data for ClientHello pattern.
    Look for handshake type 0x01 (ClientHello) followed by valid structure.
    Returns (client_random_hex, cipher_suites) or None.
    """
    # Look for ClientHello pattern: 0x01 followed by 3-byte length
    for i in range(len(data) - 40):
        if data[i] != 0x01:
            continue
        # Try to parse as handshake message
        if i + 4 > len(data):
            continue
        msg_len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
        if msg_len < 34 or msg_len > len(data) - i - 4:
            continue
        # Try to parse the ClientHello
        msg_data = data[i + 4 : i + 4 + msg_len]
        result = parse_tls_client_hello(msg_data)
        if result:
            return result
    return None


def scan_for_server_hello_pattern(data):
    """
    Scan raw packet data for ServerHello pattern.
    Look for handshake type 0x02 (ServerHello) followed by valid structure.
    Returns (cipher_suite, supported_version) or None.
    """
    for i in range(len(data) - 40):
        if data[i] != 0x02:
            continue
        if i + 4 > len(data):
            continue
        msg_len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
        if msg_len < 38 or msg_len > len(data) - i - 4:
            continue
        msg_data = data[i + 4 : i + 4 + msg_len]
        result = parse_tls_server_hello(msg_data)
        if result:
            return result
    return None


def is_quic_packet(payload):
    """Check if payload looks like a QUIC packet."""
    if len(payload) < 5:
        return False
    first = payload[0]
    # Check fixed bit
    if (first & 0x40) == 0:
        return False
    return True


def build_quic_connections(pcap_path):
    """
    Build QUIC connections from pcap file.
    Returns dict mapping connection keys to connection info.
    """
    connections = {}

    # First pass: collect all packets and group by connection
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
                continue

            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue

            payload = bytes(pkt[Raw].load)
            if not payload or not is_quic_packet(payload):
                continue

            udp = pkt[UDP]
            src = Endpoint(ip_layer.src, udp.sport)
            dst = Endpoint(ip_layer.dst, udp.dport)
            ts = float(pkt.time)

            # Parse QUIC packet
            first = payload[0]
            is_long_header = (first & 0x80) != 0

            if is_long_header:
                header = parse_quic_long_header(payload)
                if not header:
                    continue

                dcid = bytes(header["dcid"])
                scid = bytes(header["scid"])

                # Find or create connection
                conn = None
                for key, c in connections.items():
                    if dcid in c["connection_ids"] or scid in c["connection_ids"]:
                        conn = c
                        break

                if conn is None:
                    conn_key = (src, dst, dcid.hex() if dcid else scid.hex())
                    conn = {
                        "connection_ids": set(),
                        "packets": [],
                        "client_random": None,
                        "cipher_suite": None,
                        "client_dir": None,
                        "server_dir": None,
                        "first_seen": ts,
                        "client_hello_ts": None,
                        "server_hello_ts": None,
                        "endpoints": {src, dst},
                        "dcid_len": header["dcid_len"],
                        "client_cid_len": 0,  # Client's CID length (from client's SCID or server's DCID)
                        "server_cid_len": 0,  # Server's CID length (from server's SCID or client's DCID)
                        "initial_dcid": None,
                        "client_crypto_frames": [],  # For reassembly
                        "server_crypto_frames": [],  # For reassembly
                    }
                    connections[conn_key] = conn

                if dcid:
                    conn["connection_ids"].add(dcid)
                if scid:
                    conn["connection_ids"].add(scid)
                conn["endpoints"].add(src)
                conn["endpoints"].add(dst)

                if ts < conn["first_seen"]:
                    conn["first_seen"] = ts

                packet_info = {
                    "data": payload,
                    "timestamp": ts,
                    "src": src,
                    "dst": dst,
                    "header": header,
                    "is_long": True,
                }
                conn["packets"].append(packet_info)

                # For Initial packets, decrypt and collect CRYPTO frames
                if header["type"] == QUIC_LONG_HEADER_INITIAL:
                    # Determine if this is client or server based on DCID presence
                    # Client Initial: has DCID (server's), no/empty SCID typically
                    # Server Initial: empty DCID, has SCID
                    
                    is_client_pkt = len(dcid) > 0 and len(scid) == 0
                    is_server_pkt = len(dcid) == 0 and len(scid) > 0
                    
                    if is_client_pkt:
                        # This is a client packet - use DCID for key derivation
                        # Client's DCID = server's CID, Client's SCID = client's CID
                        conn["server_cid_len"] = header["dcid_len"]  # Server CID length
                        conn["client_cid_len"] = header["scid_len"]  # Client CID length (may be 0)
                        
                        if conn["initial_dcid"] is None:
                            conn["initial_dcid"] = dcid
                            conn["client_dir"] = (src, dst)
                            conn["client_hello_ts"] = ts
                        
                        plaintext = decrypt_initial_payload(payload, conn["initial_dcid"], is_client=True)
                        if plaintext:
                            frames = extract_crypto_frames(plaintext)
                            conn["client_crypto_frames"].extend(frames)
                    
                    elif is_server_pkt and conn["initial_dcid"]:
                        # Server response - use original client DCID
                        # Server's DCID = client's CID, Server's SCID = server's CID
                        if conn["client_cid_len"] == 0:
                            conn["client_cid_len"] = header["dcid_len"]  # Client CID from server's DCID
                        if conn["server_cid_len"] == 0:
                            conn["server_cid_len"] = header["scid_len"]  # Server CID from server's SCID
                        
                        if conn["server_dir"] is None:
                            conn["server_dir"] = (src, dst)
                            conn["server_hello_ts"] = ts
                        
                        plaintext = decrypt_initial_payload(payload, conn["initial_dcid"], is_client=False)
                        if plaintext:
                            frames = extract_crypto_frames(plaintext)
                            conn["server_crypto_frames"].extend(frames)

            else:
                # Short header packet
                for key, conn in connections.items():
                    if src in conn["endpoints"] and dst in conn["endpoints"]:
                        dcid_len = conn.get("dcid_len", 0)
                        header = parse_quic_short_header(payload, dcid_len)
                        if header:
                            packet_info = {
                                "data": payload,
                                "timestamp": ts,
                                "src": src,
                                "dst": dst,
                                "header": header,
                                "is_long": False,
                            }
                            conn["packets"].append(packet_info)
                        break

    # Second pass: reassemble CRYPTO streams and extract handshake info
    for conn in connections.values():
        # Reassemble client CRYPTO stream and extract ClientHello
        if conn["client_crypto_frames"]:
            crypto_stream = reassemble_crypto_stream(conn["client_crypto_frames"])
            if len(crypto_stream) >= 38:
                # Parse TLS handshake
                hs_type = crypto_stream[0]
                hs_len = (crypto_stream[1] << 16) | (crypto_stream[2] << 8) | crypto_stream[3]
                if hs_type == 0x01 and len(crypto_stream) >= 4 + hs_len:
                    msg_data = crypto_stream[4 : 4 + hs_len]
                    result = parse_tls_client_hello(msg_data)
                    if result:
                        conn["client_random"], conn["offered_cipher_suites"] = result
        
        # Reassemble server CRYPTO stream and extract ServerHello
        if conn["server_crypto_frames"]:
            crypto_stream = reassemble_crypto_stream(conn["server_crypto_frames"])
            if len(crypto_stream) >= 42:
                hs_type = crypto_stream[0]
                hs_len = (crypto_stream[1] << 16) | (crypto_stream[2] << 8) | crypto_stream[3]
                if hs_type == 0x02 and len(crypto_stream) >= 4 + hs_len:
                    msg_data = crypto_stream[4 : 4 + hs_len]
                    result = parse_tls_server_hello(msg_data)
                    if result:
                        conn["cipher_suite"], _ = result
        
        # Determine directions if not already set
        if conn["client_dir"] and not conn["server_dir"]:
            src, dst = conn["client_dir"]
            conn["server_dir"] = (dst, src)
        elif conn["server_dir"] and not conn["client_dir"]:
            src, dst = conn["server_dir"]
            conn["client_dir"] = (dst, src)

    return connections


def select_1rtt_packet(conn, direction, dcid_len=0):
    """
    Select a suitable 1-RTT (short header) packet for key extraction.
    Prefer packets shortly after the handshake completes.
    """
    src, dst = direction
    candidates = []
    
    # Minimum packet size for voses: need at least pn_offset + 4 (max PN len) + 16 (sample) + 16 (auth tag)
    # For short header: 1 + dcid_len + 4 + 16 + 16 = 37 + dcid_len minimum
    min_size = 1 + dcid_len + 4 + 16 + 16  # ~40 bytes minimum

    start_time = conn.get("client_hello_ts") or conn.get("first_seen")

    for pkt in conn["packets"]:
        if pkt["src"] != src or pkt["dst"] != dst:
            continue
        if pkt["is_long"]:
            continue  # Skip long header packets
        if len(pkt["data"]) < min_size:
            continue  # Skip packets too small for voses
        candidates.append(pkt)

    if not candidates:
        return None

    # Prefer medium-sized packets (not too small, not too large)
    # Sort by size and pick one in the middle-lower range
    candidates.sort(key=lambda p: len(p["data"]))
    # Pick from the lower third but not the smallest
    idx = max(0, len(candidates) // 4)
    return candidates[idx]


def select_handshake_packet(conn, direction):
    """
    Select a suitable Handshake packet for key extraction.
    """
    src, dst = direction
    candidates = []
    
    # Minimum packet size for QUIC long header with header protection
    # Long header: ~20 bytes header + 4 PN + 16 sample + 16 tag = ~56 bytes minimum
    min_size = 60

    start_time = conn.get("client_hello_ts") or conn.get("first_seen")

    for pkt in conn["packets"]:
        if pkt["src"] != src or pkt["dst"] != dst:
            continue
        if not pkt["is_long"]:
            continue
        header = pkt["header"]
        if header["type"] != QUIC_LONG_HEADER_HANDSHAKE:
            continue
        if len(pkt["data"]) < min_size:
            continue  # Skip packets too small for voses
        if start_time is not None and pkt["timestamp"] is not None:
            if pkt["timestamp"] - start_time > 10.0:
                continue
        candidates.append(pkt)

    if not candidates:
        return None

    # Prefer medium-sized packets
    candidates.sort(key=lambda p: len(p["data"]))
    idx = max(0, len(candidates) // 4)
    return candidates[idx]


def run_voses_quic(voses_path, dump_path, quic_packet, dcid_len, client_random,
                   algorithm, keylog_path, role):
    """
    Run voses in QUIC mode to search for traffic secrets.
    Returns (success, output, return_code, elapsed_time).
    """
    with tempfile.NamedTemporaryFile(prefix="voses_quic_", suffix=".bin", delete=False) as handle:
        handle.write(quic_packet)
        packet_path = handle.name

    pre_size = os.path.getsize(keylog_path) if os.path.exists(keylog_path) else 0

    args = [
        voses_path,
        "--quic",
        "--quic_packet", packet_path,
        "--client_random", client_random,
        "--haystack", dump_path,
        "--memory-alignment", str(MEMORY_ALIGNMENT),
        "--entropy", str(ENTROPY_THRESHOLD),
        "--key-log", keylog_path,
        "--algorithm", algorithm,
    ]

    # Add dcid_len for short header packets
    if dcid_len >= 0:
        args.extend(["--dcid_len", str(dcid_len)])

    args.append("--client" if role == "client" else "--server")

    try:
        start_time = time.perf_counter()
        result = subprocess.run(args, capture_output=True, text=True)
        elapsed = time.perf_counter() - start_time
    finally:
        os.unlink(packet_path)

    post_size = os.path.getsize(keylog_path) if os.path.exists(keylog_path) else 0
    output = (result.stdout or "") + (result.stderr or "")
    success = post_size > pre_size
    return success, output, result.returncode, elapsed


def attempt_quic_secret(conn, direction, dump_path, keylog_path, role, voses_path, algorithm):
    """
    Attempt to extract QUIC traffic secret for a given direction.
    """
    # Determine the correct DCID length for this direction
    # For 1-RTT packets:
    #   - Client->Server: DCID = server's CID -> use server_cid_len
    #   - Server->Client: DCID = client's CID -> use client_cid_len
    if role == "client":
        # Client sending to server, DCID is server's CID
        dcid_len_for_dir = conn.get("server_cid_len", 0)
    else:
        # Server sending to client, DCID is client's CID
        dcid_len_for_dir = conn.get("client_cid_len", 0)
    
    # First try 1-RTT packets (short header)
    packet = select_1rtt_packet(conn, direction, dcid_len_for_dir)
    dcid_len = -1

    if packet:
        dcid_len = dcid_len_for_dir

    if not packet:
        print(f"[!] No suitable QUIC packets found for {role} direction.")
        return False

    src, dst = direction
    packet_type = "1-RTT" if not packet["is_long"] else "Handshake"
    print(f"[*] {role} scan: QUIC ({packet_type}) | connection: {src.ip}:{src.port} -> {dst.ip}:{dst.port}")
    print(f"    Selected packet len={len(packet['data'])}, dcid_len={dcid_len}")

    success, output, code, elapsed = run_voses_quic(
        voses_path,
        dump_path,
        packet["data"],
        dcid_len if not packet["is_long"] else -1,
        conn["client_random"],
        algorithm,
        keylog_path,
        role,
    )

    if code != 0:
        print(output.strip())
        print(f"[!] voses exited with code {code} for {role} scan.")

    if success:
        print(f"[+] {role} traffic secret found. (took {elapsed:.2f}s)")
        return True

    print(f"[!] Failed to find {role} traffic secret. (took {elapsed:.2f}s)")
    return False


def match_connection_by_hint(connections, hint):
    """
    Find a QUIC connection matching the given hint.
    """
    candidates = []

    for conn_key, conn in connections.items():
        if conn["client_random"] is None:
            continue

        # Check if endpoints match
        if hint["src"] in conn["endpoints"] and hint["dst"] in conn["endpoints"]:
            candidates.append(conn)

    if not candidates:
        return None

    hint_ts = hint["timestamp_ms"] / 1000.0

    def time_for(conn):
        return conn["client_hello_ts"] or conn["server_hello_ts"] or conn["first_seen"] or hint_ts

    return min(candidates, key=lambda c: abs(time_for(c) - hint_ts))


def get_connection_time_range(conn):
    """Return the observed time range for a QUIC connection."""
    packet_times = [
        pkt["timestamp"]
        for pkt in conn.get("packets", [])
        if pkt.get("timestamp") is not None
    ]
    start_time = conn.get("client_hello_ts") or conn.get("first_seen")
    if start_time is None and packet_times:
        start_time = min(packet_times)

    end_time = max(packet_times) if packet_times else start_time
    return start_time, end_time


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


def select_quic_algorithm(conn):
    """Select a voses algorithm for a parsed QUIC connection."""
    algorithm = QUIC_CIPHER_SUITES.get(conn.get("cipher_suite"))
    if algorithm:
        return algorithm

    for suite in conn.get("offered_cipher_suites", []):
        if suite in QUIC_CIPHER_SUITES:
            return QUIC_CIPHER_SUITES[suite]

    return "gcm_128_sha_256"


def get_args():
    parser = argparse.ArgumentParser(
        description="Extract QUIC TLS 1.3 traffic secrets from memory dumps using voses."
    )
    parser.add_argument("--pcap", required=True, help="Path to pcapng capture file.")
    parser.add_argument("--hints", required=True, help="Path to dump-hints.txt file.")
    parser.add_argument("--dumps", required=True, help="Directory containing memory dumps.")
    parser.add_argument("--keylog", required=True, help="Output key log file path.")
    parser.add_argument(
        "--voses",
        default=os.path.join(os.getcwd(), "voses"),
        help="Path to voses binary (default: ./voses).",
    )
    parser.add_argument(
        "--use-closest-dump",
        action="store_true",
        help=(
            "If no endpoint-matched hint is available for a QUIC connection, "
            "search the first existing dump after that connection ends."
        ),
    )
    return parser.parse_args()


def main():
    args = get_args()

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
        print(f"Error: voses binary not found or not executable: {args.voses}", file=sys.stderr)
        return 1

    keylog_dir = os.path.dirname(args.keylog)
    if keylog_dir and not os.path.exists(keylog_dir):
        os.makedirs(keylog_dir)

    start_time = time.time()

    hints = parse_hints(args.hints)
    if not hints:
        print("Error: no usable hints found.", file=sys.stderr)
        return 1

    print(f"Building QUIC connections from {args.pcap}...")
    connections = build_quic_connections(args.pcap)

    # Filter connections with client_random (successful handshake detection)
    valid_connections = [c for c in connections.values() if c["client_random"] is not None]
    if not valid_connections:
        print("No QUIC connections with detected ClientHello found in capture.")
        return 0

    print(f"Found {len(valid_connections)} QUIC connections with detected handshakes.")

    # Build list of sessions to process from hints
    sessions = []
    processed_connections = set()  # Track connections we've already queued
    
    for hint in hints:
        if hint["proto"].upper() != "UDP":
            continue

        conn = match_connection_by_hint(connections, hint)
        if not conn:
            continue

        if conn["client_random"] is None:
            continue

        # Skip if we've already processed this connection
        conn_id = conn["client_random"]
        if conn_id in processed_connections:
            continue

        algorithm = select_quic_algorithm(conn)

        dump_path = hint["file"]
        if not os.path.isabs(dump_path):
            dump_path = os.path.join(args.dumps, dump_path)
        if not os.path.exists(dump_path):
            continue

        if not conn["client_dir"] or not conn["server_dir"]:
            continue

        client_src, client_dst = conn["client_dir"]
        conn_str = f"{client_src.ip}:{client_src.port} -> {client_dst.ip}:{client_dst.port}"
        
        processed_connections.add(conn_id)
        sessions.append({
            "conn": conn,
            "dump_path": dump_path,
            "algorithm": algorithm,
            "conn_str": conn_str,
            "hint": hint,
            "closest_dump": False,
        })

    if args.use_closest_dump:
        for conn in valid_connections:
            conn_id = conn["client_random"]
            if conn_id in processed_connections:
                continue
            if not conn["client_dir"] or not conn["server_dir"]:
                continue

            start_ts, end_ts = get_connection_time_range(conn)
            first_after = find_first_dump_after_timeframe(hints, start_ts, end_ts, args.dumps)
            if not first_after:
                continue

            dump_path, dump_ts, distance = first_after
            client_src, client_dst = conn["client_dir"]
            conn_str = f"{client_src.ip}:{client_src.port} -> {client_dst.ip}:{client_dst.port}"
            processed_connections.add(conn_id)
            sessions.append({
                "conn": conn,
                "dump_path": dump_path,
                "algorithm": select_quic_algorithm(conn),
                "conn_str": conn_str,
                "hint": None,
                "closest_dump": True,
                "closest_distance": distance,
                "closest_ts": dump_ts,
            })

    if not sessions:
        print("No valid QUIC sessions to process.")
        return 0

    print(f"\n{'='*60}")
    print(f"Processing {len(sessions)} QUIC sessions")
    print(f"{'='*60}\n")

    # Track results
    successful_extractions = []
    failed_extractions = []

    for idx, session in enumerate(sessions):
        conn = session["conn"]
        conn_str = session["conn_str"]
        dump_path = session["dump_path"]
        algorithm = session["algorithm"]
        
        print(f"\n[Session {idx+1}/{len(sessions)}] {conn_str}")
        print(f"  Algorithm: {algorithm}")
        print(f"  Dump: {os.path.basename(dump_path)}")
        if session.get("closest_dump"):
            print(
                "  After-session fallback: "
                f"{session['closest_distance']:.3f}s after observed connection end"
            )
        print(f"  Client CID len: {conn.get('client_cid_len', 0)}, Server CID len: {conn.get('server_cid_len', 0)}")

        client_ok = attempt_quic_secret(
            conn, conn["client_dir"], dump_path, args.keylog, "client",
            args.voses, algorithm
        )
        
        server_ok = attempt_quic_secret(
            conn, conn["server_dir"], dump_path, args.keylog, "server",
            args.voses, algorithm
        )

        if client_ok and server_ok:
            successful_extractions.append((conn_str, "client+server"))
        elif client_ok:
            successful_extractions.append((conn_str, "client"))
            failed_extractions.append((conn_str, "server"))
        elif server_ok:
            successful_extractions.append((conn_str, "server"))
            failed_extractions.append((conn_str, "client"))
        else:
            failed_extractions.append((conn_str, "client+server"))

    # Print summary
    print("\n" + "=" * 60)
    print("EXTRACTION SUMMARY")
    print("=" * 60)

    if successful_extractions:
        print(f"\n[+] Successful extractions ({len(successful_extractions)}):")
        for conn, roles in successful_extractions:
            print(f"    {conn} [{roles}]")
    else:
        print("\n[!] No successful extractions.")

    if failed_extractions:
        print(f"\n[-] Failed extractions ({len(failed_extractions)}):")
        for conn, roles in failed_extractions:
            print(f"    {conn} [{roles}]")
    else:
        print("\n[+] No failed extractions.")

    elapsed_time = time.time() - start_time
    print(f"\nTotal runtime: {elapsed_time:.2f} seconds")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
