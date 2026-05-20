#!/usr/bin/env python3
"""
Post-processing script to prune bulky HTTP media payload packets for a recording.

Given a recording_id, the script:
1) Finds HTTP headers whose Content-Type is an image/* or video/*.
2) Keeps the first packet linked to that header (the one carrying the request/response header).
3) Deletes later packets for that header that only carry application payload bytes.
"""
import argparse
import logging
import re
import gzip
import zlib
import math
import collections
from typing import List, Tuple, Optional, Dict

try:
    import brotli
except ImportError:
    brotli = None

import psycopg2
from discord_zstd_decompression import decompress_discord_zstd


MEDIA_PREFIXES = ("image/", "video/")


def parse_headers(header_text: str) -> Dict[str, str]:
    """Parse raw HTTP headers into a dictionary."""
    headers = {}
    if not header_text:
        return headers
    
    lines = header_text.splitlines()
    # Skip the first line (Request/Response line)
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()
    return headers



def is_media_header(text_header: str) -> bool:
    """
    Check if an HTTP header string declares a media content type.
    Only matches on the Content-Type header to avoid false positives
    from Accept/Accept-Encoding etc.
    """
    if not text_header:
        return False

    match = re.search(r"content-type\s*:\s*([^\r\n;]+)", text_header, flags=re.IGNORECASE)
    if not match:
        return False

    content_type = match.group(1).strip().lower()
    return any(content_type.startswith(prefix) for prefix in MEDIA_PREFIXES)


def find_media_headers(conn, recording_id: int) -> List[Tuple[int, str]]:
    """Return header_information_ids for media responses within the recording."""
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT DISTINCT h.header_information_id, h.text_header
            FROM http_header_information h
            JOIN packet_header_information phi ON phi.header_information_id = h.header_information_id
            JOIN packet p ON p.packet_id = phi.packet_id
            WHERE p.recording_id = %s
              AND h.text_header IS NOT NULL
            """,
            (recording_id,),
        )
        return [(hid, text) for hid, text in cur.fetchall() if is_media_header(text or "")]
    finally:
        cur.close()


def decompress_http_payloads(conn, recording_id: int) -> int:
    """
    Decompress HTTP payloads for the given recording.
    """

    # Create map of all http streams that use compression
    # map header_information_id -> [encoding, byte[]]

    # get a list of all all http_header_information that have content-encoding gzip/deflate/br
    headers = []
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT DISTINCT h.header_information_id, h.text_header
            FROM http_header_information h
            JOIN packet_header_information phi ON phi.header_information_id = h.header_information_id
            JOIN packet p ON p.packet_id = phi.packet_id
            WHERE p.recording_id = %s
              AND h.text_header IS NOT NULL
            """,
            (recording_id,),
        )

        for hid, text in cur.fetchall():
            h_dict = parse_headers(text)
            encoding = h_dict.get("content-encoding", "").lower()
            if encoding in ("gzip", "deflate", "br"):
                headers.append((hid, encoding))
    finally:
        cur.close()

    class EncodingProcessor:
        def __init__(self, encoding):
            self.encoding = encoding
            if encoding == "gzip":
                self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            elif encoding == "deflate":
                self.decompressor = zlib.decompressobj()
            elif encoding == "br" and brotli is not None:
                self.decompressor = brotli.Decompressor()
            else:
                self.decompressor = None

        def process(self, chunk: bytes) -> bytes:
            if not self.decompressor or not chunk:
                return b""
            try:
                if self.encoding == "br":
                    return self.decompressor.process(chunk)
                else:
                    return self.decompressor.decompress(chunk)
            except Exception:
                return b""

    processors = {hid: EncodingProcessor(enc) for hid, enc in headers}

    if not processors:
        return 0

    decompressed_packets_count = 0
    header_ids = list(processors.keys())

    cur = conn.cursor()
    update_cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT p.packet_id, phi.header_information_id, p.clear_application_payload
            FROM packet p
            JOIN packet_header_information phi ON phi.packet_id = p.packet_id
            WHERE p.recording_id = %s
              AND phi.header_information_id = ANY(%s)
              AND p.clear_application_payload IS NOT NULL
            ORDER BY p.number ASC
            """,
            (recording_id, header_ids),
        )

        for packet_id, hid, payload in cur.fetchall():
            if not payload:
                continue
            
            chunk = bytes(payload)
            processor = processors.get(hid)
            if processor:
                decompressed_data = processor.process(chunk)
                if decompressed_data:
                    update_cur.execute(
                        "UPDATE packet SET clear_application_payload = %s WHERE packet_id = %s",
                        (decompressed_data, packet_id)
                    )
                    decompressed_packets_count += 1

                    enc_map = {"br": "Brotli", "gzip": "Gzip", "deflate": "Deflate"}
                    enc_name = enc_map.get(processor.encoding, processor.encoding)

                    update_cur.execute(
                        "INSERT INTO packet_processing_tag (packet_id, step) VALUES (%s, %s)",
                        (packet_id, f"Decompressed payload with {enc_name}.")
                    )
        conn.commit()
    finally:
        cur.close()
        update_cur.close()

    return decompressed_packets_count


def delete_encrypted_packets_without_payload(conn, recording_id: int) -> int:
    """
    Delete packets where the final protocol is QUIC, TLS, or DTLS
    and there is no clear_application_payload.
    """
    cur = conn.cursor()
    try:
        # Get protocol IDs for encrypted protocols
        cur.execute(
            "SELECT protocol_id FROM protocol WHERE name IN ('QUIC', 'TLS', 'DTLS')"
        )
        encrypted_proto_ids = [row[0] for row in cur.fetchall()]
        
        if not encrypted_proto_ids:
            return 0

        # Delete packets
        # We check if the last element of protocol_ids is in our list of encrypted protocols
        # and if clear_application_payload is missing or empty.
        cur.execute(
            """
            DELETE FROM packet
            WHERE recording_id = %s
              AND protocol_ids[array_length(protocol_ids, 1)] = ANY(%s)
              AND (clear_application_payload IS NULL OR octet_length(clear_application_payload) = 0)
            """,
            (recording_id, encrypted_proto_ids)
        )
        deleted_count = cur.rowcount

        if deleted_count > 0:
            cur.execute(
                "INSERT INTO recording_processing_tag (recording_id, step) VALUES (%s, %s)",
                (recording_id, f"Removed {deleted_count} packets without payload.")
            )

        conn.commit()
        return deleted_count
    finally:
        cur.close()


def prune_media_payload_packets(conn, recording_id: int) -> Tuple[int, int]:
    """
    Delete packets that only carry HTTP media payload for the given recording.

    Returns:
        Tuple[media_header_count, deleted_packet_count]
    """
    media_headers = find_media_headers(conn, recording_id)
    if not media_headers:
        return 0, 0

    deleted_packets = 0
    cur = conn.cursor()
    try:
        for header_id, _ in media_headers:
            cur.execute(
                """
                SELECT p.packet_id,
                       p.number,
                       COALESCE(octet_length(p.clear_application_payload), 0) AS payload_len
                FROM packet p
                JOIN packet_header_information phi ON phi.packet_id = p.packet_id
                WHERE phi.header_information_id = %s
                  AND p.recording_id = %s
                ORDER BY p.number ASC, p.packet_id ASC
                """,
                (header_id, recording_id),
            )
            packets = cur.fetchall()
            if not packets:
                continue

            # Keep the first packet (the one that carried the request/response headers)
            keep_packet_id = packets[0][0]

            delete_ids = [pid for pid, _, payload_len in packets[1:] if payload_len > 0]
            if not delete_ids:
                continue

            cur.execute("DELETE FROM packet WHERE packet_id = ANY(%s)", (delete_ids,))
            deleted_packets += cur.rowcount
            logging.debug(
                "Header %s: kept packet %s, removed %d payload packets",
                header_id,
                keep_packet_id,
                cur.rowcount,
            )

        if deleted_packets > 0:
            cur.execute(
                "INSERT INTO recording_processing_tag (recording_id, step) VALUES (%s, %s)",
                (recording_id, f"removed {deleted_packets} HTTP Media packets")
            )

        conn.commit()
    finally:
        cur.close()

    return len(media_headers), deleted_packets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Post-process recording: Decompress HTTP payloads and remove bulky media packets."
    )
    parser.add_argument(
        "--recording-id",
        type=int,
        required=True,
        help="Recording ID to post-process",
    )
    parser.add_argument("--db-host", default="localhost", help="Database host")
    parser.add_argument("--db-port", type=int, default=5432, help="Database port")
    parser.add_argument("--db-name", default="main", help="Database name")
    parser.add_argument("--db-user", default="dbuser", help="Database user")
    parser.add_argument("--db-password", default="dbuser", help="Database password")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--prune-encrypted-control",
        action="store_true",
        help="Delete encrypted packets (QUIC, TLS, DTLS) that have no clear application payload",
    )
    return parser.parse_args()


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte array."""
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_packet_entropy(conn, recording_id: int) -> int:
    """
    For every packet with plain application payload, calculate the shannon entropy
    of the entire plain payload byte array and write the value to the packet table.
    """
    cur = conn.cursor()
    count = 0
    try:
        cur.execute(
            """
            SELECT packet_id, clear_application_payload
            FROM packet
            WHERE recording_id = %s
              AND clear_application_payload IS NOT NULL
              AND length(clear_application_payload) > 0
            """,
            (recording_id,)
        )
        rows = cur.fetchall()
        
        for packet_id, payload in rows:
            # payload is memoryview or bytes in psycopg2
            if isinstance(payload, memoryview):
                payload = bytes(payload)
                
            entropy = calculate_shannon_entropy(payload)
            
            cur.execute(
                "UPDATE packet SET entropy = %s WHERE packet_id = %s",
                (entropy, packet_id)
            )
            count += 1
            
        conn.commit()
        logging.info("Updated %d packets with entropy values.", count)
        return count
    finally:
        cur.close()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    conn = psycopg2.connect(
        host=args.db_host,
        port=args.db_port,
        dbname=args.db_name,
        user=args.db_user,
        password=args.db_password,
    )

    try:
        logging.info("Starting post-processing for recording_id=%s", args.recording_id)
        
        # 1. Decompress payloads
        decompress_count = decompress_http_payloads(conn, args.recording_id)

        # 2. Delete encrypted packets without payload
        deleted_encrypted = 0
        if args.prune_encrypted_control:
            deleted_encrypted = delete_encrypted_packets_without_payload(conn, args.recording_id)
        
        # 3. Prune media payloads
        media_header_count, deleted_packets = prune_media_payload_packets(conn, args.recording_id)
        
        # 4. Tag entropy
        entropy_tagged_count = calculate_packet_entropy(conn, args.recording_id)

        # 5. Discord Zstd Decompression
        logging.info("Running Discord Zstd Decompression...")
        decompress_discord_zstd(conn, args.recording_id)
        
        logging.info(
            "Finished post-processing: %d packets decompressed, %d encrypted packets deleted, %d media headers inspected, %d media packets deleted, %d packets updated with entropy",
            decompress_count,
            deleted_encrypted,
            media_header_count,
            deleted_packets,
            entropy_tagged_count,
        )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
