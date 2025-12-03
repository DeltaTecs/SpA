#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decompose_pcap.py

Read a pcap file and split it into per-TCP/UDP address-tuple pcap files.

Each output file corresponds to a tuple: (PROTO, SRC, SPORT, DST, DPORT) and
contains only the packets matching that exact tuple (direction preserved).

Usage:
    python decompose_pcap.py -i input.pcap -o outdir

"""
from __future__ import annotations

import argparse
import os
import re
import struct
from collections import defaultdict
from pathlib import Path
from typing import Dict, Tuple

try:
    # scapy import
    from scapy.all import PcapReader, PcapWriter, TCP, UDP, IP, IPv6
except Exception as e:  # pragma: no cover - runtime dependency
    raise ImportError(
        "Scapy is required. Install with: pip install scapy\nOriginal error: %s" % e
    )


def _safe_filename_part(s: str) -> str:
    # Replace characters that would be problematic in filenames
    s = s.replace('%', '')
    # Keep only a safe subset
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def _update_pcap_timestamp(pcap_path: str, ts_sec: int, ts_usec: int) -> None:
    """
    Update the global timestamp in a pcap file header.
    
    The timestamp is stored at bytes 4-7 (seconds) and 8-11 (microseconds).
    """
    try:
        with open(pcap_path, 'r+b') as f:
            # Read magic number to determine byte order
            f.seek(0)
            magic_bytes = f.read(4)
            magic = struct.unpack('<I', magic_bytes)[0]
            is_little_endian = (magic == 0xa1b2c3d4)
            endian = '<' if is_little_endian else '>'
            
            # Write timestamp at bytes 4-11
            f.seek(4)
            f.write(struct.pack(f'{endian}II', ts_sec, ts_usec))
    except Exception:
        # If we can't update the timestamp, continue anyway
        pass


def tuple_to_filename(proto: str, src: str, sport: int, dst: str, dport: int) -> str:
    src_s = _safe_filename_part(src)
    dst_s = _safe_filename_part(dst)
    return f"{proto}_{src_s}-{sport}_x_{dst_s}-{dport}.pcap"


def normalize_tuple_key(proto: str, src: str, sport: int, dst: str, dport: int) -> Tuple:
    """
    Create a normalized tuple key that treats bidirectional flows as the same.
    
    Returns a canonical key where the smaller address/port pair comes first,
    ensuring both directions of a flow use the same key.
    """
    pair1 = (src, sport)
    pair2 = (dst, dport)
    
    # Ensure consistent ordering: smaller address comes first
    # Compare as tuples (address, port)
    if (pair1 > pair2):
        pair1, pair2 = pair2, pair1
    
    return (proto, pair1[0], pair1[1], pair2[0], pair2[1])


def normalized_tuple_to_filename(normalized_key: Tuple) -> str:
    """Generate filename from a normalized tuple key."""
    proto, src, sport, dst, dport = normalized_key
    src_s = _safe_filename_part(src)
    dst_s = _safe_filename_part(dst)
    return f"{proto}_{src_s}-{sport}_to_{dst_s}-{dport}.pcap"


def separate_pcap(input_pcap: str, output_dir: str, include_others: bool = False) -> Dict[Tuple, int]:
    """
    Read `input_pcap`, split into files under `output_dir` by (proto, src, sport, dst, dport).

    Returns a dict mapping tuple to packet counts written.
    """
    input_path = Path(input_pcap)
    outdir = Path(output_dir)
    if not input_path.exists():
        raise FileNotFoundError(f"Input pcap not found: {input_path}")
    outdir.mkdir(parents=True, exist_ok=True)

    # Read the pcap header to preserve timestamp
    with open(str(input_path), 'rb') as f:
        pcap_header = f.read(24)  # Global header is 24 bytes
        # Timestamp is in bytes 4-7 (seconds) and 8-11 (microseconds) in native byte order
        if len(pcap_header) >= 12:
            # Check magic number to determine byte order (0xa1b2c3d4 = little endian, 0xd4c3b2a1 = big endian)
            magic = struct.unpack('<I', pcap_header[:4])[0]
            is_little_endian = (magic == 0xa1b2c3d4)
            endian = '<' if is_little_endian else '>'
            ts_sec, ts_usec = struct.unpack(f'{endian}II', pcap_header[4:12])
            pcap_timestamp = ts_sec + (ts_usec / 1e6)
        else:
            pcap_timestamp = None

    writers: Dict[Tuple, PcapWriter] = {}
    counts: Dict[Tuple, int] = defaultdict(int)
    others_writer = None

    def get_writer_for_key(key_tuple):
        if key_tuple in writers:
            return writers[key_tuple]
        fname = normalized_tuple_to_filename(key_tuple)
        path = outdir / fname
        w = PcapWriter(str(path), append=False, sync=True)
        writers[key_tuple] = w
        return w

    with PcapReader(str(input_path)) as reader:
        for pkt in reader:
            try:
                # Prefer TCP, then UDP
                if pkt.haslayer(TCP):
                    l3 = None
                    if pkt.haslayer(IP):
                        l3 = pkt[IP]
                    elif pkt.haslayer(IPv6):
                        l3 = pkt[IPv6]
                    if l3 is None:
                        # no L3 -> treat as other
                        if include_others:
                            if others_writer is None:
                                others_writer = PcapWriter(str(outdir / "others.pcap"), append=True, sync=True)
                            others_writer.write(pkt)
                        continue
                    key = normalize_tuple_key("TCP", l3.src, int(pkt[TCP].sport), l3.dst, int(pkt[TCP].dport))
                    w = get_writer_for_key(key)
                    w.write(pkt)
                    counts[key] += 1
                elif pkt.haslayer(UDP):
                    l3 = None
                    if pkt.haslayer(IP):
                        l3 = pkt[IP]
                    elif pkt.haslayer(IPv6):
                        l3 = pkt[IPv6]
                    if l3 is None:
                        if include_others:
                            if others_writer is None:
                                others_writer = PcapWriter(str(outdir / "others.pcap"), append=True, sync=True)
                            others_writer.write(pkt)
                        continue
                    key = normalize_tuple_key("UDP", l3.src, int(pkt[UDP].sport), l3.dst, int(pkt[UDP].dport))
                    w = get_writer_for_key(key)
                    w.write(pkt)
                    counts[key] += 1
                else:
                    if include_others:
                        if others_writer is None:
                            others_writer = PcapWriter(str(outdir / "others.pcap"), append=True, sync=True)
                        others_writer.write(pkt)
            except Exception:
                # Be resilient to odd packets; skip any packet that causes a problem
                # (don't crash the whole run)
                continue

    # close writers
    for w in writers.values():
        try:
            w.close()
        except Exception:
            pass
    if others_writer is not None:
        try:
            others_writer.close()
        except Exception:
            pass

    # Apply original pcap timestamp to output files
    if pcap_timestamp is not None:
        ts_sec = int(pcap_timestamp)
        ts_usec = int((pcap_timestamp - ts_sec) * 1e6)
        
        for key_tuple in writers.keys():
            fname = normalized_tuple_to_filename(key_tuple)
            path = outdir / fname
            _update_pcap_timestamp(str(path), ts_sec, ts_usec)
        
        if others_writer is not None:
            _update_pcap_timestamp(str(outdir / "others.pcap"), ts_sec, ts_usec)

    return counts


def main():
    parser = argparse.ArgumentParser(description="Split a pcap into per-TCP/UDP address-tuple pcaps")
    parser.add_argument("-i", "--input", required=True, help="Input pcap file")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory for per-tuple pcaps")
    parser.add_argument("--include-others", action="store_true", help="Also write non-TCP/UDP packets to others.pcap")
    args = parser.parse_args()

    counts = separate_pcap(args.input, args.output_dir, include_others=args.include_others)

    # Print summary
    total = sum(counts.values())
    print(f"Wrote {total} packets into {len(counts)} tuple files under {args.output_dir}")
    if counts:
        print("Per-file counts (tuple -> packets):")
        for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            proto, src, sport, dst, dport = k
            print(f"  {proto} {src}:{sport} -> {dst}:{dport} : {v}")


if __name__ == "__main__":
    main()
