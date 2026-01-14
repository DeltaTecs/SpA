#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict, namedtuple

from scapy.all import PcapReader, TCP, IP, IPv6, Raw

MEMORY_ALIGNMENT = 1
ENTROPY_THRESHOLD = 2.0
TLS13_CIPHER_SUITES = {
    0x1301: "gcm_128_sha_256",  # TLS_AES_128_GCM_SHA256
    0x1302: "gcm_256_sha_384",  # TLS_AES_256_GCM_SHA384
}
TLS_RECORD_TYPES = {20, 21, 22, 23}
TLS_VERSIONS = {0x0301, 0x0302, 0x0303, 0x0304}
TLS_MAX_RECORD_LEN = 18432  # 2^14 + 2048 allowance

Endpoint = namedtuple("Endpoint", ["ip", "port"])


def split_endpoint(text):
    text = text.strip()
    ip, port_str = text.rsplit(":", 1)
    return ip, int(port_str)


def parse_hints(path):
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


def reassemble_tcp_stream(segments):
    segments = sorted(segments, key=lambda item: item[0])
    chunks = []
    current = bytearray()
    markers = []
    start_seq = None
    expected_seq = None

    for seq, ts, payload in segments:
        if not payload:
            continue
        if start_seq is None:
            start_seq = seq
            expected_seq = seq
        if seq > expected_seq:
            if current:
                chunks.append((start_seq, bytes(current), markers))
            current = bytearray()
            markers = []
            start_seq = seq
            expected_seq = seq
        if seq < expected_seq:
            overlap = expected_seq - seq
            if overlap >= len(payload):
                continue
            payload = payload[overlap:]
            seq = expected_seq
        markers.append((len(current), ts))
        current.extend(payload)
        expected_seq = seq + len(payload)

    if current:
        chunks.append((start_seq, bytes(current), markers))
    return chunks


def timestamp_for_offset(markers, offset):
    if not markers:
        return None
    ts = markers[0][1]
    for marker_offset, marker_ts in markers:
        if marker_offset > offset:
            break
        ts = marker_ts
    return ts


def parse_tls_records(stream, markers):
    records = []
    offset = 0
    stream_len = len(stream)
    while offset + 5 <= stream_len:
        content_type = stream[offset]
        version = (stream[offset + 1] << 8) | stream[offset + 2]
        length = (stream[offset + 3] << 8) | stream[offset + 4]
        record_len = 5 + length

        if content_type not in TLS_RECORD_TYPES or version not in TLS_VERSIONS:
            offset += 1
            continue
        if record_len <= 5 or record_len > TLS_MAX_RECORD_LEN:
            offset += 1
            continue
        if offset + record_len > stream_len:
            break

        record = stream[offset : offset + record_len]
        records.append(
            {
                "type": content_type,
                "version": version,
                "data": record,
                "timestamp": timestamp_for_offset(markers, offset),
            }
        )
        offset += record_len
    return records


def parse_handshake_messages(buffer):
    messages = []
    offset = 0
    while offset + 4 <= len(buffer):
        msg_type = buffer[offset]
        msg_len = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]
        total_len = 4 + msg_len
        if offset + total_len > len(buffer):
            break
        msg_data = buffer[offset + 4 : offset + total_len]
        messages.append((msg_type, msg_data))
        offset += total_len
    return messages, buffer[offset:]


def parse_extensions(data):
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
    if len(data) < 34:
        return None
    random = data[2:34]
    idx = 34
    if idx >= len(data):
        return None
    session_id_len = data[idx]
    idx += 1 + session_id_len
    if idx + 2 > len(data):
        return None
    cipher_len = (data[idx] << 8) | data[idx + 1]
    idx += 2 + cipher_len
    if idx >= len(data):
        return None
    compression_len = data[idx]
    idx += 1 + compression_len
    if idx + 2 > len(data):
        return None
    extensions_len = (data[idx] << 8) | data[idx + 1]
    idx += 2
    if idx + extensions_len > len(data):
        return None
    extensions = parse_extensions(data[idx : idx + extensions_len])
    supported_versions = []
    ext_data = extensions.get(0x002B)
    if ext_data and len(ext_data) >= 1:
        list_len = ext_data[0]
        for i in range(1, min(len(ext_data), 1 + list_len), 2):
            if i + 1 < len(ext_data):
                supported_versions.append((ext_data[i] << 8) | ext_data[i + 1])
    return random.hex(), supported_versions


def parse_server_hello(data):
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
    extensions = parse_extensions(data[idx : idx + extensions_len])
    supported_version = None
    ext_data = extensions.get(0x002B)
    if ext_data and len(ext_data) >= 2:
        supported_version = (ext_data[0] << 8) | ext_data[1]
    return cipher_suite, supported_version


def reverse_dir(dir_key):
    return (dir_key[1], dir_key[0])


def build_flows(pcap_path):
    flows = {}
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue
            payload = bytes(pkt[Raw].load)
            if not payload:
                continue
            tcp = pkt[TCP]
            src = Endpoint(ip_layer.src, tcp.sport)
            dst = Endpoint(ip_layer.dst, tcp.dport)
            ts = float(pkt.time)
            conn_key = tuple(sorted((src, dst), key=lambda e: (e.ip, e.port)))
            flow = flows.get(conn_key)
            if not flow:
                flow = {
                    "segments": defaultdict(list),
                    "records": {},
                    "client_dir": None,
                    "server_dir": None,
                    "client_random": None,
                    "cipher_suite": None,
                    "tls13": False,
                    "client_hello_ts": None,
                    "server_hello_ts": None,
                    "first_seen": ts,
                }
                flows[conn_key] = flow
            if ts < flow["first_seen"]:
                flow["first_seen"] = ts
            dir_key = (src, dst)
            flow["segments"][dir_key].append((tcp.seq, ts, payload))

    for flow in flows.values():
        for dir_key, segments in flow["segments"].items():
            records = []
            chunks = reassemble_tcp_stream(segments)
            for _start_seq, stream, markers in chunks:
                records.extend(parse_tls_records(stream, markers))
            flow["records"][dir_key] = records

    return flows


def extract_handshake_info(flow):
    for dir_key, records in flow["records"].items():
        handshake_buffer = bytearray()
        for record in records:
            if record["type"] != 22:
                continue
            handshake_buffer.extend(record["data"][5:])
            messages, remaining = parse_handshake_messages(handshake_buffer)
            handshake_buffer = bytearray(remaining)
            for msg_type, msg_data in messages:
                if msg_type == 1 and flow["client_random"] is None:
                    parsed = parse_client_hello(msg_data)
                    if parsed:
                        client_random, _supported = parsed
                        flow["client_random"] = client_random
                        flow["client_dir"] = dir_key
                        if flow["client_hello_ts"] is None:
                            flow["client_hello_ts"] = record["timestamp"]
                elif msg_type == 2 and flow["cipher_suite"] is None:
                    parsed = parse_server_hello(msg_data)
                    if parsed:
                        cipher_suite, supported_version = parsed
                        flow["cipher_suite"] = cipher_suite
                        if cipher_suite in TLS13_CIPHER_SUITES:
                            flow["tls13"] = True
                        if supported_version == 0x0304:
                            flow["tls13"] = True
                        flow["server_dir"] = dir_key
                        if flow["server_hello_ts"] is None:
                            flow["server_hello_ts"] = record["timestamp"]

    if flow["client_dir"] and not flow["server_dir"]:
        flow["server_dir"] = reverse_dir(flow["client_dir"])
    if flow["server_dir"] and not flow["client_dir"]:
        flow["client_dir"] = reverse_dir(flow["server_dir"])


def list_app_records(records):
    app_records = []
    filtered_records = [r for r in records if r["type"] == 23]
    for i, record in enumerate(filtered_records):
        if i == 0:
            epoch = 0
            sequence = 0
        else:
            epoch = 1
            sequence = i - 1
        app_records.append(
            {
                "data": record["data"],
                "timestamp": record["timestamp"],
                "epoch": epoch,
                "sequence": sequence,
            }
        )
    return app_records


def run_voses(voses_path, dump_path, app_data, seq_num, client_random, algorithm, keylog_path, role):
    with tempfile.NamedTemporaryFile(prefix="voses_app_record_", suffix=".bin", delete=False) as handle:
        handle.write(app_data)
        app_path = handle.name

    pre_size = os.path.getsize(keylog_path) if os.path.exists(keylog_path) else 0
    args = [
        voses_path,
        "--tls13",
        "--app_data_record",
        app_path,
        "--seq_num",
        str(seq_num),
        "--client_random",
        client_random,
        "--haystack",
        dump_path,
        "--memory-alignment",
        str(MEMORY_ALIGNMENT),
        "--entropy",
        str(ENTROPY_THRESHOLD),
        "--key-log",
        keylog_path,
        "--algorithm",
        algorithm,
    ]
    args.append("--client" if role == "client" else "--server")
    try:
        start_time = time.perf_counter()
        result = subprocess.run(args, capture_output=True, text=True)
        elapsed = time.perf_counter() - start_time
    finally:
        os.unlink(app_path)

    post_size = os.path.getsize(keylog_path) if os.path.exists(keylog_path) else 0
    output = (result.stdout or "") + (result.stderr or "")
    success = post_size > pre_size
    return success, output, result.returncode, elapsed


def attempt_secret(flow, dir_key, dump_path, keylog_path, role, current_scan, total_scans):
    records = flow["records"].get(dir_key, [])
    app_records = list_app_records(records)
    if len(app_records) < 2:
        print(f"[!] Not enough TLS application data records for {role} direction.")
        return False

    start_time = flow.get("client_hello_ts") or flow.get("first_seen")
    candidates = []
    for record in app_records:
        if record["epoch"] != 1:
            continue
        if start_time is not None and record["timestamp"] is not None:
            if record["timestamp"] - start_time > 8.0:
                continue
        candidates.append(record)

    if not candidates:
        print(f"[!] No suitable application data records found (within 8s) for {role} direction.")
        return False

    candidate = min(candidates, key=lambda r: len(r["data"]))
    seq_num = candidate["sequence"]

    src, dst = dir_key
    print(f"[*] [{current_scan}/{total_scans}] {role} scan: TLS 1.3 (TLS/TCP) | connection: {src.ip}:{src.port} -> {dst.ip}:{dst.port} | algorithm: {flow['algorithm']}")
    print(f"    Selected record seq={seq_num}, len={len(candidate['data'])}, time_offset={candidate['timestamp'] - start_time if start_time else 'N/A'}")
    success, output, code, elapsed = run_voses(
        flow["voses_path"],
        dump_path,
        candidate["data"],
        seq_num,
        flow["client_random"],
        flow["algorithm"],
        keylog_path,
        role,
    )
    if code != 0:
        print(output.strip())
        print(f"[!] voses exited with code {code} for {role} scan.")
    if success:
        print(f"[+] {role} traffic secret found. (took {elapsed:.2f}s)")
        return True
    print(f"[!] Failed to find {role} traffic secret.")
    return False


def get_session_time_range(flow):
    """Get the start and end time of a TLS session."""
    start_time = flow.get("client_hello_ts") or flow.get("server_hello_ts") or flow.get("first_seen")
    
    # Find the last timestamp across all records in both directions
    end_time = start_time
    for dir_key, records in flow["records"].items():
        for record in records:
            if record["timestamp"] is not None:
                if end_time is None or record["timestamp"] > end_time:
                    end_time = record["timestamp"]
    
    return start_time, end_time


def find_dumps_in_timeframe(hints, start_time, end_time, dumps_dir):
    """Find all dump files whose timestamps fall within the given timeframe."""
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
    # Sort by timestamp so we try earlier dumps first
    matching_dumps.sort(key=lambda x: x[1])
    return matching_dumps


def generate_adaptive_search_order(num_dumps):
    """
    Generate an adaptive search order that uses larger steps first, then fills gaps.
    
    This is similar to binary search: start with the first dump, then jump to middle,
    then quarters, etc. This allows faster discovery if the secret is in a later dump.
    
    For example, with 8 dumps [0,1,2,3,4,5,6,7], the order would be:
    Step 1 (stride 8): 0
    Step 2 (stride 4): 4
    Step 3 (stride 2): 2, 6
    Step 4 (stride 1): 1, 3, 5, 7
    Result: [0, 4, 2, 6, 1, 3, 5, 7]
    """
    if num_dumps == 0:
        return []
    if num_dumps == 1:
        return [0]
    
    order = []
    visited = set()
    
    # Start with the first element (index 0) - most likely to have the secret
    order.append(0)
    visited.add(0)
    
    # Binary search-like stepping: start with large strides, halve each round
    stride = num_dumps // 2
    while stride >= 1:
        idx = stride
        while idx < num_dumps:
            if idx not in visited:
                order.append(idx)
                visited.add(idx)
            idx += stride * 2 if stride > 1 else stride
        stride //= 2
    
    # Ensure all indices are covered (shouldn't be needed, but safety check)
    for i in range(num_dumps):
        if i not in visited:
            order.append(i)
    
    return order


def get_args():
    parser = argparse.ArgumentParser(
        description="Extract TLS 1.3 traffic secrets from memory dumps using voses."
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

    hints = parse_hints(args.hints)
    if not hints:
        print("Error: no usable hints found.", file=sys.stderr)
        return 1

    flows = build_flows(args.pcap)
    for flow in flows.values():
        extract_handshake_info(flow)

    tls13_flows = [flow for flow in flows.values() if flow["tls13"]]
    if not tls13_flows:
        print("No TLS 1.3 sessions found in capture.")
        return 0

    print(f"Found {len(tls13_flows)} TLS 1.3 sessions in capture.")
    print()

    # Collect session info with time ranges
    sessions = []
    for flow in tls13_flows:
        if flow["client_random"] is None:
            print(f"[!] Skipping session without client random")
            continue
        algorithm = TLS13_CIPHER_SUITES.get(flow["cipher_suite"])
        if not algorithm:
            print(f"[!] Skipping session with unsupported cipher suite: {flow['cipher_suite']}")
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
        print(f"    Time range: {start_time:.3f} - {end_time:.3f} ({end_time - start_time:.3f}s duration)")

    if not sessions:
        print("\nNo valid TLS 1.3 sessions to process.")
        return 0

    print(f"\n{'='*60}")
    print(f"Processing {len(sessions)} TLS 1.3 sessions")
    print(f"{'='*60}\n")

    successful_extractions = []
    failed_extractions = []
    skipped_sessions = []
    current_scan = 0
    total_scans = 0

    # Pre-calculate total scans by checking dumps for each session
    session_dumps = []
    for session in sessions:
        dumps = find_dumps_in_timeframe(hints, session["start_time"], session["end_time"], args.dumps)
        session_dumps.append(dumps)
        if dumps:
            # Worst case: 2 scans per dump (client + server), but we stop when both found
            total_scans += len(dumps) * 2

    for idx, session in enumerate(sessions):
        flow = session["flow"]
        conn_str = session["conn_str"]
        dumps = session_dumps[idx]
        
        print(f"\n[Session {idx+1}/{len(sessions)}] {conn_str}")
        print(f"  Time range: {session['start_time']:.3f} - {session['end_time']:.3f}")
        
        if not dumps:
            print(f"  [WARNING] No dumps found within session timeframe - skipping session")
            skipped_sessions.append(conn_str)
            continue
        
        print(f"  Found {len(dumps)} dump(s) in timeframe:")
        for dump_path, dump_ts in dumps:
            print(f"    - {os.path.basename(dump_path)} (ts: {dump_ts:.3f})")

        flow["algorithm"] = session["algorithm"]
        flow["voses_path"] = args.voses

        client_ok = False
        server_ok = False

        # Generate adaptive search order: larger steps first, then fill gaps
        search_order = generate_adaptive_search_order(len(dumps))
        print(f"  Search order (adaptive): {[os.path.basename(dumps[i][0]) for i in search_order[:5]]}{'...' if len(search_order) > 5 else ''}")

        # Try dumps in adaptive order until both secrets are found
        for dump_idx in search_order:
            if client_ok and server_ok:
                break
            
            dump_path, dump_ts = dumps[dump_idx]
            print(f"\n  Trying dump [{dump_idx+1}/{len(dumps)}]: {os.path.basename(dump_path)}")
            
            if not client_ok:
                current_scan += 1
                client_ok = attempt_secret(flow, flow["client_dir"], dump_path, args.keylog, "client", current_scan, total_scans)
            
            if not server_ok:
                current_scan += 1
                server_ok = attempt_secret(flow, flow["server_dir"], dump_path, args.keylog, "server", current_scan, total_scans)

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

    if skipped_sessions:
        print(f"\n[!] Skipped sessions (no dumps in timeframe) ({len(skipped_sessions)}):")
        for conn in skipped_sessions:
            print(f"    {conn}")

    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
