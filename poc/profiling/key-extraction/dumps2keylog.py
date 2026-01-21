#!/usr/bin/env python3
"""
dumps2keylog.py - Unified TLS/DTLS/QUIC Key Extractor

This script combines the functionality of three specialized key extraction scripts:
    - dumps2keylog_tls12.py: TLS 1.2 and DTLS 1.2 master secrets
    - dumps2keylog_tls13.py: TLS 1.3 traffic secrets
    - dumps2keylog_quic.py: QUIC (TLS 1.3 over UDP) traffic secrets

All extracted keys are written to a single NSS Key Log file that can be used
by Wireshark to decrypt the captured traffic.

Workflow:
    1. Runs the TLS 1.2/DTLS 1.2 extractor to find master secrets
    2. Runs the TLS 1.3 extractor to find traffic secrets
    3. Runs the QUIC extractor to find QUIC traffic secrets
    4. Combines all results into a single keylog file

Usage:
    python dumps2keylog.py --pcap <capture.pcapng> --hints <dump-hints.txt> \\
                           --dumps <dumps_dir> --keylog <output.keylog> \\
                           --voses <path_to_voses>

Arguments:
    --pcap              Path to the pcapng network capture file
    --hints             Path to the dump-hints.txt file with memory dump timestamps
    --dumps             Directory containing the memory dump files
    --keylog            Output path for the combined NSS key log file
    --voses             Path to the voses binary (required)
    --skip-tls12        Skip TLS 1.2/DTLS 1.2 extraction
    --skip-tls13        Skip TLS 1.3 extraction
    --skip-quic         Skip QUIC extraction
    --max-seq-attempts-up    Maximum sequence number increment attempts for TLS 1.3 (default: 10)
    --max-seq-attempts-down  Maximum sequence number decrement attempts for TLS 1.3 (default: 5)

Requirements:
    - scapy: For parsing pcap files
    - voses: External binary tool for searching memory dumps for TLS secrets
    - dumps2keylog_tls12.py, dumps2keylog_tls13.py, dumps2keylog_quic.py
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def get_script_dir():
    """Get the directory containing this script."""
    return Path(__file__).parent.resolve()


def run_extractor(script_name, args, description):
    """
    Run a key extraction script as a subprocess.
    
    Args:
        script_name: Name of the script (e.g., 'dumps2keylog_tls12.py')
        args: List of command line arguments to pass
        description: Human-readable description for logging
        
    Returns:
        Tuple of (success: bool, output: str, return_code: int)
    """
    script_path = get_script_dir() / script_name
    
    if not script_path.exists():
        return False, f"Script not found: {script_path}", -1
    
    cmd = [sys.executable, str(script_path)] + args
    
    print(f"\n{'=' * 60}")
    print(f"Running {description}")
    print(f"{'=' * 60}")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,  # Let output flow to console
            text=True,
        )
        return result.returncode == 0, "", result.returncode
    except Exception as e:
        return False, str(e), -1


def merge_keylogs(keylog_files, output_path):
    """
    Merge multiple keylog files into a single output file, removing duplicates.
    
    Args:
        keylog_files: List of paths to keylog files to merge
        output_path: Path to the output merged keylog file
    """
    seen_lines = set()
    lines = []
    
    for keylog_path in keylog_files:
        if not os.path.exists(keylog_path):
            continue
        with open(keylog_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and line not in seen_lines:
                    seen_lines.add(line)
                    lines.append(line)
    
    if lines:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        return len(lines)
    return 0


def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract all TLS/DTLS/QUIC keys from memory dumps using voses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script combines three specialized extractors:
  - TLS 1.2 / DTLS 1.2: Master secrets for older TLS connections
  - TLS 1.3: Traffic secrets for modern TLS connections
  - QUIC: Traffic secrets for QUIC (TLS 1.3 over UDP) connections

Examples:
  %(prog)s --pcap capture.pcapng --hints dump-hints.txt --dumps ./dumps --keylog keys.log --voses ./voses
  %(prog)s --pcap capture.pcapng --hints hints.txt --dumps ./dumps --keylog keys.log --voses ./voses --skip-quic
"""
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
        required=True,
        help="Path to voses binary."
    )
    parser.add_argument(
        "--skip-tls12",
        action="store_true",
        help="Skip TLS 1.2/DTLS 1.2 extraction."
    )
    parser.add_argument(
        "--skip-tls13",
        action="store_true",
        help="Skip TLS 1.3 extraction."
    )
    parser.add_argument(
        "--skip-quic",
        action="store_true",
        help="Skip QUIC extraction."
    )
    parser.add_argument(
        "--max-seq-attempts-up",
        type=int,
        default=10,
        help="Maximum sequence number increment attempts for TLS 1.3 (default: 10)."
    )
    parser.add_argument(
        "--max-seq-attempts-down",
        type=int,
        default=5,
        help="Maximum sequence number decrement attempts for TLS 1.3 (default: 5)."
    )
    return parser.parse_args()


def main():
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
    if not os.path.isfile(args.voses):
        print(f"Error: voses binary not found: {args.voses}", file=sys.stderr)
        return 1
    
    # Ensure output directory exists
    keylog_dir = os.path.dirname(args.keylog)
    if keylog_dir and not os.path.exists(keylog_dir):
        os.makedirs(keylog_dir)
    
    start_time = time.time()
    
    print("=" * 60)
    print("UNIFIED TLS/DTLS/QUIC KEY EXTRACTOR")
    print("=" * 60)
    print(f"PCAP file:    {args.pcap}")
    print(f"Hints file:   {args.hints}")
    print(f"Dumps dir:    {args.dumps}")
    print(f"Output:       {args.keylog}")
    print(f"Voses binary: {args.voses}")
    print()
    
    extractors_to_run = []
    if not args.skip_tls12:
        extractors_to_run.append("TLS 1.2/DTLS 1.2")
    if not args.skip_tls13:
        extractors_to_run.append("TLS 1.3")
    if not args.skip_quic:
        extractors_to_run.append("QUIC")
    
    if not extractors_to_run:
        print("Error: All extractors are skipped. Nothing to do.", file=sys.stderr)
        return 1
    
    print(f"Extractors to run: {', '.join(extractors_to_run)}")
    
    # Create temporary keylog files for each extractor
    temp_keylogs = []
    results = {}
    
    try:
        # TLS 1.2/DTLS 1.2 extraction
        if not args.skip_tls12:
            tls12_keylog = tempfile.mktemp(suffix='_tls12.keylog')
            temp_keylogs.append(tls12_keylog)
            
            tls12_args = [
                "--pcap", args.pcap,
                "--hints", args.hints,
                "--dumps", args.dumps,
                "--keylog", tls12_keylog,
                "--voses", args.voses,
            ]
            
            success, output, code = run_extractor(
                "dumps2keylog_tls12.py",
                tls12_args,
                "TLS 1.2 / DTLS 1.2 Extractor"
            )
            results["TLS 1.2/DTLS 1.2"] = {"success": success, "code": code, "keylog": tls12_keylog}
        
        # TLS 1.3 extraction
        if not args.skip_tls13:
            tls13_keylog = tempfile.mktemp(suffix='_tls13.keylog')
            temp_keylogs.append(tls13_keylog)
            
            tls13_args = [
                "--pcap", args.pcap,
                "--hints", args.hints,
                "--dumps", args.dumps,
                "--keylog", tls13_keylog,
                "--voses", args.voses,
                "--max-seq-attempts-up", str(args.max_seq_attempts_up),
                "--max-seq-attempts-down", str(args.max_seq_attempts_down),
            ]
            
            success, output, code = run_extractor(
                "dumps2keylog_tls13.py",
                tls13_args,
                "TLS 1.3 Extractor"
            )
            results["TLS 1.3"] = {"success": success, "code": code, "keylog": tls13_keylog}
        
        # QUIC extraction
        if not args.skip_quic:
            quic_keylog = tempfile.mktemp(suffix='_quic.keylog')
            temp_keylogs.append(quic_keylog)
            
            quic_args = [
                "--pcap", args.pcap,
                "--hints", args.hints,
                "--dumps", args.dumps,
                "--keylog", quic_keylog,
                "--voses", args.voses,
            ]
            
            success, output, code = run_extractor(
                "dumps2keylog_quic.py",
                quic_args,
                "QUIC Extractor"
            )
            results["QUIC"] = {"success": success, "code": code, "keylog": quic_keylog}
        
        # Merge all keylog files
        print(f"\n{'=' * 60}")
        print("MERGING KEYLOGS")
        print(f"{'=' * 60}")
        
        keylog_files_to_merge = [r["keylog"] for r in results.values() if os.path.exists(r["keylog"])]
        total_keys = merge_keylogs(keylog_files_to_merge, args.keylog)
        
        print(f"Merged {total_keys} unique key entries to: {args.keylog}")
        
    finally:
        # Clean up temporary keylog files
        for temp_file in temp_keylogs:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
    
    # Print summary
    elapsed_time = time.time() - start_time
    
    print(f"\n{'=' * 60}")
    print("OVERALL SUMMARY")
    print(f"{'=' * 60}")
    
    for extractor_name, result in results.items():
        status = "OK" if result["success"] else f"FAILED (code {result['code']})"
        keys_found = 0
        if os.path.exists(result["keylog"]):
            with open(result["keylog"], 'r', encoding='utf-8') as f:
                keys_found = sum(1 for line in f if line.strip())
        print(f"  {extractor_name}: {status}")
    
    print()
    print(f"Total unique keys extracted: {total_keys}")
    print(f"Output file: {args.keylog}")
    print(f"Total runtime: {elapsed_time:.2f} seconds")
    print(f"{'=' * 60}")
    
    # Return non-zero if all extractors failed
    all_failed = all(not r["success"] for r in results.values())
    return 1 if all_failed and total_keys == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
