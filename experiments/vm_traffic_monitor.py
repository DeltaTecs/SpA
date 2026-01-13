import argparse
import subprocess
import time
import os
import sys
import datetime
import pwd
import shutil
import threading
from scapy.all import sniff, IP, IPv6, TCP, UDP, Raw

# Global sets to track flows we've already dumped for
# Format: (proto, src_ip, src_port, dst_ip, dst_port)
processed_flows = set()

# Track how many app data packets we've seen for a flow
# Format: (proto, src_ip, src_port, dst_ip, dst_port) -> int (count)
flow_app_data_packet_counts = {}

def get_args():
    parser = argparse.ArgumentParser(description="Monitor traffic and dump VM RAM on specific events.")
    parser.add_argument("--ip", required=True, nargs='+', help="Target IP address(es) to listen for (source). Supports IPv4 and IPv6.")
    parser.add_argument("--vm", required=True, help="Name of the VirtualBox VM.")
    parser.add_argument("--dump-dir", required=True, help="Directory to save RAM dumps.")
    parser.add_argument("--hints", required=True, help="Path to the hints .txt file.")
    parser.add_argument("--interface", required=True, help="Network interface to listen on.")
    parser.add_argument("--user", help="User to run VBoxManage commands as (required if running script as root but VM belongs to a user).")
    return parser.parse_args()

def run_vbox_command(args, user=None):
    """Runs a VBoxManage command and returns the output."""
    cmd = []
    if user:
        cmd = ["sudo", "-u", user]
    
    cmd.append("VBoxManage")
    cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command {' '.join(cmd)}: {e.stderr}", file=sys.stderr)
        raise

def perform_dump(vm_name, dump_dir, hints_file, flow_key, reason, user=None):
    """Pauses VM, dumps RAM, resumes VM, and logs."""
    proto, src_ip, src_port, dst_ip, dst_port = flow_key
    
    dump_filename = f"{os.urandom(6).hex()}.elf"
    
    # Optimization: Write to /dev/shm (RAM disk) first to minimize VM pause time
    # and avoid blocking on disk I/O.
    staging_dir = "/dev/shm" if os.path.exists("/dev/shm") else dump_dir
    staging_path = os.path.join(staging_dir, dump_filename)
    final_path = os.path.join(dump_dir, dump_filename)
    
    print(f"[*] Triggered by {flow_key} ({reason}). Starting dump...")
    
    start_time = time.time()
    
    try:
        # 1. Pause VM
        run_vbox_command(["controlvm", vm_name, "pause"], user)
        
        # 2. Dump RAM to staging area
        # 'dumpvmcore' dumps the VM core (including RAM)
        run_vbox_command(["debugvm", vm_name, "dumpvmcore", f"--filename={staging_path}"], user)
        
        # 3. Resume VM immediately
        run_vbox_command(["controlvm", vm_name, "resume"], user)
        
    except Exception as e:
        print(f"[!] Failed to perform dump sequence: {e}")
        try:
            run_vbox_command(["controlvm", vm_name, "resume"], user)
        except:
            pass
        return

    duration = time.time() - start_time
    print(f"[+] Dump (RAM write) completed in {duration:.2f} seconds.")
    
    # 4. Offload file move and logging to background thread to resume sniffing
    def finalize_dump():
        try:
            if staging_dir != dump_dir:
                # Move from RAM disk to disk
                shutil.move(staging_path, final_path)
                # Ensure ownership is correct if root moved it
                if user:
                    try:
                        uid = pwd.getpwnam(user).pw_uid
                        gid = pwd.getpwnam(user).pw_gid
                        os.chown(final_path, uid, gid)
                    except Exception as ex:
                        print(f"Warning: Failed to chown moved file: {ex}")
            
            print(f"[+] Dump saved to {final_path}")
            
            # Write hint
            timestamp_ms = int(start_time * 1000)
            hint_line = f"Timestamp: {timestamp_ms} | File: {dump_filename} | Connection: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Cause: {reason}\n"
            with open(hints_file, "a") as f:
                f.write(hint_line)
        except Exception as e:
            print(f"[!] Error in background finalization: {e}")

    threading.Thread(target=finalize_dump).start()

def analyze_packet(pkt, args):
    # Optimization: Use getlayer to avoid double parsing (haslayer + getitem)
    ip_layer = pkt.getlayer(IP)
    ipv6_layer = pkt.getlayer(IPv6)
    
    if ip_layer:
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    elif ipv6_layer:
        src_ip = ipv6_layer.src
        dst_ip = ipv6_layer.dst
    else:
        return

    # Redundant check removed: BPF filter 'host {ip}' already handles this efficiently in kernel.
    
    proto = None
    src_port = 0
    dst_port = 0
    payload = b""

    tcp_layer = pkt.getlayer(TCP)
    udp_layer = pkt.getlayer(UDP)

    if tcp_layer:
        proto = "TCP"
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        raw_layer = pkt.getlayer(Raw)
        if raw_layer:
            payload = raw_layer.load
    elif udp_layer:
        proto = "UDP"
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        raw_layer = pkt.getlayer(Raw)
        if raw_layer:
            payload = raw_layer.load
    else:
        return

    if not payload:
        return

    flow_key = (proto, src_ip, src_port, dst_ip, dst_port)
    reverse_flow_key = (proto, dst_ip, dst_port, src_ip, src_port)
    
    if flow_key in processed_flows or reverse_flow_key in processed_flows:
        return

    trigger_dump = False
    reason = ""
    has_app_data = False

    # TLS Detection (TCP)
    if proto == "TCP":
        # TLS Record Layer: Content Type (1 byte), Version (2 bytes), Length (2 bytes)
        # 20: ChangeCipherSpec, 21: Alert, 22: Handshake, 23: Application Data
        
        offset = 0
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            length = int.from_bytes(payload[offset+3:offset+5], byteorder='big')
            record_len = 5 + length
            
            if offset + record_len > len(payload):
                break
            
            if content_type == 23: # Application Data
                has_app_data = True
                break
            
            offset += record_len

    # QUIC Detection (UDP)
    elif proto == "UDP":
        if len(payload) > 0:
            first_byte = payload[0]
            is_long_header = (first_byte & 0x80) != 0
            
            if not is_long_header:
                # Short Header (1-RTT) -> Application Data
                has_app_data = True

    if has_app_data:
        count = flow_app_data_packet_counts.get(flow_key, 0) + 1
        flow_app_data_packet_counts[flow_key] = count
        
        if count == 2:
            trigger_dump = True
            reason = "Second Application Data Packet"

    if trigger_dump:
        perform_dump(args.vm, args.dump_dir, args.hints, flow_key, reason, args.user)
        processed_flows.add(flow_key)
        processed_flows.add(reverse_flow_key)
        # Clean up state to save memory
        if flow_key in flow_app_data_packet_counts:
            del flow_app_data_packet_counts[flow_key]
        if reverse_flow_key in flow_app_data_packet_counts:
            del flow_app_data_packet_counts[reverse_flow_key]

def check_vm_exists(vm_name, user=None):
    """Checks if the VM exists using VBoxManage."""
    try:
        # 'showvminfo' returns 0 if VM exists, non-zero otherwise
        run_vbox_command(["showvminfo", vm_name], user)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    args = get_args()
    
    if not check_vm_exists(args.vm, args.user):
        print(f"Warning: VM '{args.vm}' not found by VBoxManage. Proceeding anyway...", file=sys.stderr)
    
    if not os.path.exists(args.dump_dir):
        os.makedirs(args.dump_dir)
    
    # If running as a specific user, ensure they own the dump directory
    if args.user:
        try:
            uid = pwd.getpwnam(args.user).pw_uid
            gid = pwd.getpwnam(args.user).pw_gid
            os.chown(args.dump_dir, uid, gid)
        except Exception as e:
            print(f"Warning: Failed to change ownership of {args.dump_dir} to {args.user}: {e}", file=sys.stderr)
        
    if args.ip:
        print(f"Listening for traffic from {', '.join(args.ip)}...")
        
    print(f"Target VM: {args.vm}")
    print(f"Dump Directory: {args.dump_dir}")
    print(f"Hints File: {args.hints}")
    
    # Ensure hints file directory exists
    hints_dir = os.path.dirname(args.hints)
    if hints_dir and not os.path.exists(hints_dir):
        os.makedirs(hints_dir)

    # Construct BPF filter for multiple IPs
    filter_parts = [f"host {ip}" for ip in args.ip]
    sniff_filter = " or ".join(filter_parts)
    
    sniff(filter=sniff_filter, prn=lambda pkt: analyze_packet(pkt, args), store=0, iface=args.interface)

if __name__ == "__main__":
    main()
