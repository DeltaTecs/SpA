#!/usr/bin/env python3
import argparse
import sys
from scapy.all import *

# Increase Scapy's default snaplen to capture full packets if needed, 
# though usually reading from pcap handles this.

def is_service_discovery(pkt):
    """Check if packet is a service discovery packet (MDNS, SSDP, LLMNR)."""
    if UDP in pkt:
        # MDNS (5353), SSDP (1900), LLMNR (5355)
        # Check both source and destination ports
        ports = [5353, 1900, 5355]
        if pkt[UDP].dport in ports or pkt[UDP].sport in ports:
            return True
    return False

def filter_pcap(input_file, output_file):
    """
    Filter pcap file based on:
    1. No TCP packets without data (payload)
    2. No ARP
    3. No Service Discovery
    """
    print(f"Filtering {input_file}...")
    
    count_total = 0
    count_kept = 0
    
    # PcapWriter to write packets incrementally
    writer = PcapWriter(output_file, append=False, sync=True)
    
    try:
        # PcapReader to read packets incrementally
        with PcapReader(input_file) as reader:
            for pkt in reader:
                count_total += 1
                
                # 1. Filter out ARP
                if ARP in pkt:
                    continue
                
                # 2. Filter out Service Discovery
                if is_service_discovery(pkt):
                    continue
                
                # 3. Filter out TCP packets that do not carry data
                if TCP in pkt:
                    # Check if TCP segment has payload
                    # In Scapy, pkt[TCP].payload is the layer after TCP.
                    # If it's NoPayload or empty Raw, len is 0.
                    if len(pkt[TCP].payload) == 0:
                        continue
                
                # If we passed all filters, write the packet
                writer.write(pkt)
                count_kept += 1
                
                if count_total % 1000 == 0:
                    print(f"Processed {count_total} packets...", end='\r')
                    
    except Exception as e:
        print(f"\nError processing file: {e}")
        sys.exit(1)
    finally:
        writer.close()
        
    print(f"\nDone. Processed {count_total} packets. Kept {count_kept} packets.")
    print(f"Output saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter pcapng files: remove ARP, Service Discovery, and empty TCP packets.")
    parser.add_argument("input_file", help="Path to input pcapng file")
    parser.add_argument("output_file", help="Path to output pcapng file")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found.")
        sys.exit(1)
        
    filter_pcap(args.input_file, args.output_file)
