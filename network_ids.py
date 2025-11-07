#!/usr/bin/env python3
"""
Enhanced Lightweight Network Intrusion Detection System (IDS)
Cross-platform IDS using Scapy for robust packet capture
"""

# Fix Scapy cache directory issue before importing
import os
import tempfile
try:
    # Create a writable cache directory in temp
    temp_cache = os.path.join(tempfile.gettempdir(), 'scapy_cache')
    os.makedirs(temp_cache, mode=0o755, exist_ok=True)
    os.environ['SCAPY_CACHE_DIR'] = temp_cache
    # Also set other Scapy environment variables to avoid permission issues
    os.environ['SCAPY_NO_COLOR'] = '1'
    os.environ['SCAPY_DEFAULT_CACHE_SIZE'] = '10'
    # Force disable auto-loading of contrib modules that might cause issues
    os.environ['SCAPY_DISABLE_CONTRIB'] = '1'
except Exception:
    pass  # Continue even if cache setup fails

from scapy.all import sniff, IP, TCP, UDP, get_if_list
import socket
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import os
import sys
import argparse
import logging
import ipaddress
from pathlib import Path

class EnhancedNetworkIDS:
    # --- Added 'json_file' to the constructor ---
    def __init__(self, interface=None, log_file='ids_alerts.log', config_file='ids_config.json', json_file='ids_alerts.json'):
        self.interface = interface
        self.log_file = log_file
        self.config_file = config_file
        self.json_file_path = json_file  # <-- Store the path
        self.running = False
        self.packets_processed = 0
        self.start_time = None
        self.load_config()
        self.port_scan_tracker = defaultdict(lambda: deque())
        self.brute_force_tracker = defaultdict(lambda: deque())
        self.connection_tracker = defaultdict(lambda: deque())
        self.suspicious_ips = set()
        self.stats = {'total_packets': 0, 'tcp_packets': 0, 'udp_packets': 0, 'alerts_generated': 0, 'unique_sources': set(), 'top_ports': defaultdict(int)}
        self.last_stats_display = time.time()
        self.setup_logging()
        self.initialize_json_file()

    def load_config(self):
        default_config = {
            'detection_thresholds': {
                'port_scan_threshold': 10,
                # --- CHANGE 1: Added new HEAVY threshold ---
                'port_scan_heavy_threshold': 100,
                'port_scan_massive_threshold': 1000,
                'port_scan_window': 30,
                'brute_force_threshold': 5,
                'brute_force_window': 60,
                'connection_flood_threshold': 50,
                'connection_flood_window': 10,
                'suspicious_ip_threshold': 3
            },
            'monitored_ports': {
                'auth_ports': [22, 23, 21, 3389, 25, 110, 143, 993, 995, 465, 587],
                'web_ports': [80, 443, 8080, 8443],
                'critical_ports': [22, 3389, 21, 23]
            },
            'network_settings': {
                'local_networks': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
                'whitelist_ips': ['127.0.0.1'],
                'blacklist_ips': []
            },
            'alert_settings': {
                'max_alerts_stored': 1000,
                'auto_cleanup_days': 7,
                'severity_levels': {
                    'PORT_SCAN': 'MEDIUM',
                    # --- CHANGE 2: Added severity for HEAVY scan ---
                    'HEAVY_PORT_SCAN': 'HIGH',
                    'MASSIVE_PORT_SCAN': 'CRITICAL',
                    'BRUTE_FORCE': 'HIGH',
                    'CONNECTION_FLOOD': 'HIGH',
                    'SUSPICIOUS_ACTIVITY': 'MEDIUM'
                }
            }
        }
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    # This line merges the default config with the loaded one
                    loaded_config = json.load(f)
                    for key in default_config:
                        if key in loaded_config:
                            # Update nested dictionaries
                            if isinstance(default_config[key], dict):
                                default_config[key].update(loaded_config[key])
                            else:
                                default_config[key] = loaded_config[key]
                        else:
                            # Add new keys if not in default (less common)
                            default_config[key] = loaded_config.get(key, default_config[key])
                    self.config = default_config
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                self.config = default_config
        else:
            self.config = default_config
            self.save_config()

    def save_config(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")

    def initialize_json_file(self):
        alerts_file = self.json_file_path 
        if not os.path.exists(alerts_file):
            try:
                json_path = Path(alerts_file)
                json_dir = json_path.parent
                json_dir.mkdir(exist_ok=True)
                
                with open(alerts_file, 'w') as f:
                    json.dump([], f)
                print(f"Initialized {alerts_file}")
            except Exception as e:
                print(f"Could not initialize {alerts_file}: {e}")

    def setup_logging(self):
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_dir / self.log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(log_format))
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger = logging.getLogger('NetworkIDS')
        self.logger.setLevel(logging.INFO)
        if not self.logger.hasHandlers(): # Avoid duplicate logs in hybrid mode
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def safe_log(self, level, message):
        try:
            if sys.platform.startswith('win'):
                emoji_replacements = {
                    '🛡️': '[SHIELD]', '✅': '[OK]', '❌': '[ERROR]',
                    '⚠️': '[WARNING]', '🚨': '[ALERT]', '📊': '[STATS]',
                    '🛑': '[STOP]', '🔍': '[SEARCH]', '🧪': '[TEST]', '🚫': '[BLOCKED]'
                }
                safe_message = message
                for emoji, replacement in emoji_replacements.items():
                    safe_message = safe_message.replace(emoji, replacement)
                getattr(self.logger, level)(safe_message)
            else:
                getattr(self.logger, level)(message)
        except Exception:
            getattr(self.logger, level)(message.encode('ascii', 'replace').decode('ascii'))

    def is_local_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.config['network_settings']['local_networks']:
                if ip_obj in ipaddress.ip_network(network):
                    return True
            return False
        except:
            return False
    
    def is_whitelisted(self, ip):
        return ip in self.config['network_settings']['whitelist_ips']

    def get_local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 465: 'SMTPS',
            587: 'SMTP', 3389: 'RDP', 5900: 'VNC', 1433: 'MSSQL', 3306: 'MySQL',
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, f'Port-{port}')
    
    def detect_massive_port_scan(self, src_ip, dst_ip, unique_ports, window):
        """
        Checks for massive port scans (e.g., 1000+)
        Returns True if an alert was generated, False otherwise.
        """
        threshold_massive = self.config['detection_thresholds']['port_scan_massive_threshold']
        
        if len(unique_ports) >= threshold_massive:
            self.generate_alert(
                "MASSIVE_PORT_SCAN", 
                {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'ports_scanned': list(unique_ports),
                    'count': len(unique_ports),
                    'time_window': window
                },
                detection_method_override="ML-Based" # <-- Hardcoded override
            )
            return True # Alert was generated
        return False # No alert

    # --- CHANGE 3: This is the new function for HEAVY (100+) port scans ---
    def detect_heavy_port_scan(self, src_ip, dst_ip, unique_ports, window):
        """
        Checks for heavy port scans (e.g., 100-999)
        Returns True if an alert was generated, False otherwise.
        """
        threshold_heavy = self.config['detection_thresholds']['port_scan_heavy_threshold']
        
        if len(unique_ports) >= threshold_heavy:
            self.generate_alert(
                "PORT_SCAN", # <-- Type is "PORT_SCAN" as requested
                {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'ports_scanned': list(unique_ports),
                    'count': len(unique_ports),
                    'time_window': window,
                    'description': 'Heavy port scan detected' # Added description
                },
                severity="HIGH", # <-- Set severity to HIGH
                detection_method_override="ML-Based" # <-- Hardcoded override
            )
            return True # Alert was generated
        return False # No alert

    def detect_port_scan(self, src_ip, dst_ip, unique_ports, window):
        """
        Checks for standard port scans (e.g., 10-99)
        Returns True if an alert was generated, False otherwise.
        """
        threshold_medium = self.config['detection_thresholds']['port_scan_threshold']
        
        if len(unique_ports) >= threshold_medium:
            self.generate_alert(
                "PORT_SCAN", 
                {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'ports_scanned': list(unique_ports),
                    'count': len(unique_ports),
                    'time_window': window
                }
                
            )
            return True # Alert was generated
        return False # No alert

    def detect_brute_force(self, src_ip, dst_ip, dst_port, scapy_tcp_layer):
        # ... (This function remains unchanged) ...
        if self.is_whitelisted(src_ip):
            return
        auth_ports = set(self.config['monitored_ports']['auth_ports'])
        if dst_port not in auth_ports:
            return
        
        current_time = time.time()
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        
        flags = str(scapy_tcp_layer.flags)
        if 'S' in flags or 'R' in flags:
            self.brute_force_tracker[key].append(current_time)
        else:
            return
        
        threshold = self.config['detection_thresholds']['brute_force_threshold']
        window = self.config['detection_thresholds']['brute_force_window']
        
        while (self.brute_force_tracker[key] and 
               current_time - self.brute_force_tracker[key][0] > window):
            self.brute_force_tracker[key].popleft()
        
        attempt_count = len(self.brute_force_tracker[key])
        
        if attempt_count >= threshold:
            self.generate_alert("BRUTE_FORCE", {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'service': self.get_service_name(dst_port),
                'attempt_count': attempt_count,
                'time_window': window,
                'pattern': 'Repeated connection attempts to authentication service'
            })
            self.brute_force_tracker[key].clear()

    def detect_connection_flood(self, src_ip, dst_ip, dst_port, scapy_tcp_layer):
        # ... (This function remains unchanged) ...
        if self.is_whitelisted(src_ip):
            return
        
        flags = str(scapy_tcp_layer.flags)
        if 'S' not in flags:
            return
            
        current_time = time.time()
        key_port = f"{src_ip}->{dst_ip}:{dst_port}"
        key_dest = f"{src_ip}->{dst_ip}"
        
        self.connection_tracker[key_port].append(current_time)
        self.connection_tracker[key_dest].append(current_time)
        
        threshold = self.config['detection_thresholds']['connection_flood_threshold']
        window = self.config['detection_thresholds']['connection_flood_window']
        
        while (self.connection_tracker[key_port] and 
               current_time - self.connection_tracker[key_port][0] > window):
            self.connection_tracker[key_port].popleft()
        
        while (self.connection_tracker[key_dest] and 
               current_time - self.connection_tracker[key_dest][0] > window):
            self.connection_tracker[key_dest].popleft()
        
        if len(self.connection_tracker[key_port]) >= threshold:
            self.generate_alert("CONNECTION_FLOOD", {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'service': self.get_service_name(dst_port),
                'connection_count': len(self.connection_tracker[key_port]),
                'time_window': window,
                'flood_type': 'Port-specific flood'
            })
            self.connection_tracker[key_port].clear()
        
        elif len(self.connection_tracker[key_dest]) >= threshold * 2:
            self.generate_alert("CONNECTION_FLOOD", {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': 'multiple',
                'service': 'Multiple services',
                'connection_count': len(self.connection_tracker[key_dest]),
                'time_window': window,
                'flood_type': 'Destination-wide flood'
            })
            self.connection_tracker[key_dest].clear()

    def generate_alert(self, alert_type, details, severity=None, detection_method_override=None):
        src_ip = details.get('src_ip')
        
        # --- CHANGE 4: Updated alert key logic ---
        # Use a more specific key for port scans to prevent one tier from locking out another
        if alert_type == "PORT_SCAN":
             alert_key = f"{src_ip}_{details.get('dst_ip')}_PORT_SCAN" # Key for 10+
        elif alert_type == "HEAVY_PORT_SCAN":
             alert_key = f"{src_ip}_{details.get('dst_ip')}_HEAVY_PORT_SCAN" # Key for 100+
        elif alert_type == "MASSIVE_PORT_SCAN":
             alert_key = f"{src_ip}_{details.get('dst_ip')}_MASSIVE_PORT_SCAN" # Key for 1000+
        else:
            alert_key = f"{src_ip}_{alert_type}"
            
        if alert_key in self.suspicious_ips:
            return

        if severity is None:
            severity = self.config['alert_settings']['severity_levels'].get(alert_type, 'MEDIUM')
        
        details['alert_id'] = f"{alert_type}_{int(time.time())}_{hash(str(details)) % 10000}"
        details['local_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if detection_method_override:
            details['detection_method'] = detection_method_override
        else:
            details['detection_method'] = 'Rule-Based'
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'details': details
        }
        
        log_detection_method = detection_method_override or 'Rule-Based'
        self.safe_log('warning', f"🚨 ALERT: {alert_type} ({log_detection_method}) | Severity: {severity} | {src_ip} -> {details.get('dst_ip')}")
        self.stats['alerts_generated'] += 1
        
        self.suspicious_ips.add(alert_key)
        threading.Timer(120, lambda: self.suspicious_ips.discard(alert_key)).start()
        
        self.save_alert(alert)

    def save_alert(self, alert):
        alerts_file = self.json_file_path
        alerts = []
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file, 'r') as f:
                    alerts = json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading existing alerts: {e}")
        
        alerts.append(alert)
        max_alerts = self.config['alert_settings']['max_alerts_stored']
        alerts = alerts[-max_alerts:]
        
        try:
            json_path = Path(alerts_file)
            json_dir = json_path.parent
            json_dir.mkdir(exist_ok=True)
            
            with open(alerts_file, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save alert: {e}")

    # --- CHANGE 5: Updated logic in check_for_port_scans ---
    def check_for_port_scans(self, src_ip, dst_ip, dst_port):
        """
        Gathers port scan data and checks for alerts in the correct order.
        """
        if self.is_whitelisted(src_ip):
            return

        current_time = time.time()
        key = f"{src_ip}->{dst_ip}"
        window = self.config['detection_thresholds']['port_scan_window']

        # Add current port and time to tracker
        self.port_scan_tracker[key].append((dst_port, current_time))
        
        # Clean old entries
        while (self.port_scan_tracker[key] and 
               current_time - self.port_scan_tracker[key][0][1] > window):
            self.port_scan_tracker[key].popleft()
        
        unique_ports = set(port for port, _ in self.port_scan_tracker[key])

        # Check in order of severity (most severe first)
        # This prevents a massive scan from also triggering a heavy/medium alert
        
        # 1. Check for MASSIVE scan (1000+)
        alert_fired = self.detect_massive_port_scan(src_ip, dst_ip, unique_ports, window)
        if alert_fired:
            self.port_scan_tracker[key].clear() # Clear tracker
            return # Exit function

        # 2. Check for HEAVY scan (100+) <-- NEW CHECK
        alert_fired = self.detect_heavy_port_scan(src_ip, dst_ip, unique_ports, window)
        if alert_fired:
            self.port_scan_tracker[key].clear() # Clear tracker
            return # Exit function

        # 3. Check for MEDIUM scan (10+)
        alert_fired = self.detect_port_scan(src_ip, dst_ip, unique_ports, window)
        if alert_fired:
            self.port_scan_tracker[key].clear() # Clear tracker
            return # Exit function

    def packet_handler(self, packet):
        try:
            if not packet.haslayer(IP):
                return
            
            self.packets_processed += 1
            self.stats['total_packets'] += 1
            ip_layer = packet.getlayer(IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            self.stats['unique_sources'].add(src_ip)
            
            if src_ip in self.config['network_settings']['blacklist_ips']:
                return

            if packet.haslayer(TCP):
                self.stats['tcp_packets'] += 1
                tcp_layer = packet.getlayer(TCP)
                dst_port = tcp_layer.dport
                self.stats['top_ports'][dst_port] += 1
                
                # Check for specific attacks first
                self.detect_brute_force(src_ip, dst_ip, dst_port, tcp_layer)
                self.detect_connection_flood(src_ip, dst_ip, dst_port, tcp_layer)
                
                # Then check for port scans
                self.check_for_port_scans(src_ip, dst_ip, dst_port)
            
            elif packet.haslayer(UDP):
                self.stats['udp_packets'] += 1
                udp_layer = packet.getlayer(UDP)
                dst_port = udp_layer.dport
                self.stats['top_ports'][dst_port] += 1
                
                self.check_for_port_scans(src_ip, dst_ip, dst_port)
            
            current_time = time.time()
            if current_time - self.last_stats_display >= 10:
                self.display_realtime_stats()
                self.last_stats_display = current_time

        except Exception as e:
            if self.logger.level == logging.DEBUG:
                self.logger.debug(f"Packet processing error: {e}")
    
    def display_realtime_stats(self):
        # ... (This function remains unchanged) ...
        runtime = time.time() - self.start_time if self.start_time else 0
        pps = self.packets_processed / runtime if runtime > 0 else 0
        self.safe_log('info', f"📊 Real-time: {self.packets_processed:,} packets | {pps:.1f} pps | {len(self.stats['unique_sources'])} sources | {self.stats['alerts_generated']} alerts")
    
    def stop(self):
        # ... (This function remains unchanged) ...
        self.running = False
        self.safe_log('info', "🛑 Stopping IDS...")

    def start(self):
        # ... (This function remains unchanged) ...
        self.safe_log('info', "🛡️ Starting Enhanced Network IDS (Scapy Engine)...")
        self.safe_log('info', f"Writing alerts to: {self.json_file_path}")
        
        self.running = True
        self.start_time = time.time()
        
        cleanup_thread = threading.Thread(target=self.cleanup_old_entries, daemon=True)
        cleanup_thread.start()
        
        self.safe_log('info', "✅ IDS started successfully. Monitoring network traffic...")
        self.safe_log('info', "🛑 Press Ctrl+C to stop.")
        
        try:
            sniff_kwargs = {'prn': self.packet_handler, 'store': 0, 'stop_filter': lambda p: not self.running}
            if self.interface:
                sniff_kwargs['iface'] = self.interface
            
            sniff(**sniff_kwargs)
        except (PermissionError, OSError) as e:
            self.safe_log('error', f"❌ ERROR: Scapy could not start. {e}")
            self.safe_log('error', "Please run with appropriate permissions (sudo on Linux/Mac, Administrator on Windows)")
            return False
        except Exception as e:
            self.safe_log('error', f"❌ An unexpected error occurred: {e}")
        finally:
            if self.running:
                self.stop()
            self.print_statistics()
            self.safe_log('info', "✅ IDS stopped gracefully.")
        return True
        
    def print_statistics(self):
        # ... (This function remains unchanged) ...
        if not self.start_time:
            return
        runtime = time.time() - self.start_time
        runtime_str = str(timedelta(seconds=int(runtime)))
        print(f"\n📊 IDS Statistics (Runtime: {runtime_str})")
        print(f"   Packets Processed: {self.packets_processed:,}")
        print(f"   TCP Packets: {self.stats['tcp_packets']:,}")
        print(f"   UDP Packets: {self.stats['udp_packets']:,}")
        print(f"   Alerts Generated: {self.stats['alerts_generated']}")
    
    def cleanup_old_entries(self):
        # ... (This function remains unchanged) ...
        while self.running:
            time.sleep(30)
            current_time = time.time()
            for key in list(self.port_scan_tracker.keys()):
                while (self.port_scan_tracker[key] and 
                       current_time - self.port_scan_tracker[key][0][1] > 60):
                    self.port_scan_tracker[key].popleft()
                if not self.port_scan_tracker[key]:
                    del self.port_scan_tracker[key]

def list_interfaces():
    # ... (This function remains unchanged) ...
    interfaces = get_if_list()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(f"   {i}. {iface}")
    return interfaces

def main():
    parser = argparse.ArgumentParser(description='Enhanced Lightweight Network IDS')
    parser.add_argument('-i', '--interface', help='Network interface name to monitor (e.g., "en0", "eth0", "Wi-Fi")')
    parser.add_argument('--list-interfaces', action='store_true', help='List available network interfaces')
    parser.add_argument('--sensitive', action='store_true', help='Use sensitive detection thresholds')
    parser.add_argument('--json-file', default='ids_alerts.json', help='Path to save the JSON alerts file')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🛡️ Enhanced Network Intrusion Detection System (Scapy Engine)")
    print("=" * 60)
    
    if args.list_interfaces:
        list_interfaces()
        return 0
    
    if sys.platform.startswith('win'):
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️ Warning: Not running as Administrator. Packet capture may fail.")
        except ImportError:
            pass
    else:
        if os.geteuid() != 0:
            print("⚠️ Warning: Not running as root. Packet capture may fail.")
            print("   Try: sudo python network_ids.py -i <interface>")

    ids = EnhancedNetworkIDS(interface=args.interface, json_file=args.json_file)
    
    if args.sensitive:
        print("🔍 Sensitive mode enabled")
        ids.config['detection_thresholds']['port_scan_threshold'] = 3
        # --- CHANGE 6: Added sensitive setting for heavy scan ---
        ids.config['detection_thresholds']['port_scan_heavy_threshold'] = 50
        ids.config['detection_thresholds']['port_scan_massive_threshold'] = 500 # Lower massive scan for sensitive mode
        ids.config['detection_thresholds']['brute_force_threshold'] = 2
        ids.config['detection_thresholds']['connection_flood_threshold'] = 20
    
    return 0 if ids.start() else 1

if __name__ == "__main__":
    sys.exit(main())