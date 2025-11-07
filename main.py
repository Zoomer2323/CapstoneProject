#!/usr/bin/env python3
"""
Main entry point for Network Intrusion Detection System
Supports both rule-based (Scapy) and ML-based detection
"""

# Fix Scapy cache directory issue before any imports
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
except Exception:
    pass

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run hybrid mode and output alerts to the React dashboard
  python main.py --mode hybrid -i "Intel(R) Wi-Fi 6 AX201 160MHz" --json-file "ids-dashboard-frontend/public/ids_alerts.json"

  # Use rule-based detection (Scapy)
  python main.py --mode rule -i en0

  # Use ML-based detection
  python main.py --mode ml -i en0
  
  # List available interfaces
  python main.py --list-interfaces
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['rule', 'ml', 'hybrid', 'auto'],
        default='auto',
        help='Detection mode: rule-based (Scapy), ML-based, hybrid (both), or auto (default: auto)'
    )
    
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor (e.g., "en0", "eth0", "Wi-Fi")'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    parser.add_argument(
        '--sensitive',
        action='store_true',
        help='Use sensitive detection thresholds (rule-based mode only)'
    )
    
    parser.add_argument(
        '--model',
        default='rf_model_MULTI_CLASS.pkl',
        help='Path to ML model file (ML mode only)'
    )
    
    parser.add_argument(
        '--scaler',
        default='ids_scaler_MULTI_CLASS.pkl',
        help='Path to scaler file (ML mode only)'
    )
    
    # --- NEW ARGUMENT ADDED ---
    parser.add_argument(
        '--json-file',
        default='ids_alerts.json',
        help='Path to save the JSON alerts file (e.g., "ids-dashboard-frontend/public/ids_alerts.json")'
    )
    # --- END OF NEW ARGUMENT ---
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        try:
            # Fix cache directory issue before importing scapy
            import os
            import tempfile
            
            # Try to use temp directory for cache to avoid permission issues
            temp_cache = os.path.join(tempfile.gettempdir(), 'scapy_cache')
            os.makedirs(temp_cache, mode=0o755, exist_ok=True)
            os.environ['SCAPY_CACHE_DIR'] = temp_cache
            
            from scapy.all import get_if_list
            interfaces = get_if_list()
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
        except (ImportError, PermissionError) as e:
            print("Scapy not available or cache issue. Listing interfaces using system command:")
            import subprocess
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if line and not line.startswith(' ') and not line.startswith('\t') and ':' in line:
                        iface = line.split(':')[0].strip()
                        if iface and iface not in interfaces:
                            interfaces.append(iface)
                for i, iface in enumerate(interfaces, 1):
                    print(f"  {i}. {iface}")
            except Exception:
                print("  Could not list interfaces. Common interfaces on macOS: en0, en1, en2")
        return 0
    
    # Determine which mode to use
    mode = args.mode
    if mode == 'auto':
        # Check if ML model files exist
        if os.path.exists(args.model) and os.path.exists(args.scaler):
            print("ML model files found. Using hybrid detection (rule-based + ML-based).")
            mode = 'hybrid'
        else:
            print("ML model files not found. Using rule-based detection.")
            mode = 'rule'
    
    # Handle hybrid mode
    if mode == 'hybrid':
        try:
            from hybrid_ids import main as hybrid_main
            # Create args namespace for hybrid
            class HybridArgs:
                def __init__(self):
                    self.interface = args.interface
                    self.rule_only = False
                    self.ml_only = False
                    self.model = args.model
                    self.scaler = args.scaler
                    # --- PASS JSON-FILE ARGUMENT ---
                    self.json_file = args.json_file
            
            hybrid_args = HybridArgs()
            return hybrid_main(hybrid_args)
        except ImportError as e:
            print(f"Hybrid mode not available: {e}")
            print("Falling back to rule-based mode.")
            mode = 'rule'
        except Exception as e:
            print(f"Error starting hybrid mode: {e}")
            import traceback
            traceback.print_exc()
            print("Falling back to rule-based mode.")
            mode = 'rule'
    
    # Run the appropriate IDS
    if mode == 'ml':
        print("=" * 60)
        print("Starting Cross-Platform ML-Based IDS")
        print("=" * 60)
        
        # Try cross-platform ML first, then fallback to NFStreamer, then rule-based
        try:
            from cross_platform_ml_ids import CrossPlatformMLIDS
            
            print("🧠 Using Cross-Platform ML Detection (Scapy + ML Models)")
            ids = CrossPlatformMLIDS(
                interface=args.interface,
                model_path=args.model,
                scaler_path=args.scaler,
                json_file=args.json_file  # <-- PASS JSON-FILE ARGUMENT
            )
            return 0 if ids.start() else 1
            
        except (ImportError, FileNotFoundError) as e:
            print(f"⚠️  Cross-platform ML not available: {e}")
            print("🔄 Trying NFStreamer-based ML...")
            
            try:
                # --- PASS JSON-FILE ARGUMENT ---
                import ml_ids # Import module
                from ml_ids import NetworkIDS, get_default_interface
                
                # Set the global variables in ml_ids before initializing
                ml_ids.JSON_FILE = args.json_file
                ml_ids.LOG_FILE = 'logs/ml_ids_alerts.log'
                # --- END OF FIX ---
                
                # Auto-detect interface if not provided
                interface = args.interface
                if not interface:
                    interface = get_default_interface()
                    if interface:
                        print(f"Auto-detected interface: {interface}")
                
                ids = NetworkIDS(
                    model_path=args.model,
                    scaler_path=args.scaler,
                    interface=interface
                )
                ids.start()
                return 0
                
            except ImportError as nf_error:
                print(f"❌ NFStream ML also not available: {nf_error}")
                print("Make sure required packages are installed:")
                print("  pip install nfstream joblib pandas scikit-learn numpy")
                print("\n⚠️  NFStream installation issues are common on newer systems.")
                print("🔄 Falling back to rule-based detection...")
                mode = 'rule'
            except Exception as nf_error:
                print(f"❌ NFStream ML error: {nf_error}")
                if "mach-o file" in str(nf_error) or "ndpi_wrap.so" in str(nf_error):
                    print("🔍 This appears to be a compatibility issue with NFStream on your system.")
                    print("   NFStream may not be compatible with your macOS/Python version.")
                print("🔄 Falling back to rule-based detection...")
                mode = 'rule'
                
        except Exception as e:
            print(f"❌ Error starting ML-based IDS: {e}")
            print("🔄 Falling back to rule-based detection...")
            mode = 'rule'
    
    # Execute rule-based mode (either directly requested or as fallback)
    if mode == 'rule':
        print("\n" + "=" * 60)
        print("Starting Rule-Based IDS (Scapy)")
        print("=" * 60)
        
        try:
            from network_ids import EnhancedNetworkIDS
            
            # --- PASS JSON-FILE ARGUMENT ---
            ids = EnhancedNetworkIDS(
                interface=args.interface,
                json_file=args.json_file
            )
            
            if args.sensitive:
                print("🔍 Sensitive mode enabled")
                ids.config['detection_thresholds']['port_scan_threshold'] = 3
                ids.config['detection_thresholds']['brute_force_threshold'] = 2
                ids.config['detection_thresholds']['connection_flood_threshold'] = 20
            
            return 0 if ids.start() else 1
            
        except ImportError as e:
            print(f"❌ Error: Could not import network_ids module: {e}")
            print("Make sure Scapy is installed: pip install scapy")
            return 1
        except Exception as e:
            print(f"❌ Error starting rule-based IDS: {e}")
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())