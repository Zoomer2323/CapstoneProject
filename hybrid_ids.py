#!/usr/bin/env python3
"""
Hybrid IDS - Combines Rule-Based and ML-Based Detection
Uses both Scapy (rule-based) and ML model for comprehensive attack detection
"""

import threading
import time
import sys
import os
import argparse

# Fix Scapy cache directory issue before importing
import tempfile
try:
    temp_cache = os.path.join(tempfile.gettempdir(), 'scapy_cache')
    os.makedirs(temp_cache, mode=0o755, exist_ok=True)
    os.environ['SCAPY_CACHE_DIR'] = temp_cache
except Exception:
    pass

def main(args=None):
    if args is None:
        parser = argparse.ArgumentParser(description='Hybrid IDS - Rule-Based + ML-Based Detection')
        parser.add_argument('-i', '--interface', help='Network interface to monitor')
        parser.add_argument('--rule-only', action='store_true', help='Use only rule-based detection')
        parser.add_argument('--ml-only', action='store_true', help='Use only ML-based detection')
        parser.add_argument('--model', default='rf_model_MULTI_CLASS.pkl', help='ML model path')
        parser.add_argument('--scaler', default='ids_scaler_MULTI_CLASS.pkl', help='Scaler path')
        args = parser.parse_args()
    
    print("=" * 70)
    print("🛡️  Hybrid IDS - Rule-Based + ML-Based Detection")
    print("=" * 70)
    print()
    
    threads = []
    
    # Start Rule-Based IDS
    if not args.ml_only:
        try:
            from network_ids import EnhancedNetworkIDS
            print("✅ Starting Rule-Based Detection (Scapy)...")
            rule_ids = EnhancedNetworkIDS(interface=args.interface)
            
            def run_rule_based():
                rule_ids.start()
            
            rule_thread = threading.Thread(target=run_rule_based, daemon=True)
            rule_thread.start()
            threads.append(rule_thread)
            print("✅ Rule-Based IDS started")
        except Exception as e:
            print(f"⚠️  Rule-Based IDS failed to start: {e}")
            if args.rule_only:
                print("❌ Rule-only mode requested but failed. Exiting.")
                return 1
    
    # Start ML-Based IDS
    if not args.rule_only:
        try:
            from ml_ids import NetworkIDS, get_default_interface
            
            # Check if model files exist
            if not os.path.exists(args.model) or not os.path.exists(args.scaler):
                print(f"⚠️  ML model files not found. Skipping ML detection.")
                print(f"   Expected: {args.model}, {args.scaler}")
            else:
                interface = args.interface
                if not interface:
                    interface = get_default_interface()
                
                print("✅ Starting ML-Based Detection (NFStreamer)...")
                ml_ids = NetworkIDS(
                    model_path=args.model,
                    scaler_path=args.scaler,
                    interface=interface
                )
                
                def run_ml_based():
                    ml_ids.start()
                
                ml_thread = threading.Thread(target=run_ml_based, daemon=True)
                ml_thread.start()
                threads.append(ml_thread)
                print("✅ ML-Based IDS started")
        except ImportError as e:
            print(f"⚠️  ML-Based IDS dependencies not available: {e}")
            print("   Install with: pip install nfstream lightgbm")
        except Exception as e:
            print(f"⚠️  ML-Based IDS failed to start: {e}")
            if args.ml_only:
                print("❌ ML-only mode requested but failed. Exiting.")
                return 1
    
    if not threads:
        print("❌ No detection methods started. Exiting.")
        return 1
    
    print()
    print("=" * 70)
    print("✅ Hybrid IDS is running!")
    print("=" * 70)
    print("📊 Both detection methods are active and saving to ids_alerts.json")
    print("🌐 View alerts in real-time at: http://localhost:8000/dashboard.html")
    print("🛑 Press Ctrl+C to stop")
    print("=" * 70)
    print()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("🛑 Stopping Hybrid IDS...")
        print("=" * 70)
        return 0

if __name__ == "__main__":
    sys.exit(main())

