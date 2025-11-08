#!/usr/bin/env python3
"""
One-Time Alert Generator
This script runs ONCE, adds a specified number of test alerts
to the JSON file, and then exits.

Usage:
  python add_test_alerts.py --count 5 --json-file "path/to/ids_alerts.json"
"""

import json
import os
import sys
import logging
from pathlib import Path
import warnings
import time
import datetime
import random
import argparse

# --- GLOBAL FILE PATH (can be set by command-line) ---
JSON_FILE = 'ids_alerts.json'
LOG_FILE = 'logs/add_test_alerts.log'

warnings.filterwarnings('ignore', category=UserWarning)

# --- LOGGING SETUP ---
def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_path = Path(LOG_FILE)
    log_dir = log_path.parent
    log_dir.mkdir(exist_ok=True)
    
    logger = logging.getLogger('IDS_TEST_GENERATOR') # Unique logger name
    logger.setLevel(logging.INFO)
    
    if not logger.hasHandlers():
        fh = logging.FileHandler(log_path, encoding='utf-8') 
        fh.setFormatter(logging.Formatter(log_format))
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter(log_format))
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

logger = setup_logging() 

# --- ALERT FUNCTIONS (Copied from ml_ids.py) ---
def save_alert(alert):
    alerts = []
    if os.path.exists(JSON_FILE):
        try:
            with open(JSON_FILE, 'r') as f:
                alerts = json.load(f)
        except:
            alerts = []
    
    alerts.append(alert)
    alerts = alerts[-1000:] # Keep only the last 1000 alerts
    
    try:
        json_path = Path(JSON_FILE)
        json_dir = json_path.parent
        json_dir.mkdir(exist_ok=True)
        
        with open(JSON_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save alert to {JSON_FILE}: {e}")

def generate_alert(alert_type, details, severity="HIGH"):
    details['alert_id'] = f"{alert_type}_{int(time.time())}_{hash(str(details)) % 10000}"
    details['local_time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # This part is key: it hardcodes the detection method
    details['detection_method'] = 'ML' 
    
    alert = {
        'timestamp': datetime.datetime.now().isoformat(),
        'type': alert_type.upper(),
        'severity': severity,
        'details': details
    }
    
    logger.info(f"Generating Alert: {alert_type} | {details.get('src_ip')} -> {details.get('dst_ip')}")
    save_alert(alert)

# --- MAIN EXECUTION ---
def run_alert_generator(alert_count):
    """Generates a specific number of alerts and then stops."""
    
    logger.info(f"Starting alert generation...")
    logger.info(f"Target file: {JSON_FILE}")

    simulated_attacks = [
        ("DDoS", "CRITICAL"),
        ("BOTNET", "HIGH"),
        ("INFILTRATION", "HIGH"),
    ]

    for i in range(alert_count):
        # Pick a random attack
        attack_type, severity = random.choice(simulated_attacks)
        
        # Create details
        sim_src_ip = f"10.200.{random.randint(1, 254)}.{random.randint(1, 254)}"
        sim_dst_ip = "192.168.1.102" # Fixed IP as requested
        
        details = {
            "src_ip": sim_src_ip,
            "dst_ip": sim_dst_ip,
            "src_port": random.randint(10000, 65000),
            "dst_port": random.choice([80, 443, 8080]),
            "protocol": random.choice([6, 17]), # 6=TCP, 17=UDP
            "predicted_attack_type": attack_type,
            "detection_method": "ML",
            "flow_id": random.randint(1000, 9999)
        }
        
        # Generate the alert
        generate_alert(attack_type, details, severity=severity)
        # We add a tiny sleep to ensure timestamps are unique
        time.sleep(0.01) 

    logger.info(f"✅ Success! Added {alert_count} new alerts to {JSON_FILE}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='One-Time ML Alert Generator')
    
    parser.add_argument(
        '--json-file', 
        default='ids-dashboard-frontend/public/ids_alerts.json',
        help='Path to save the JSON alerts file'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=5,
        help='Number of test alerts to generate'
    )
    
    args = parser.parse_args()

    # Set the global JSON_FILE path so the functions can use it
    JSON_FILE = args.json_file
    
    print("="*70)
    print(f"Running One-Time Alert Generator...")
    print("="*70)
    
    run_alert_generator(args.count)