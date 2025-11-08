#!/usr/bin/env python3
"""
ML-Based IDS (Alert Generator)
This script does NOT scan any packets.
It pretends to be the ML-IDS and generates "Model-Based" alerts
every 10-20 seconds to test the dashboard.
It is designed to be imported by hybrid_ids.py or main.py.
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

# --- GLOBAL FILE PATHS (can be overridden by hybrid_ids.py) ---
LOG_FILE = 'logs/ml_alerts.log'
JSON_FILE = 'ids_alerts.json'

warnings.filterwarnings('ignore', category=UserWarning)

# --- LOGGING SETUP ---
def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_path = Path(LOG_FILE)
    log_dir = log_path.parent
    log_dir.mkdir(exist_ok=True)
    
    logger = logging.getLogger('IDS_ML_GENERATOR') # Unique logger name
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

# --- ALERT FUNCTIONS (Copied from real ml_ids.py) ---
def save_alert(alert):
    alerts = []
    if os.path.exists(JSON_FILE):
        try:
            with open(JSON_FILE, 'r') as f:
                alerts = json.load(f)
        except:
            alerts = []
    
    alerts.append(alert)
    alerts = alerts[-1000:]
    
    try:
        json_path = Path(JSON_FILE)
        json_dir = json_path.parent
        json_dir.mkdir(exist_ok=True)
        
        with open(JSON_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save alert: {e}")

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
    
    logger.warning(f"🚨 [ML] ALERT: {alert_type} | {details.get('src_ip')} -> {details.get('dst_ip')}")
    save_alert(alert)

# --- ALERT GENERATOR FUNCTIONS ---

def get_default_interface():
    """Dummy function to allow hybrid_ids.py to import it without error."""
    logger.info("get_default_interface called (returning None).")
    return None

class NetworkIDS:
    """
    This is the NetworkIDS class (Alert Generator).
    It matches the real one so hybrid_ids.py can import it,
    but its start() method just generates alerts.
    """
    def __init__(self, model_path, scaler_path, interface=None):
        global logger
        logger = setup_logging() # Re-init logger in case file paths were changed
        logger.info("=" * 70)
        logger.info("🛡️  ML-Based IDS (Alert Generator) Initializing...")
        logger.info("=" * 70)
        logger.info(f"Model: {model_path} (Ignored)")
        logger.info(f"Scaler: {scaler_path} (Ignored)")
        logger.info(f"Interface: {interface} (Ignored)")
        self.running = True

    def start(self):
        """Generates an ML alert every 10-20 seconds."""
        logger.info(f"Writing alerts to: {JSON_FILE}")
        logger.info(f"Writing logs to: {LOG_FILE}")
        logger.info("✅ ML engine (Alert Generator) started. Generating alerts...")

        simulated_attacks = [
            ("DDoS", "CRITICAL"),
            ("BOTNET", "HIGH"),
            ("INFILTRATION", "HIGH"),
        ]

        try:
            while self.running:
                # Wait for a random time
                sleep_time = random.randint(110, 120)
                time.sleep(sleep_time)
                
                # Pick a random attack
                attack_type, severity = random.choice(simulated_attacks)
                
                # Create details
                sim_src_ip = f"10.200.{random.randint(1, 254)}.{random.randint(1, 254)}"
                sim_dst_ip = f"192.168.1.102"
                
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

        except KeyboardInterrupt:
            self.running = False
            logger.info("🛑 Stopping ML alert generator.")
        except Exception as e:
            logger.error(f"❌ ML error: {e}")

if __name__ == "__main__":
    print("="*70)
    print("This is an ML-IDS Alert Generator script.")
    print("It is meant to be imported by main.py or hybrid_ids.py, not run directly.")
    print("\nTo run your system, use your main.py script:")
    print('  python main.py --mode hybrid -i "Your-Interface"')
    print("="*70)