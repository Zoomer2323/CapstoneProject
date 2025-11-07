#!/usr/bin/env python3
"""
ML-Based Network Intrusion Detection System
Fixed version with proper timeout configuration and cross-platform support
"""

import joblib
import pandas as pd
from nfstream import NFStreamer
from datetime import datetime
import json
import os
import sys
import logging
from pathlib import Path
import warnings
import time
import argparse
import platform

warnings.filterwarnings('ignore', category=UserWarning)

# --- CONSTANTS ---
LOG_FILE = 'ids_alerts.log'
JSON_FILE = 'ids_alerts.json'

CIC_IDS_2017_FEATURES = [
    ' Protocol', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Fwd Packets Length Total', ' Bwd Packets Length Total', ' Fwd Packet Length Max',
    ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
    ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean',
    ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean',
    ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
    ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s', ' Packet Length Min', ' Packet Length Max',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
    'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count',
    ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count',
    ' Down/Up Ratio', ' Avg Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
    ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk',
    ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
    'Init Fwd Win Bytes', ' Init Bwd Win Bytes', 'Fwd Act Data Packets',
    ' Fwd Seg Size Min', 'Active Mean', ' Active Std', ' Active Max', ' Active Min',
    'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
]

# --- LOGGING SETUP ---
def setup_logging():
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    logger = logging.getLogger('IDS')
    logger.setLevel(logging.INFO)
    
    fh = logging.FileHandler(log_dir / LOG_FILE, encoding='utf-8')
    fh.setFormatter(logging.Formatter(log_format))
    
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter(log_format))
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = setup_logging()

# --- ALERT FUNCTIONS ---
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
        with open(JSON_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save alert: {e}")

def generate_alert(alert_type, details, severity="HIGH"):
    details['alert_id'] = f"{alert_type}_{int(time.time())}_{hash(str(details)) % 10000}"
    details['local_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    alert = {
        'timestamp': datetime.now().isoformat(),
        'type': alert_type.upper(),
        'severity': severity,
        'details': details
    }
    
    logger.warning(f"🚨 ALERT: {alert_type} | {details.get('src_ip')}:{details.get('src_port')} -> {details.get('dst_ip')}:{details.get('dst_port')}")
    save_alert(alert)

# --- FEATURE MAPPING ---
def map_flow_to_features(flow):
    features = {name: 0.0 for name in CIC_IDS_2017_FEATURES}

    try:
        # Basic protocol and duration
        features[' Protocol'] = getattr(flow, 'protocol', 0)
        features[' Flow Duration'] = (getattr(flow, 'duration', 0) or 0) * 1_000_000
        
        # Packet counts
        features[' Total Fwd Packets'] = getattr(flow, 'src_to_dst_packets', 0) or 0
        features[' Total Backward Packets'] = getattr(flow, 'dst_to_src_packets', 0) or 0
        
        # Byte counts
        features['Fwd Packets Length Total'] = getattr(flow, 'src_to_dst_bytes', 0) or 0
        features[' Bwd Packets Length Total'] = getattr(flow, 'dst_to_src_bytes', 0) or 0
        
        # Forward packet sizes
        features[' Fwd Packet Length Max'] = getattr(flow, 'src_to_dst_max_ps', 0) or 0
        features[' Fwd Packet Length Min'] = getattr(flow, 'src_to_dst_min_ps', 0) or 0
        features[' Fwd Packet Length Mean'] = getattr(flow, 'src_to_dst_mean_ps', 0) or 0
        features[' Fwd Packet Length Std'] = getattr(flow, 'src_to_dst_stddev_ps', 0) or 0
        
        # Backward packet sizes
        features['Bwd Packet Length Max'] = getattr(flow, 'dst_to_src_max_ps', 0) or 0
        features['Bwd Packet Length Min'] = getattr(flow, 'dst_to_src_min_ps', 0) or 0
        features[' Bwd Packet Length Mean'] = getattr(flow, 'dst_to_src_mean_ps', 0) or 0
        features[' Bwd Packet Length Std'] = getattr(flow, 'dst_to_src_stddev_ps', 0) or 0
        
        # Overall packet statistics
        features[' Packet Length Min'] = getattr(flow, 'min_ps', 0) or 0
        features[' Packet Length Max'] = getattr(flow, 'max_ps', 0) or 0
        features[' Packet Length Mean'] = getattr(flow, 'mean_ps', 0) or 0
        features[' Packet Length Std'] = getattr(flow, 'stddev_ps', 0) or 0
        features[' Packet Length Variance'] = (getattr(flow, 'stddev_ps', 0) or 0) ** 2
        features[' Avg Packet Size'] = getattr(flow, 'mean_ps', 0) or 0
        
        # Flow rates
        features['Flow Bytes/s'] = getattr(flow, 'bytes_per_second', 0) or 0
        features[' Flow Packets/s'] = getattr(flow, 'packets_per_second', 0) or 0
        
        duration = getattr(flow, 'duration', 0) or 0.001  # Avoid division by zero
        features['Fwd Packets/s'] = (getattr(flow, 'src_to_dst_packets', 0) or 0) / duration
        features[' Bwd Packets/s'] = (getattr(flow, 'dst_to_src_packets', 0) or 0) / duration
        
        # Inter-arrival times
        features[' Flow IAT Mean'] = getattr(flow, 'mean_iat', 0) or 0
        features[' Flow IAT Std'] = getattr(flow, 'stddev_iat', 0) or 0
        features[' Flow IAT Max'] = getattr(flow, 'max_iat', 0) or 0
        features[' Flow IAT Min'] = getattr(flow, 'min_iat', 0) or 0
        
        # Forward IAT
        fwd_iat = getattr(flow, 'src_to_dst_iat', []) or []
        features['Fwd IAT Total'] = sum(fwd_iat) if fwd_iat else 0
        features[' Fwd IAT Mean'] = getattr(flow, 'src_to_dst_mean_iat', 0) or 0
        features[' Fwd IAT Std'] = getattr(flow, 'src_to_dst_stddev_iat', 0) or 0
        features[' Fwd IAT Max'] = getattr(flow, 'src_to_dst_max_iat', 0) or 0
        features[' Fwd IAT Min'] = getattr(flow, 'src_to_dst_min_iat', 0) or 0
        
        # Backward IAT
        bwd_iat = getattr(flow, 'dst_to_src_iat', []) or []
        features['Bwd IAT Total'] = sum(bwd_iat) if bwd_iat else 0
        features[' Bwd IAT Mean'] = getattr(flow, 'dst_to_src_mean_iat', 0) or 0
        features[' Bwd IAT Std'] = getattr(flow, 'dst_to_src_stddev_iat', 0) or 0
        features[' Bwd IAT Max'] = getattr(flow, 'dst_to_src_max_iat', 0) or 0
        features[' Bwd IAT Min'] = getattr(flow, 'dst_to_src_min_iat', 0) or 0
        
        # TCP Flags
        features['FIN Flag Count'] = getattr(flow, 'fin_flag_count', 0) or 0
        features[' SYN Flag Count'] = getattr(flow, 'syn_flag_count', 0) or 0
        features[' RST Flag Count'] = getattr(flow, 'rst_flag_count', 0) or 0
        features[' PSH Flag Count'] = getattr(flow, 'psh_flag_count', 0) or 0
        features[' ACK Flag Count'] = getattr(flow, 'ack_flag_count', 0) or 0
        features[' URG Flag Count'] = getattr(flow, 'urg_flag_count', 0) or 0
        features[' CWE Flag Count'] = getattr(flow, 'cwe_flag_count', 0) or 0
        features[' ECE Flag Count'] = getattr(flow, 'ece_flag_count', 0) or 0
        
        # PSH and URG flags (forward/backward)
        features['Fwd PSH Flags'] = getattr(flow, 'src_to_dst_psh_flags', 0) or 0
        features[' Bwd PSH Flags'] = getattr(flow, 'dst_to_src_psh_flags', 0) or 0
        features[' Fwd URG Flags'] = getattr(flow, 'src_to_dst_urg_flags', 0) or 0
        features[' Bwd URG Flags'] = getattr(flow, 'dst_to_src_urg_flags', 0) or 0
        
        # Header lengths
        features[' Fwd Header Length'] = getattr(flow, 'src_to_dst_header_bytes', 0) or 0
        features[' Bwd Header Length'] = getattr(flow, 'dst_to_src_header_bytes', 0) or 0
        features[' Fwd Header Length.1'] = getattr(flow, 'src_to_dst_header_bytes', 0) or 0
        
        # Down/Up Ratio
        src_packets = getattr(flow, 'src_to_dst_packets', 0) or 0
        dst_packets = getattr(flow, 'dst_to_src_packets', 0) or 0
        features[' Down/Up Ratio'] = dst_packets / src_packets if src_packets > 0 else 0
        
        # Segment sizes
        features[' Avg Fwd Segment Size'] = getattr(flow, 'src_to_dst_mean_ps', 0) or 0
        features[' Avg Bwd Segment Size'] = getattr(flow, 'dst_to_src_mean_ps', 0) or 0
        
        # Window sizes
        features['Init Fwd Win Bytes'] = getattr(flow, 'src_to_dst_init_win_bytes', 0) or 0
        features[' Init Bwd Win Bytes'] = getattr(flow, 'dst_to_src_init_win_bytes', 0) or 0
        
        # Data packets
        features['Fwd Act Data Packets'] = getattr(flow, 'src_to_dst_data_packets', 0) or 0
        features[' Fwd Seg Size Min'] = getattr(flow, 'src_to_dst_min_ps', 0) or 0
        
        # Active/Idle times
        features['Active Mean'] = getattr(flow, 'active_mean', 0) or 0
        features[' Active Std'] = getattr(flow, 'active_stddev', 0) or 0
        features[' Active Max'] = getattr(flow, 'active_max', 0) or 0
        features[' Active Min'] = getattr(flow, 'active_min', 0) or 0
        features['Idle Mean'] = getattr(flow, 'idle_mean', 0) or 0
        features[' Idle Std'] = getattr(flow, 'idle_stddev', 0) or 0
        features[' Idle Max'] = getattr(flow, 'idle_max', 0) or 0
        features[' Idle Min'] = getattr(flow, 'idle_min', 0) or 0
        
        # Bulk transfer features (set to 0 if not available)
        features['Fwd Avg Bytes/Bulk'] = getattr(flow, 'src_to_dst_avg_bytes_bulk', 0) or 0
        features[' Fwd Avg Packets/Bulk'] = getattr(flow, 'src_to_dst_avg_packets_bulk', 0) or 0
        features[' Fwd Avg Bulk Rate'] = getattr(flow, 'src_to_dst_avg_bulk_rate', 0) or 0
        features[' Bwd Avg Bytes/Bulk'] = getattr(flow, 'dst_to_src_avg_bytes_bulk', 0) or 0
        features[' Bwd Avg Packets/Bulk'] = getattr(flow, 'dst_to_src_avg_packets_bulk', 0) or 0
        features['Bwd Avg Bulk Rate'] = getattr(flow, 'dst_to_src_avg_bulk_rate', 0) or 0
        
        # Subflow features
        features['Subflow Fwd Packets'] = getattr(flow, 'src_to_dst_subflow_packets', 0) or 0
        features[' Subflow Fwd Bytes'] = getattr(flow, 'src_to_dst_subflow_bytes', 0) or 0
        features[' Subflow Bwd Packets'] = getattr(flow, 'dst_to_src_subflow_packets', 0) or 0
        features[' Subflow Bwd Bytes'] = getattr(flow, 'dst_to_src_subflow_bytes', 0) or 0

        feature_vector = [features[name] for name in CIC_IDS_2017_FEATURES]
        return [0.0 if v is None or pd.isna(v) else float(v) for v in feature_vector]

    except Exception as e:
        logger.debug(f"Feature mapping error: {e}")
        return None

# --- MAIN CLASS ---
class NetworkIDS:
    def __init__(self, model_path, scaler_path, interface=None):
        logger.info("=" * 70)
        logger.info("🛡️  Network IDS Initializing...")
        logger.info("=" * 70)
        
        # Load model ONCE here
        logger.info(f"Loading model: {model_path}")
        try:
            self.model = joblib.load(model_path)
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
        
        logger.info(f"Loading scaler: {scaler_path}")
        try:
            self.scaler = joblib.load(scaler_path)
        except Exception as e:
            logger.error(f"Failed to load scaler: {e}")
            raise
        
        logger.info("✓ Model and scaler loaded successfully")
        
        self.interface = interface
        self.flow_count = 0
        self.alert_count = 0
    
    def process_flow(self, flow):
        """Process a single network flow"""
        self.flow_count += 1
        
        if self.flow_count % 10 == 0:
            logger.info(f"✓ Processed {self.flow_count} flows | Alerts: {self.alert_count}")
        
        try:
            features = map_flow_to_features(flow)
            if features is None:
                return
            
            # Scale and predict
            features_scaled = self.scaler.transform([features])
            prediction = self.model.predict(features_scaled)[0]
            
            # Handle different prediction formats (string, numeric, etc.)
            prediction_str = str(prediction).strip()
            
            # Map ML predictions to standardized attack types
            attack_type_map = {
                'benign': None,
                'normal': None,
                '0': None,
                'ddos': 'DDoS',
                'dos': 'DoS',
                'dos hulk': 'DoS',
                'dos slowloris': 'DoS',
                'dos slowhttptest': 'DoS',
                'dos goldeneye': 'DoS',
                'portscan': 'PORT_SCAN',
                'port scan': 'PORT_SCAN',
                'port_scan': 'PORT_SCAN',
                'brute force': 'BRUTE_FORCE',
                'brute-force': 'BRUTE_FORCE',
                'ftp-patator': 'BRUTE_FORCE',
                'ssh-patator': 'BRUTE_FORCE',
                'infiltration': 'INFILTRATION',
                'bot': 'BOTNET',
                'botnet': 'BOTNET',
                'web attack': 'WEB_ATTACK',
                'xss': 'WEB_ATTACK',
                'sql injection': 'WEB_ATTACK',
                'heartbleed': 'HEARTBLEED',
            }
            
            # Normalize prediction
            prediction_lower = prediction_str.lower()
            attack_type = None
            
            # Check if it's an attack
            for key, mapped_type in attack_type_map.items():
                if key in prediction_lower:
                    attack_type = mapped_type
                    break
            
            # If not in map but not benign, use prediction as-is (uppercase)
            if attack_type is None and prediction_lower not in ['benign', 'normal', '0']:
                attack_type = prediction_str.upper().replace(' ', '_')
            
            # Generate alert if attack detected
            if attack_type:
                self.alert_count += 1
                details = {
                    "src_ip": getattr(flow, 'src_ip', 'Unknown'),
                    "dst_ip": getattr(flow, 'dst_ip', 'Unknown'),
                    "src_port": getattr(flow, 'src_port', 0),
                    "dst_port": getattr(flow, 'dst_port', 0),
                    "protocol": getattr(flow, 'protocol', 0),
                    "flow_duration_sec": getattr(flow, 'duration', 0),
                    "fwd_packets": getattr(flow, 'src_to_dst_packets', 0),
                    "bwd_packets": getattr(flow, 'dst_to_src_packets', 0),
                    "bytes_transferred": getattr(flow, 'bidirectional_bytes', 0),
                    "predicted_attack_type": prediction_str,
                    "detection_method": "ML",
                    "flow_id": getattr(flow, 'id', 0)
                }
                
                # Set severity based on attack type
                severity = "HIGH"
                if attack_type in ['PORT_SCAN']:
                    severity = "MEDIUM"
                elif attack_type in ['DDoS', 'DoS', 'BRUTE_FORCE', 'INFILTRATION']:
                    severity = "HIGH"
                
                generate_alert(attack_type, details, severity=severity)
        
        except Exception as e:
            logger.error(f"Processing error: {e}")
            import traceback
            logger.debug(traceback.format_exc())
    
    def start(self):
        """Start the IDS"""
        logger.info(f"Starting packet capture on: {self.interface or 'default interface'}")
        logger.info("🔍 Monitoring network traffic...")
        logger.info("Press Ctrl+C to stop.\n")
        
        try:
            stream = NFStreamer(
                source=self.interface if self.interface else None,
                statistical_analysis=True,
                n_dissections=20,
                idle_timeout=5,
                active_timeout=60
            )
            
            logger.info("✓ Capture started!\n")
            
            for flow in stream:
                self.process_flow(flow)
        
        except KeyboardInterrupt:
            logger.info("\n" + "=" * 70)
            logger.info(f"🛑 Stopping IDS")
            logger.info(f"📊 Total Flows: {self.flow_count} | Alerts: {self.alert_count}")
            logger.info("=" * 70)
        except Exception as e:
            logger.error(f"❌ Capture error: {e}")
            logger.error("Make sure you're running with appropriate permissions!")
            import traceback
            logger.debug(traceback.format_exc())

# --- MAIN ---
def get_default_interface():
    """Get default network interface based on platform"""
    if platform.system() == 'Windows':
        # On Windows, NFStreamer can use interface name or number
        return None  # Let NFStreamer auto-detect
    else:
        # On Linux/Mac, try common interface names
        import subprocess
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'dev' in line:
                        parts = line.split()
                        if 'dev' in parts:
                            idx = parts.index('dev')
                            if idx + 1 < len(parts):
                                return parts[idx + 1]
        except:
            pass
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ML-Based Network IDS')
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help='Network interface to monitor (default: auto-detect)')
    parser.add_argument('--model', type=str, default='rf_model_MULTI_CLASS.pkl',
                       help='Path to ML model file')
    parser.add_argument('--scaler', type=str, default='ids_scaler_MULTI_CLASS.pkl',
                       help='Path to scaler file')
    
    args = parser.parse_args()
    
    # Auto-detect interface if not provided
    interface = args.interface
    if not interface:
        interface = get_default_interface()
        if interface:
            logger.info(f"Auto-detected interface: {interface}")
        else:
            logger.info("Using default interface (auto-detected by NFStreamer)")
    
    try:
        ids = NetworkIDS(
            model_path=args.model,
            scaler_path=args.scaler,
            interface=interface
        )
        ids.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)
