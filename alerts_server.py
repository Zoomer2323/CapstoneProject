#!/usr/bin/env python3
"""
Real-Time IDS Alert Dashboard Server
Displays all alerts from any IDS (ML-only, Hybrid, Test Mode)
Auto-refreshes every 2 seconds
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
from datetime import datetime

ALERTS_FILE = 'ids_alerts.json'
PORT = 8000

class AlertDashboardHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/api/alerts':
            self.serve_alerts_api()
        elif self.path == '/api/stats':
            self.serve_stats_api()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        """Serve the HTML dashboard"""
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Alert Dashboard - Real-Time</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        
        .header .status {
            display: inline-block;
            padding: 8px 20px;
            background: #4CAF50;
            color: white;
            border-radius: 20px;
            margin-top: 15px;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .stat-card .label {
            color: #666;
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card.danger .number {
            color: #e74c3c;
        }
        
        .stat-card.warning .number {
            color: #f39c12;
        }
        
        .stat-card.success .number {
            color: #27ae60;
        }
        
        .alerts-section {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .alerts-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid #eee;
        }
        
        .alerts-header h2 {
            color: #667eea;
            font-size: 1.8em;
        }
        
        .refresh-info {
            color: #666;
            font-size: 0.9em;
        }
        
        .alert-card {
            background: #f8f9fa;
            border-left: 5px solid #667eea;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            transition: all 0.3s;
            animation: slideIn 0.5s;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .alert-card:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }
        
        .alert-card.critical {
            border-left-color: #e74c3c;
            background: #fee;
        }
        
        .alert-card.high {
            border-left-color: #f39c12;
            background: #fef8e7;
        }
        
        .alert-card.medium {
            border-left-color: #3498db;
            background: #eef5fb;
        }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .alert-type {
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .alert-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .badge-ml {
            background: #667eea;
            color: white;
        }
        
        .badge-rule {
            background: #27ae60;
            color: white;
        }
        
        .badge-hybrid {
            background: #f39c12;
            color: white;
        }
        
        .alert-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .detail-item {
            display: flex;
            flex-direction: column;
        }
        
        .detail-label {
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        
        .detail-value {
            font-size: 1.1em;
            font-weight: bold;
            color: #2c3e50;
            word-break: break-all;
        }
        
        .confidence-bar {
            width: 100%;
            height: 20px;
            background: #eee;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 5px;
        }
        
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #27ae60, #2ecc71);
            transition: width 0.5s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .no-alerts {
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-size: 1.2em;
        }
        
        .no-alerts .icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
            opacity: 0.9;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #667eea;
            font-size: 1.2em;
        }
        
        .timestamp {
            font-size: 0.9em;
            color: #999;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ IDS Alert Dashboard</h1>
            <p class="subtitle">Real-Time Intrusion Detection System Monitoring</p>
            <div class="status" id="status">● MONITORING ACTIVE</div>
        </div>
        
        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <div class="number" id="total-alerts">0</div>
                <div class="label">Total Alerts</div>
            </div>
            <div class="stat-card danger">
                <div class="number" id="critical-alerts">0</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card warning">
                <div class="number" id="ml-detections">0</div>
                <div class="label">ML Detections</div>
            </div>
            <div class="stat-card success">
                <div class="number" id="rule-detections">0</div>
                <div class="label">Rule-Based</div>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="alerts-header">
                <h2>🚨 Recent Alerts</h2>
                <div class="refresh-info">Auto-refresh: <span id="countdown">2</span>s</div>
            </div>
            <div id="alerts-container">
                <div class="loading">Loading alerts...</div>
            </div>
        </div>
        
        <div class="footer">
            <p>Last updated: <span id="last-update">Never</span></p>
            <p>Dashboard running on http://localhost:8000</p>
        </div>
    </div>
    
    <script>
        let refreshInterval;
        let countdownInterval;
        let countdown = 2;
        
        async function fetchAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                displayAlerts(alerts);
                
                const statsResponse = await fetch('/api/stats');
                const stats = await statsResponse.json();
                updateStats(stats);
                
                document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
                document.getElementById('status').textContent = '● MONITORING ACTIVE';
            } catch (error) {
                console.error('Error fetching alerts:', error);
                document.getElementById('status').textContent = '● CONNECTION ERROR';
            }
        }
        
        function displayAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            
            if (alerts.length === 0) {
                container.innerHTML = `
                    <div class="no-alerts">
                        <div class="icon">🔍</div>
                        <div>No alerts detected yet</div>
                        <div style="font-size: 0.9em; margin-top: 10px;">
                            Start an attack to see real-time detection
                        </div>
                    </div>
                `;
                return;
            }
            
            alerts.sort((a, b) => (b.alert_id || 0) - (a.alert_id || 0));
            const recentAlerts = alerts.slice(0, 20);
            
            container.innerHTML = recentAlerts.map(alert => {
                const severity = getSeverity(alert);
                const method = (alert.detection_method || 'UNKNOWN').toUpperCase();
                const badgeClass = method.includes('ML') ? 'badge-ml' : 
                                  method.includes('RULE') ? 'badge-rule' : 'badge-hybrid';
                
                return `
                    <div class="alert-card ${severity}">
                        <div class="alert-header">
                            <div class="alert-type">${alert.attack_type || 'Unknown Attack'}</div>
                            <div class="alert-badge ${badgeClass}">${method}</div>
                        </div>
                        
                        <div class="alert-details">
                            <div class="detail-item">
                                <span class="detail-label">Alert ID</span>
                                <span class="detail-value">#${alert.alert_id || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Source IP</span>
                                <span class="detail-value">${alert.src_ip || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Destination IP</span>
                                <span class="detail-value">${alert.dst_ip || 'N/A'}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Port</span>
                                <span class="detail-value">${alert.dst_port || alert.src_port || 'N/A'}</span>
                            </div>
                        </div>
                        
                        ${alert.confidence ? `
                        <div class="detail-item" style="margin-top: 15px;">
                            <span class="detail-label">Confidence</span>
                            <div class="confidence-bar">
                                <div class="confidence-fill" style="width: ${alert.confidence * 100}%">
                                    ${(alert.confidence * 100).toFixed(1)}%
                                </div>
                            </div>
                        </div>
                        ` : ''}
                        
                        <div class="timestamp">
                            🕐 ${formatTimestamp(alert.timestamp)}
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function updateStats(stats) {
            document.getElementById('total-alerts').textContent = stats.total || 0;
            document.getElementById('critical-alerts').textContent = stats.critical || 0;
            document.getElementById('ml-detections').textContent = stats.ml_detections || 0;
            document.getElementById('rule-detections').textContent = stats.rule_detections || 0;
        }
        
        function getSeverity(alert) {
            const type = (alert.attack_type || '').toUpperCase();
            if (type.includes('DDOS') || type.includes('FLOOD')) return 'critical';
            if (type.includes('SCAN') || type.includes('PROBE')) return 'high';
            return 'medium';
        }
        
        function formatTimestamp(timestamp) {
            if (!timestamp) return 'Unknown time';
            const date = new Date(timestamp);
            return date.toLocaleString();
        }
        
        function startCountdown() {
            countdown = 2;
            countdownInterval = setInterval(() => {
                countdown--;
                document.getElementById('countdown').textContent = countdown;
                if (countdown <= 0) countdown = 2;
            }, 1000);
        }
        
        fetchAlerts();
        startCountdown();
        refreshInterval = setInterval(fetchAlerts, 2000);
        
        window.addEventListener('beforeunload', () => {
            clearInterval(refreshInterval);
            clearInterval(countdownInterval);
        });
    </script>
</body>
</html>
"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_alerts_api(self):
        """Serve alerts as JSON API"""
        try:
            if os.path.exists(ALERTS_FILE):
                with open(ALERTS_FILE, 'r') as f:
                    content = f.read().strip()
                    if content:
                        alerts = json.loads(content)
                        if not isinstance(alerts, list):
                            alerts = [alerts]
                    else:
                        alerts = []
            else:
                alerts = []
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(alerts).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
    
    def serve_stats_api(self):
        """Serve statistics as JSON API"""
        try:
            if os.path.exists(ALERTS_FILE):
                with open(ALERTS_FILE, 'r') as f:
                    content = f.read().strip()
                    if content:
                        alerts = json.loads(content)
                        if not isinstance(alerts, list):
                            alerts = [alerts]
                    else:
                        alerts = []
            else:
                alerts = []
            
            stats = {
                'total': len(alerts),
                'critical': sum(1 for a in alerts if 'ddos' in (a.get('attack_type', '')).lower() or 'flood' in (a.get('attack_type', '')).lower()),
                'ml_detections': sum(1 for a in alerts if 'ml' in (a.get('detection_method', '')).lower()),
                'rule_detections': sum(1 for a in alerts if 'rule' in (a.get('detection_method', '')).lower()),
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())
    
    def log_message(self, format, *args):
        """Suppress log messages"""
        pass

def main():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        🛡️  IDS REAL-TIME ALERT DASHBOARD                    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    print(f"📊 Dashboard running at: http://localhost:{PORT}")
    print(f"📁 Monitoring alerts file: {ALERTS_FILE}")
    print()
    print("✅ Features:")
    print("   • Auto-refresh every 2 seconds")
    print("   • Shows all detection methods (ML, Rule-Based, Hybrid)")
    print("   • Real-time statistics")
    print("   • Beautiful responsive UI")
    print()
    print("🚀 Open your browser to: http://localhost:8000")
    print()
    print("Press Ctrl+C to stop the server")
    print("="*70)
    print()
    
    try:
        server = HTTPServer(('localhost', PORT), AlertDashboardHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n✅ Dashboard stopped")
        print("Goodbye!")

if __name__ == '__main__':
    main()
