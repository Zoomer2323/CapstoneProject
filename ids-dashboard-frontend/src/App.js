import React, { useState, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { format } from 'date-fns';
import { Activity, AlertTriangle, Brain, FileText, Shield } from 'lucide-react';

import Header from './components/Header';
import StatsGrid from './components/StatsGrid';
import ChartsSection from './components/ChartsSection';
import AlertsTable from './components/AlertsTable';
import './App.css';

// KEEPS THE APP RUNNING - NO LONGER USES alerts_server.py

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [status, setStatus] = useState({ message: 'Connecting...', isError: false });
  const [lastUpdate, setLastUpdate] = useState(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');

  // --- NEW DATA FETCHING HOOK ---
  // This hook now fetches the JSON file directly and calculates stats
  useEffect(() => {
    const pollData = async () => {
      try {
        // Fetch the JSON file directly. The cachebust ensures we get the latest file.
        const response = await fetch(`ids_alerts.json?cachebust=${new Date().getTime()}`);
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const data = await response.json();

        // 1. Transform the data to match what the app expects
        // We flatten the 'details' object and map 'type' to 'attack_type'
        const transformedAlerts = data.map(alert => ({
          ...alert.details,                   // Spreads src_ip, dst_ip, alert_id, detection_method
          attack_type: alert.type,          // Map 'type' to 'attack_type'
          severity: alert.severity,         // Use the provided severity (e.g., "MEDIUM", "HIGH")
          timestamp: alert.timestamp        // Keep the top-level timestamp
        }));
        
        setAlerts(transformedAlerts);

        // 2. Calculate stats manually from the transformed data
        const newStats = {
          total: transformedAlerts.length,
          // Map "HIGH" severity alerts to the "Critical" card, as "critical" isn't in the JSON
          critical: transformedAlerts.filter(a => a.severity?.toLowerCase() === 'high').length,
          ml_detections: transformedAlerts.filter(a => a.detection_method?.toLowerCase().includes('ml')).length,
          rule_detections: transformedAlerts.filter(a => a.detection_method?.toLowerCase().includes('rule')).length,
        };
        
        setStats(newStats);
        
        setStatus({ message: 'Connected', isError: false });
        setLastUpdate(new Date());

      } catch (error) {
        console.error('Failed to fetch and parse ids_alerts.json:', error);
        setStatus({ message: 'Disconnected', isError: true });
      }
    };

    pollData(); // Initial fetch
    const interval = setInterval(pollData, 2000); // Poll every 2 seconds
    return () => clearInterval(interval);
  }, []); // Empty dependency array means this runs once on mount

  // Memoized filtered alerts for the table
  // This logic now works because the data is transformed correctly
  const filteredAlerts = useMemo(() => {
    return alerts
      .filter(alert => {
        // Severity Filter
        if (severityFilter !== 'all' && alert.severity?.toLowerCase() !== severityFilter) {
          return false;
        }
        // Type Filter (detection_method)
        if (typeFilter !== 'all' && !alert.detection_method?.toLowerCase().includes(typeFilter)) {
          return false;
        }
        // Search Term Filter
        if (searchTerm) {
          const search = searchTerm.toLowerCase();
          return (
            alert.attack_type?.toLowerCase().includes(search) ||
            alert.src_ip?.includes(search) ||
            alert.dst_ip?.includes(search)
          );
        }
        return true;
      })
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)); // Sort by timestamp
  }, [alerts, searchTerm, severityFilter, typeFilter]);

  // Memoized chart data for Attack Types (Doughnut)
  // This now works because 'attack_type' is correctly mapped
  const attackTypeChartData = useMemo(() => {
    const alertsByType = {};
    alerts.forEach(alert => {
      const type = alert.attack_type || 'Unknown';
      alertsByType[type] = (alertsByType[type] || 0) + 1;
    });

    const sortedAlerts = Object.entries(alertsByType)
      .sort(([, countA], [, countB]) => countB - countA);

    return {
      labels: sortedAlerts.map(([type]) => type.replace(/_/g, ' ')),
      data: sortedAlerts.map(([, count]) => count),
    };
  }, [alerts]);

  // Memoized chart data for Alerts over Time (Stacked Bar)
  // This now works because 'severity' is correctly parsed
  const alertsByTimeChartData = useMemo(() => {
    const labels = [];
    const hourlyBuckets = {};
    const now = new Date();

    for (let i = 23; i >= 0; i--) {
      const hour = new Date(now.getTime() - (i * 3600 * 1000));
      const hourKey = format(hour, 'HH:00');
      labels.push(hourKey);
      hourlyBuckets[hourKey] = { critical: 0, high: 0, medium: 0 };
    }

    alerts.forEach(alert => {
      const alertTime = new Date(alert.timestamp);
      if ((now - alertTime) < (24 * 3600 * 1000)) {
        const hourKey = format(alertTime, 'HH:00');
        if (hourlyBuckets[hourKey]) {
          const severity = alert.severity?.toLowerCase();
          // We map 'high' severity from JSON to 'critical' bucket for the chart
          if (severity === 'high') { 
            hourlyBuckets[hourKey].critical++;
          } else if (severity === 'medium') {
            hourlyBuckets[hourKey].medium++;
          }
          // Note: 'low' severity isn't in your JSON, so it won't be charted
        }
      }
    });

    return {
      labels,
      criticalData: labels.map(label => hourlyBuckets[label].critical),
      highData: labels.map(label => hourlyBuckets[label].high), // This will be 0, which is fine
      mediumData: labels.map(label => hourlyBuckets[label].medium),
    };
  }, [alerts]);


  // This statCards array now correctly reads the manually calculated stats
  const statCards = [
    {
      title: 'Total Alerts',
      value: stats.total || 0,
      icon: Activity,
      color: 'var(--primary)',
    },
    {
      title: 'High Severity', // Changed label from "Critical Alerts"
      value: stats.critical || 0, // Mapped from 'high' severity
      icon: AlertTriangle,
      color: 'var(--alert-critical)',
    },
    {
      title: 'ML Detections',
      value: stats.ml_detections || 0,
      icon: Brain,
      color: 'var(--secondary)',
    },
    {
      title: 'Rule-Based',
      value: stats.rule_detections || 0,
      icon: FileText,
      color: 'var(--alert-rule-based)',
    },
  ];

  return (
    <div className="app-container">
      <Header
        status={status}
        lastUpdate={lastUpdate ? format(lastUpdate, 'HH:mm:ss') : 'N/A'}
      />
      <main className="main-content">
        {/* Hero Section */}
        <motion.section
          className="hero-section"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="hero-content">
            <Shield className="hero-icon" />
            <div>
              <h2 className="hero-title">
                Real-Time Intrusion Detection
              </h2>
              <p className="hero-subtitle">
                Monitoring alerts from ids_alerts.json
              </p>
            </div>
          </div>
        </motion.section>

        {/* Stats Grid */}
        <StatsGrid stats={statCards} />

        {/* Charts Section */}
        <ChartsSection
          alertsByTimeData={alertsByTimeChartData}
          attackTypeData={attackTypeChartData}
        />

        {/* Alerts Table */}
        <AlertsTable
          alerts={filteredAlerts}
          searchTerm={searchTerm}
          setSearchTerm={setSearchTerm}
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          typeFilter={typeFilter}
          setTypeFilter={setTypeFilter}
        />
      </main>
    </div>
  );
}

export default App;