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

  // --- DATA FETCHING HOOK ---
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
          critical: transformedAlerts.filter(a => a.severity?.toLowerCase() === 'high').length, // Map "HIGH" to critical
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

  // --- *** THIS IS THE CHANGED SECTION *** ---
  // Memoized chart data for Alerts over Time (Last 1 Hour by 5-min intervals)
  const alertsByTimeChartData = useMemo(() => {
    const labels = [];
    const minuteBuckets = {};
    const now = new Date();
    const bucketSizeMinutes = 5;
    const totalBuckets = 12; // 12 buckets of 5 minutes = 60 minutes
    
    // Create a set to track added labels and ensure correct order
    const labelSet = new Set();

    // Initialize the last 60 minutes in 5-minute intervals
    for (let i = totalBuckets - 1; i >= 0; i--) {
        const timeWindowEnd = new Date(now.getTime() - (i * bucketSizeMinutes * 60 * 1000));
        
        // Find the start of the 5-minute bucket
        const minutes = timeWindowEnd.getMinutes();
        const startOfBucketMinutes = minutes - (minutes % bucketSizeMinutes);
        const bucketTime = new Date(timeWindowEnd.getFullYear(), timeWindowEnd.getMonth(), timeWindowEnd.getDate(), timeWindowEnd.getHours(), startOfBucketMinutes);
      
        const hourKey = format(bucketTime, 'HH:mm'); // e.g., "14:05"
        
        if (!labelSet.has(hourKey)) { 
            labelSet.add(hourKey);
            labels.push(hourKey);
            minuteBuckets[hourKey] = { critical: 0, high: 0, medium: 0 };
        }
    }

    // Populate buckets with alert data
    alerts.forEach(alert => {
      const alertTime = new Date(alert.timestamp);
      // Only include alerts from the last 1 hour
      if ((now - alertTime) < (60 * 60 * 1000)) { 
        
        // Find the correct 5-minute bucket for the alert
        const minutes = alertTime.getMinutes();
        const startOfBucketMinutes = minutes - (minutes % bucketSizeMinutes);
        const bucketTime = new Date(alertTime.getFullYear(), alertTime.getMonth(), alertTime.getDate(), alertTime.getHours(), startOfBucketMinutes);
        const hourKey = format(bucketTime, 'HH:mm');

        if (minuteBuckets.hasOwnProperty(hourKey)) {
          const severity = alert.severity?.toLowerCase();
          if (severity === 'high') { // Map 'high' (from JSON) to 'critical' (for chart)
            minuteBuckets[hourKey].critical++;
          } else if (severity === 'medium') {
            minuteBuckets[hourKey].medium++;
          }
        }
      }
    });

    return {
      labels,
      criticalData: labels.map(label => minuteBuckets[label].critical),
      highData: labels.map(label => minuteBuckets[label].high), // Will be 0
      mediumData: labels.map(label => minuteBuckets[label].medium),
    };
  }, [alerts]);
  // --- *** END OF CHANGED SECTION *** ---


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