import React from 'react';
import { motion } from 'framer-motion';
import { format } from 'date-fns';
import { Card, CardHeader, CardTitle, CardContent, Badge } from './ui/Card';
import './AlertsTable.css';

// Get badge variant based on severity string
const getSeverityBadgeVariant = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'destructive';
    case 'high':
      return 'warning';
    case 'medium':
      return 'info';
    default:
      return 'secondary';
  }
};

const AlertsTable = ({
  alerts,
  searchTerm,
  setSearchTerm,
  severityFilter,
  setSeverityFilter,
  typeFilter,
  setTypeFilter,
}) => {
  return (
    <motion.section
      className="table-section"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.6 }}
    >
      <Card>
        <CardHeader className="table-header-controls">
          <CardTitle>Recent Alerts</CardTitle>
          <div className="filter-controls">
            <input
              type="text"
              placeholder="Search IP or Attack..."
              className="filter-input"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <select
              className="filter-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
            <select
              className="filter-select"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <option value="all">All Types</option>
              <option value="ml">ML</option>
              <option value="rule">Rule-Based</option>
            </select>
          </div>
        </CardHeader>
        <CardContent className="table-card-content">
          <div className="table-wrapper">
            <table className="alerts-table">
              <thead>
                <tr className="table-header-row">
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Detection</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 25).map((alert, index) => ( // Show top 25
                  <motion.tr
                    key={alert.alert_id || index}
                    className="table-body-row"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                  >
                    <td className="font-medium">
                      {alert.attack_type || 'Unknown'}
                    </td>
                    <td>
                      <Badge variant={getSeverityBadgeVariant(alert.severity)}>
                        {alert.severity || 'Unknown'}
                      </Badge>
                    </td>
                    <td>{alert.detection_method || 'Unknown'}</td>
                    <td className="font-mono">{alert.src_ip || 'N/A'}</td>
                    <td className="font-mono">{alert.dst_ip || 'N/A'}</td>
                    <td className="font-mono">
                      {alert.timestamp
                        ? format(new Date(alert.timestamp), 'MMM dd, HH:mm:ss')
                        : 'N/A'}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
            {alerts.length === 0 && (
              <div className="no-alerts-message">
                No alerts found matching your criteria.
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.section>
  );
};

export default AlertsTable;