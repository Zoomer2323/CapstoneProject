import React from 'react';
import './AlertCard.css';

// Helper function to format timestamp
const formatTimestamp = (timestamp) => {
  if (!timestamp) return 'Unknown time';
  return new Date(timestamp).toLocaleString();
};

// Helper function to determine severity class
const getSeverity = (alert) => {
  const type = (alert.attack_type || '').toUpperCase();
  if (type.includes('DDOS') || type.includes('FLOOD')) return 'critical';
  if (type.includes('SCAN') || type.includes('PROBE')) return 'high';
  return 'medium';
};

// Helper function to get badge class
const getBadgeClass = (method) => {
  const m = (method || 'UNKNOWN').toUpperCase();
  if (m.includes('ML')) return 'badge-ml';
  if (m.includes('RULE')) return 'badge-rule';
  if (m.includes('HYBRID')) return 'badge-hybrid';
  return 'badge-ml'; // default
};

const AlertCard = ({ alert }) => {
  const severityClass = getSeverity(alert);
  const method = alert.detection_method || 'UNKNOWN';
  const badgeClass = getBadgeClass(method);
  const confidence = alert.confidence ? (alert.confidence * 100).toFixed(1) : null;

  return (
    <div className={`alert-card ${severityClass}`}>
      <div className="alert-header">
        <div className="alert-type">{alert.attack_type || 'Unknown Attack'}</div>
        <div className={`alert-badge ${badgeClass}`}>{method.toUpperCase()}</div>
      </div>

      <div className="alert-details">
        <div className="detail-item">
          <span className="detail-label">Alert ID</span>
          <span className="detail-value">#{alert.alert_id || 'N/A'}</span>
        </div>
        <div className="detail-item">
          <span className="detail-label">Source IP</span>
          <span className="detail-value">{alert.src_ip || 'N/A'}</span>
        </div>
        <div className="detail-item">
          <span className="detail-label">Destination IP</span>
          <span className="detail-value">{alert.dst_ip || 'N/A'}</span>
        </div>
        <div className="detail-item">
          <span className="detail-label">Port</span>
          <span className="detail-value">{alert.dst_port || alert.src_port || 'N/A'}</span>
        </div>
      </div>

      {confidence && (
        <div className="detail-item confidence-wrapper">
          <span className="detail-label">Confidence</span>
          <div className="confidence-bar">
            <div
              className="confidence-fill"
              style={{ width: `${confidence}%` }}
            >
              {confidence}%
            </div>
          </div>
        </div>
      )}

      <div className="timestamp">
        🕐 {formatTimestamp(alert.timestamp)}
      </div>
    </div>
  );
};

export default AlertCard;