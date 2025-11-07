import React from 'react';
import { Shield } from 'lucide-react';
import { motion } from 'framer-motion';
import './Header.css';

const Header = ({ status, lastUpdate }) => {
  return (
    <header className="app-header">
      <nav className="header-nav">
        <div className="header-title">
          <Shield className="header-icon" />
          <h1 className="header-logo-text">IDS Dashboard</h1>
        </div>
        <div className="header-status-group">
          <div className="status-display">
            <motion.div
              className="status-dot"
              animate={{
                background: status.isError ? 'var(--alert-critical)' : 'var(--primary)',
                opacity: [0.5, 1, 0.5],
              }}
              transition={{
                duration: status.isError ? 0.5 : 2,
                repeat: status.isError ? 0 : Infinity,
              }}
            />
            <span className="status-text">{status.message}</span>
          </div>
          <div className="update-time">
            Last update: {lastUpdate}
          </div>
        </div>
      </nav>
    </header>
  );
};

export default Header;