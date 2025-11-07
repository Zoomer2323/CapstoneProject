import React from 'react';
import './Footer.css';

const Footer = ({ lastUpdate }) => {
  const timeString = lastUpdate ? lastUpdate.toLocaleTimeString() : 'Never';
  
  return (
    <div className="footer">
      <p>Last updated: <span id="last-update">{timeString}</span></p>
      <p>Dashboard running on http://localhost:8000</p>
    </div>
  );
};

export default Footer;