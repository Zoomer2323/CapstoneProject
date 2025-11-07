import React from 'react';
import { motion } from 'framer-motion';
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card';
import './StatsCard.css';

const StatsCard = ({ title, value, icon: Icon, color }) => {
  return (
    <Card className="stats-card">
      <CardHeader className="stats-card-header">
        <CardTitle className="stats-card-title">{title}</CardTitle>
        <Icon className="stats-card-icon" style={{ color: color }} />
      </CardHeader>
      <CardContent>
        <motion.div
          className="stats-card-value"
          key={value}
          initial={{ scale: 1.2, opacity: 0, color: color }}
          animate={{ scale: 1, opacity: 1, color: '#FFFFFF' }}
          transition={{ duration: 0.4 }}
        >
          {value}
        </motion.div>
      </CardContent>
    </Card>
  );
};

export default StatsCard;