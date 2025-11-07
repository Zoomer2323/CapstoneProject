import React from 'react';
import StatsCard from './StatsCard';
import './StatsGrid.css';
import { motion } from 'framer-motion';

const StatsGrid = ({ stats }) => {
  return (
    <motion.section
      className="stats-grid"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.2 }}
    >
      {stats.map((stat, index) => (
        <StatsCard
          key={index}
          title={stat.title}
          value={stat.value}
          icon={stat.icon}
          color={stat.color}
        />
      ))}
    </motion.section>
  );
};

export default StatsGrid;