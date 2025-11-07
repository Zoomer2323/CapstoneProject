import React from 'react';
import { motion } from 'framer-motion';
import AlertsByTimeChart from './AlertsByTimeChart'; // Import new chart
import AlertsByTypeChart from './AlertsByTypeChart'; // Import new chart
import './ChartsSection.css';

const ChartsSection = ({ alertsByTimeData, attackTypeData }) => {
  return (
    <motion.section
      className="charts-grid" // Use a grid class
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: 0.4 }}
    >
      {/* Bar Chart */}
      <AlertsByTimeChart chartData={alertsByTimeData} />

      {/* Doughnut Chart */}
      <AlertsByTypeChart chartData={attackTypeData} />
    </motion.section>
  );
};

export default ChartsSection;