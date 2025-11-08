import React from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const AlertsByTimeChart = ({ chartData }) => {
  
  // --- THIS IS THE FIX ---
  // We define the colors directly here instead of using CSS variables
  const data = {
    labels: chartData.labels,
    datasets: [
      {
        label: 'Critical',
        data: chartData.criticalData,
        backgroundColor: '#ef4444', // Red
      },
      {
        label: 'High',
        data: chartData.highData,
        backgroundColor: '#f59e0b', // Orange
      },
      {
        label: 'Medium',
        data: chartData.mediumData,
        backgroundColor: '#3b82f6', // Blue
      },
    ],
  };
  // --- END OF FIX ---

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#e2e8f0', // Legend text color
        },
      },
      tooltip: {
        titleFont: { size: 14, family: 'var(--font-heading)' },
        bodyFont: { size: 12, family: 'var(--font-paragraph)' },
      },
    },
    scales: {
      x: {
        stacked: true,
        ticks: { color: '#94a3b8' }, // X-axis labels
        grid: { color: 'rgba(100, 116, 139, 0.1)' }, // X-axis grid lines
      },
      y: {
        stacked: true,
        ticks: { color: '#94a3b8', stepSize: 1 }, // Y-axis labels
        grid: { color: 'rgba(100, 116, 139, 0.1)' }, // Y-axis grid lines
      },
    },
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alerts Over Time (Last 1 Hour)</CardTitle>
      </CardHeader>
      <CardContent>
        <div style={{ height: '300px' }}>
          <Bar data={data} options={options} />
        </div>
      </CardContent>
    </Card>
  );
};

export default AlertsByTimeChart;