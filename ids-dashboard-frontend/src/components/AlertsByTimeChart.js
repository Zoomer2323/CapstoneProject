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
  const data = {
    labels: chartData.labels,
    datasets: [
      {
        label: 'Critical',
        data: chartData.criticalData,
        backgroundColor: 'var(--alert-critical)',
      },
      {
        label: 'High',
        data: chartData.highData,
        backgroundColor: 'var(--alert-high)',
      },
      {
        label: 'Medium',
        data: chartData.mediumData,
        backgroundColor: 'var(--alert-medium)',
      },
    ],
  };

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
        <CardTitle>Alerts Over Time (Last 24h)</CardTitle>
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