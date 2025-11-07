import React from 'react';
import { Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card';

ChartJS.register(ArcElement, Tooltip, Legend);

// Define a color palette
const CHART_COLORS = [
  '#00FFC6', // primary
  '#ef4444', // critical
  '#f59e0b', // high
  '#3b82f6', // medium
  '#f39c12', // rule-based
  '#64FFDA', // secondary
  '#a855f7', // purple
  '#ec4899', // pink
];

const AlertsByTypeChart = ({ chartData }) => {
  const data = {
    labels: chartData.labels,
    datasets: [
      {
        label: 'Alerts',
        data: chartData.data,
        backgroundColor: CHART_COLORS,
        borderColor: 'var(--background)',
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          color: '#e2e8f0',
          font: {
            family: 'var(--font-paragraph)'
          },
          boxWidth: 20
        },
      },
      tooltip: {
        titleFont: { size: 14, family: 'var(--font-heading)' },
        bodyFont: { size: 12, family: 'var(--font-paragraph)' },
      },
    },
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alerts by Attack Type</CardTitle>
      </CardHeader>
      <CardContent>
        <div style={{ height: '300px' }}>
          <Doughnut data={data} options={options} />
        </div>
      </CardContent>
    </Card>
  );
};

export default AlertsByTypeChart;