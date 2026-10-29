import React from 'react';

interface ProgressBarProps { percent: number; height?: string; showLabel?: boolean; }

const ProgressBar: React.FC<ProgressBarProps> = ({ percent, height = 'h-2.5', showLabel = true }) => {
  const capped = Number.isFinite(percent) ? Math.min(100, Math.max(0, percent)) : 0;
  const color = capped > 90 ? 'bg-red-500' : capped > 70 ? 'bg-amber-500' : 'bg-green-500';
  return (
    <div className="w-full">
      <div className={`w-full ${height} bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden`}>
        <div className={`h-full rounded-full transition-all duration-700 ${color}`} style={{ width: `${capped}%` }} />
      </div>
      {showLabel && <p className="text-right text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 font-semibold">{capped.toFixed(1)}%</p>}
    </div>
  );
};

export default ProgressBar;
