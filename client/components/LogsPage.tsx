import React, { useState, useEffect, useRef } from 'react';
import { useLanguage } from '../contexts/LanguageContext';
import { ArrowLeftIcon, DocumentTextIcon } from './icons';
import { LoadLogs, ClearLogs } from '../services/api';


interface LogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
}

interface LogsPageProps {
  onBack: () => void;
}

const LogsPage: React.FC<LogsPageProps> = ({ onBack }) => {
  const { t, isRTL } = useLanguage();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [filter, setFilter] = useState<'all' | 'info' | 'warn' | 'error' | 'debug'>('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const terminalRef = useRef<HTMLDivElement>(null);

  // Load logs from backend with polling for real-time updates
  useEffect(() => {
    const loadLogs = async () => {
      try {
        const backendLogs = await LoadLogs();
        setLogs(backendLogs);
      } catch (error) {
        console.error('Failed to load logs:', error);
      }
    };
    loadLogs();
    const interval = setInterval(loadLogs, 2000);
    return () => clearInterval(interval);
  }, []);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'error':
        return 'text-red-400';
      case 'warn':
        return 'text-yellow-400';
      case 'info':
        return 'text-blue-400';
      case 'debug':
        return 'text-gray-400';
      default:
        return 'text-green-400';
    }
  };

  const getLevelBadge = (level: string) => {
    const baseClasses = 'px-2 py-0.5 rounded text-xs font-mono font-medium';
    switch (level) {
      case 'error':
        return `${baseClasses} bg-red-900/30 text-red-300 border border-red-700/50`;
      case 'warn':
        return `${baseClasses} bg-yellow-900/30 text-yellow-300 border border-yellow-700/50`;
      case 'info':
        return `${baseClasses} bg-blue-900/30 text-blue-300 border border-blue-700/50`;
      case 'debug':
        return `${baseClasses} bg-gray-900/30 text-gray-300 border border-gray-700/50`;
      default:
        return `${baseClasses} bg-green-900/30 text-green-300 border border-green-700/50`;
    }
  };

  const filteredLogs = filter === 'all' ? logs : logs.filter(log => log.level === filter);

  const clearLogs = async () => {
    try {
      await ClearLogs();
      setLogs([]);
    } catch (error) {
      console.error('Failed to clear logs:', error);
    }
  };

  const exportLogs = () => {
    const logText = logs.map(log =>
      `[${formatTimestamp(log.timestamp)}] ${log.level.toUpperCase()}: ${log.message}`
    ).join('\n');

    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `candyconnect-logs-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className={`${isRTL ? 'text-right' : 'text-left'} flex flex-col h-full min-h-0`}>
      {/* Header */}
      <div className={`flex items-center justify-between mb-4 flex-shrink-0 ${isRTL ? 'flex-row-reverse' : ''}`}>
        <div className={`flex items-center ${isRTL ? 'flex-row-reverse space-x-reverse space-x-4' : 'space-x-4'}`}>
          <button
            onClick={onBack}
            className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors"
          >
            <ArrowLeftIcon className={`w-6 h-6 ${isRTL ? 'rotate-180' : ''}`} />
          </button>
          <h2 className="text-2xl font-bold text-slate-800 dark:text-slate-200">{t('logs')}</h2>
        </div>
      </div>

      {/* Controls */}
      <div className="bg-white dark:bg-slate-800 rounded-lg p-3 shadow-sm border border-slate-200/50 dark:border-slate-700/50 flex-shrink-0 mb-4">
        <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
          <div className={`flex items-center space-x-3 ${isRTL ? 'flex-row-reverse space-x-reverse' : ''}`}>
            {/* Filter */}
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              className="px-3 py-1.5 text-sm border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200 focus:ring-2 focus:ring-orange-500 focus:border-transparent"
            >
              <option value="all">All Levels</option>
              <option value="info">Info</option>
              <option value="warn">Warning</option>
              <option value="error">Error</option>
              <option value="debug">Debug</option>
            </select>
          </div>

          <div className={`flex items-center space-x-2 ${isRTL ? 'flex-row-reverse space-x-reverse' : ''}`}>
            <button
              onClick={clearLogs}
              className="px-3 py-1.5 text-sm bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20 rounded-md hover:bg-red-500/20 transition-colors"
            >
              Clear
            </button>
            <button
              onClick={exportLogs}
              className="px-3 py-1.5 text-sm bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20 rounded-md hover:bg-orange-500/20 transition-colors"
            >
              Export
            </button>
          </div>
        </div>
      </div>

      {/* Terminal */}
      <div className="flex-1 min-h-0 bg-black rounded-lg border border-slate-700 overflow-hidden shadow-inner flex flex-col mb-4">
        {/* Terminal Header */}
        <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex-shrink-0">
          <div className="flex items-center space-x-2">
            <div className="flex space-x-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
            <div className="flex items-center space-x-2 ml-4">
              <DocumentTextIcon className="w-4 h-4 text-slate-400" />
              <span className="text-sm text-slate-300 font-mono">candyconnect.log</span>
            </div>
          </div>
        </div>

        {/* Terminal Content */}
        <div
          ref={terminalRef}
          className="flex-1 min-h-0 overflow-y-auto p-4 font-mono bg-black scrollbar-thin scrollbar-track-slate-800 scrollbar-thumb-slate-600"
        >
          {filteredLogs.length === 0 ? (
            <div className="text-slate-500 text-center py-8">
              {filter === 'all' ? 'No logs available' : `No ${filter} logs found`}
            </div>
          ) : (
            <div className="space-y-1">
              {filteredLogs.map((log, index) => (
                <div key={`${log.timestamp}-${index}`} className="flex items-start space-x-3 hover:bg-slate-900/50 px-2 py-1 rounded">
                  <span className="text-slate-500 mt-0.5 min-w-[45px] text-[10px]">
                    {formatTimestamp(log.timestamp)}
                  </span>
                  <span className={getLevelBadge(log.level)}>
                    {log.level.toUpperCase()}
                  </span>
                  <span className="text-slate-200 flex-1 leading-tight text-[10px]">
                    {log.message}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Status Bar */}
      <div className="bg-slate-800 rounded-lg px-4 py-2 text-xs text-slate-400 font-mono flex-shrink-0">
        <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
          <span>{filteredLogs.length} entries</span>
          <span>Last updated: {logs.length > 0 ? formatTimestamp(logs[logs.length - 1].timestamp) : 'Never'}</span>
        </div>
      </div>
    </div>
  );
};

export default LogsPage;
