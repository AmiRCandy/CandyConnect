import React from 'react';
import { SpinnerIcon, SignalIcon } from './icons';
import greenCandy from '../assets/green-candy.svg';
import redCandy from '../assets/red-candy.svg';

interface StatusDisplayProps {
  isConnected: boolean;
  isConnecting: boolean;
  location: string;
  onLocationClick?: () => void;
  ping?: number;
  pingSuccess?: boolean;
  isPinging?: boolean;
}

const StatusDisplay: React.FC<StatusDisplayProps> = ({ isConnected, isConnecting, location, onLocationClick, ping, pingSuccess, isPinging }) => {
  const getStatus = () => {
    if (isConnecting) {
      return {
        text: 'Connecting...',
        textColor: 'text-yellow-600 dark:text-yellow-400',
      };
    }
    if (isConnected) {
      return {
        text: 'Connected',
        textColor: 'text-green-600 dark:text-green-400',
      };
    }
    return {
      text: 'Disconnected',
      textColor: 'text-slate-700 dark:text-slate-300',
    };
  };

  const { text, textColor } = getStatus();
  const candySrc = isConnected ? greenCandy : redCandy;

  return (
    <div className="flex items-center space-x-3">
      {/* Candy SVG icon as status indicator */}
      <div className="flex-shrink-0 relative">
        {isConnecting ? (
          <div className="w-14 h-14 flex items-center justify-center">
            <img
              src={redCandy}
              alt="Connecting"
              className="w-14 h-14 animate-pulse opacity-50"
              draggable={false}
            />
          </div>
        ) : (
          <div className="w-14 h-14 flex items-center justify-center">
            <img
              src={candySrc}
              alt={isConnected ? 'Connected' : 'Disconnected'}
              className={`w-14 h-14 transition-all duration-500 ${isConnected ? 'drop-shadow-[0_0_8px_rgba(74,222,128,0.4)]' : 'drop-shadow-[0_0_8px_rgba(248,113,113,0.3)]'}`}
              draggable={false}
            />
          </div>
        )}
      </div>
      <div
        className={`flex-grow min-w-0 cursor-pointer hover:opacity-80 transition-opacity group`}
        onClick={onLocationClick}
        title="Click to measure latency"
      >
        <p className={`text-xl font-bold ${textColor}`}>{text}</p>
        <div className="flex items-center space-x-2">
          {isPinging ? (
            <>
              <SpinnerIcon className="w-3 h-3 text-blue-500 animate-spin" />
              <span className="text-blue-600 dark:text-blue-400 text-xs font-medium">Pinging...</span>
            </>
          ) : ping !== undefined ? (
            pingSuccess ? (
              <>
                <SignalIcon className="w-3 h-3 text-green-500" />
                <span className="text-green-600 dark:text-green-400 text-xs font-medium">{ping}ms</span>
              </>
            ) : (
              <span className="text-red-600 dark:text-red-400 text-xs font-medium">Failed</span>
            )
          ) : (
            <span className="text-slate-400 group-hover:text-blue-400 text-xs font-medium transition-colors">Click to Ping</span>
          )}
          <p className="text-slate-500 dark:text-slate-400 text-sm truncate">{location}</p>
        </div>
      </div>
    </div>
  );
};

export default StatusDisplay;
