import React, { useState, useEffect, useCallback } from 'react';
import { useLanguage } from '../contexts/LanguageContext';
import { LoadConfigs, PingConfig, LoadSettings, SaveSettings } from '../services/api';
import type { VPNConfig } from '../services/api';
import { ArrowLeftIcon, SpinnerIcon } from './icons';

interface ProfilesPageProps {
  isConnected: boolean;
  connectedProtocol: string | null;
  onConnect: (configId: string) => void;
  onDisconnect: () => void;
  onBack: () => void;
}

const ProfilesPage: React.FC<ProfilesPageProps> = ({
  isConnected,
  connectedProtocol,
  onConnect,
  onDisconnect,
  onBack,
}) => {
  const { t, isRTL } = useLanguage();
  const [configs, setConfigs] = useState<VPNConfig[]>([]);
  const [selectedConfigId, setSelectedConfigId] = useState<string | null>(null);
  const [pings, setPings] = useState<Record<string, { latency: number; success: boolean; loading: boolean }>>({});
  const [connecting, setConnecting] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoPilot, setAutoPilot] = useState(false);
  const [autoPilotRunning, setAutoPilotRunning] = useState(false);
  const [filterProtocol, setFilterProtocol] = useState<string>('all');

  useEffect(() => {
    loadConfigs();
    loadSettings();
  }, []);

  const loadConfigs = async () => {
    setLoading(true);
    try {
      const cfgs = await LoadConfigs();
      setConfigs(cfgs);
      // Auto-ping all configs
      cfgs.forEach(c => pingConfig(c.id));
    } catch (err) {
      console.error('Failed to load configs:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadSettings = async () => {
    try {
      const settings = await LoadSettings();
      setAutoPilot(settings.autoPilot || false);
      if (settings.selectedProfile) {
        setSelectedConfigId(settings.selectedProfile);
      }
    } catch {}
  };

  const pingConfig = async (id: string) => {
    setPings(prev => ({ ...prev, [id]: { latency: 0, success: false, loading: true } }));
    try {
      const result = await PingConfig(id);
      setPings(prev => ({ ...prev, [id]: { latency: result.latency, success: result.success, loading: false } }));
    } catch {
      setPings(prev => ({ ...prev, [id]: { latency: 0, success: false, loading: false } }));
    }
  };

  const handleSelectConfig = async (configId: string) => {
    setSelectedConfigId(configId);
    // Save selection to settings
    try {
      await SaveSettings({ selectedProfile: configId });
    } catch {}
  };

  const handleConnect = async (configId: string) => {
    if (connecting) return;

    // If already connected to this config, disconnect
    if (isConnected && connectedProtocol === configId) {
      onDisconnect();
      return;
    }

    setConnecting(configId);
    setSelectedConfigId(configId);

    try {
      // Save selection
      await SaveSettings({ selectedProfile: configId });
      onConnect(configId);
    } finally {
      setTimeout(() => setConnecting(null), 1500);
    }
  };

  const handleAutoPilotToggle = async () => {
    const newValue = !autoPilot;
    setAutoPilot(newValue);
    await SaveSettings({ autoPilot: newValue });
    if (newValue) {
      runAutoPilot();
    }
  };

  const runAutoPilot = useCallback(async () => {
    setAutoPilotRunning(true);
    let bestConfig: string | null = null;
    let bestLatency = Infinity;

    for (const config of configs) {
      try {
        const result = await PingConfig(config.id);
        setPings(prev => ({ ...prev, [config.id]: { latency: result.latency, success: result.success, loading: false } }));
        if (result.success && result.latency < bestLatency) {
          bestLatency = result.latency;
          bestConfig = config.id;
        }
      } catch {}
    }

    if (bestConfig) {
      setSelectedConfigId(bestConfig);
      await SaveSettings({ selectedProfile: bestConfig });
      onConnect(bestConfig);
    }
    setAutoPilotRunning(false);
  }, [configs, onConnect]);

  // Get unique protocol names for filter
  const protocolNames = Array.from(new Set(configs.map(c => c.protocol)));

  // Filter configs
  const filteredConfigs = filterProtocol === 'all'
    ? configs
    : configs.filter(c => c.protocol === filterProtocol);

  const securityBadgeColor: Record<string, string> = {
    tls: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-800',
    reality: 'bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400 border-purple-200 dark:border-purple-800',
    aead: 'bg-amber-50 dark:bg-amber-900/20 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800',
    curve25519: 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
    ipsec: 'bg-cyan-50 dark:bg-cyan-900/20 text-cyan-600 dark:text-cyan-400 border-cyan-200 dark:border-cyan-800',
    obfs: 'bg-pink-50 dark:bg-pink-900/20 text-pink-600 dark:text-pink-400 border-pink-200 dark:border-pink-800',
    default: 'bg-slate-50 dark:bg-slate-700/40 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-600',
  };

  const transportIcons: Record<string, string> = {
    websocket: '🌊',
    grpc: '⚙️',
    tcp: '🔌',
    udp: '📡',
    dns: '🌐',
    default: '🔗',
  };

  return (
    <div className={`space-y-4 ${isRTL ? 'text-right' : 'text-left'}`}>
      {/* Header */}
      <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
        <div className={`flex items-center ${isRTL ? 'flex-row-reverse space-x-reverse space-x-4' : 'space-x-4'}`}>
          <button onClick={onBack} className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors">
            <ArrowLeftIcon className={`w-6 h-6 ${isRTL ? 'rotate-180' : ''}`} />
          </button>
          <div>
            <h2 className="text-2xl font-bold text-slate-800 dark:text-slate-200">{t('profiles')}</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {configs.length} {configs.length === 1 ? 'config' : 'configs'} available
            </p>
          </div>
        </div>
        <button
          onClick={loadConfigs}
          className="text-xs text-orange-500 hover:text-orange-600 font-semibold transition-colors"
        >
          {t('refresh')}
        </button>
      </div>

      {/* Auto Pilot */}
      <div className="bg-gradient-to-r from-orange-50 to-amber-50 dark:from-orange-900/20 dark:to-amber-900/20 rounded-xl p-4 border border-orange-200/60 dark:border-orange-800/40">
        <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
          <div className={`flex items-center flex-1 min-w-0 ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
            <span className="text-2xl">🤖</span>
            <div className="min-w-0">
              <p className="font-bold text-slate-800 dark:text-slate-200 text-sm">{t('autoPilot')}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('autoPilotDesc')}</p>
            </div>
          </div>
          <div className={`flex items-center ${isRTL ? 'space-x-reverse space-x-2' : 'space-x-2'}`}>
            {autoPilotRunning && (
              <SpinnerIcon className="w-4 h-4 text-orange-500 animate-spin" />
            )}
            <button
              onClick={handleAutoPilotToggle}
              disabled={autoPilotRunning}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none ${
                autoPilot ? 'bg-orange-500' : 'bg-slate-200 dark:bg-slate-600'
              }`}
            >
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                autoPilot ? 'translate-x-6' : 'translate-x-1'
              }`} />
            </button>
          </div>
        </div>
        {autoPilot && !autoPilotRunning && (
          <button
            onClick={runAutoPilot}
            className="mt-3 w-full py-2 rounded-lg bg-orange-500 hover:bg-orange-600 active:scale-[0.98] text-white text-xs font-bold transition-all"
          >
            {t('findBestConnection')}
          </button>
        )}
      </div>

      {/* Protocol Filter Tabs */}
      {protocolNames.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => setFilterProtocol('all')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              filterProtocol === 'all'
                ? 'bg-orange-500 text-white shadow-sm'
                : 'bg-white dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-600'
            }`}
          >
            All ({configs.length})
          </button>
          {protocolNames.map(proto => {
            const count = configs.filter(c => c.protocol === proto).length;
            return (
              <button
                key={proto}
                onClick={() => setFilterProtocol(proto)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  filterProtocol === proto
                    ? 'bg-orange-500 text-white shadow-sm'
                    : 'bg-white dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-600'
                }`}
              >
                {proto} ({count})
              </button>
            );
          })}
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-10">
          <SpinnerIcon className="w-8 h-8 text-orange-500 animate-spin" />
        </div>
      )}

      {/* No configs */}
      {!loading && filteredConfigs.length === 0 && (
        <div className="text-center py-10">
          <p className="text-4xl mb-3">📭</p>
          <p className="text-slate-500 dark:text-slate-400 text-sm font-medium">No configs available</p>
          <p className="text-slate-400 dark:text-slate-500 text-xs mt-1">Check your server connection or account permissions</p>
        </div>
      )}

      {/* Config List */}
      {!loading && (
        <div className="space-y-2">
          {filteredConfigs.map((config) => {
            const ping = pings[config.id];
            const isSelected = selectedConfigId === config.id;
            const isActiveConnection = isConnected && connectedProtocol === config.id;
            const isThisConnecting = connecting === config.id;

            return (
              <button
                key={config.id}
                onClick={() => handleConnect(config.id)}
                disabled={!!connecting && !isThisConnecting}
                className={`w-full p-3.5 rounded-xl border-2 transition-all duration-200 active:scale-[0.98] ${
                  isActiveConnection
                    ? 'border-green-400 dark:border-green-500 bg-green-50 dark:bg-green-900/20'
                    : isSelected && !isConnected
                      ? 'border-orange-300 dark:border-orange-600 bg-orange-50 dark:bg-orange-900/10'
                      : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800'
                }`}
              >
                <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
                  {/* Left: icon + info */}
                  <div className={`flex items-center flex-1 min-w-0 ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
                    <span className="text-2xl flex-shrink-0">{config.icon}</span>
                    <div className={`min-w-0 flex-1 ${isRTL ? 'text-right' : 'text-left'}`}>
                      <p className="font-semibold text-slate-800 dark:text-slate-200 text-sm truncate">{config.name}</p>
                      <div className={`flex items-center gap-1.5 mt-0.5 flex-wrap ${isRTL ? 'flex-row-reverse' : ''}`}>
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {config.address}:{config.port}
                        </span>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                          securityBadgeColor[config.security] || securityBadgeColor.default
                        }`}>
                          {config.security.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-slate-400 dark:text-slate-500">
                          {transportIcons[config.transport] || transportIcons.default} {config.transport}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Right: ping + status */}
                  <div className={`flex items-center flex-shrink-0 ${isRTL ? 'flex-row-reverse space-x-reverse space-x-2' : 'space-x-2'} ml-2`}>
                    {/* Ping display */}
                    {ping && !ping.loading && ping.success && (
                      <span className="text-xs font-medium text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/30 px-2 py-0.5 rounded-full">
                        {ping.latency}ms
                      </span>
                    )}
                    {ping && ping.loading && (
                      <SpinnerIcon className="w-4 h-4 text-blue-500 animate-spin" />
                    )}
                    {ping && !ping.loading && !ping.success && (
                      <span className="text-xs font-medium text-red-500 dark:text-red-400">✕</span>
                    )}

                    {/* Status indicator */}
                    {isThisConnecting ? (
                      <SpinnerIcon className="w-5 h-5 text-orange-500 animate-spin" />
                    ) : isActiveConnection ? (
                      <span className="flex items-center space-x-1">
                        <span className="w-2.5 h-2.5 bg-green-500 rounded-full animate-pulse"></span>
                        <span className="text-xs font-bold text-green-600 dark:text-green-400">{t('connected')}</span>
                      </span>
                    ) : (
                      <svg className="w-5 h-5 text-slate-400" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                      </svg>
                    )}
                  </div>
                </div>

                {/* Protocol badge at bottom */}
                <div className={`mt-2 flex items-center ${isRTL ? 'flex-row-reverse justify-end' : 'justify-start'}`}>
                  <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded-full">
                    {config.protocol}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ProfilesPage;
