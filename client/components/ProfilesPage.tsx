import React, { useState, useEffect, useCallback } from 'react';
import { useLanguage } from '../contexts/LanguageContext';
import { LoadConfigs, PingConfig, PingAllConfigs, LoadSettings, SaveSettings } from '../services/api';
import type { VPNConfig, PingResult } from '../services/api';
import { ArrowLeftIcon, SpinnerIcon } from './icons';

interface ProfilesPageProps {
  isConnected: boolean;
  isConnecting: boolean;
  connectedProtocol: string | null;
  onConnect: (configId: string) => void;
  onDisconnect: () => void;
  onBack: () => void;
}

const ProfilesPage: React.FC<ProfilesPageProps> = ({
  isConnected,
  isConnecting,
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
  const [pingingAll, setPingingAll] = useState(false);
  const [lastPingAllTime, setLastPingAllTime] = useState<string | null>(null);

  useEffect(() => {
    loadConfigs();
    loadSettings();
  }, []);

  const loadConfigs = async () => {
    setLoading(true);
    try {
      const cfgs = await LoadConfigs();
      setConfigs(cfgs);
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
    } catch { }
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

  const handlePingAll = async () => {
    if (pingingAll) return;
    setPingingAll(true);

    // Set all configs to loading state
    const loadingState: Record<string, { latency: number; success: boolean; loading: boolean }> = {};
    configs.forEach(c => {
      loadingState[c.id] = { latency: 0, success: false, loading: true };
    });
    setPings(loadingState);

    try {
      // Try bulk ping first
      const results = await PingAllConfigs();
      const newPings: Record<string, { latency: number; success: boolean; loading: boolean }> = {};

      results.forEach(r => {
        const configId = r.configId || r.profileName;
        newPings[configId] = {
          latency: r.latency,
          success: r.success,
          loading: false,
        };
      });

      // For any configs not covered by the bulk response, ping individually
      for (const config of configs) {
        if (!newPings[config.id]) {
          try {
            const result = await PingConfig(config.id);
            newPings[config.id] = {
              latency: result.latency,
              success: result.success,
              loading: false,
            };
          } catch {
            newPings[config.id] = { latency: 0, success: false, loading: false };
          }
        }
      }

      setPings(newPings);
      setLastPingAllTime(new Date().toLocaleTimeString());
    } catch {
      // Fallback: ping each individually
      for (const config of configs) {
        await pingConfig(config.id);
      }
      setLastPingAllTime(new Date().toLocaleTimeString());
    } finally {
      setPingingAll(false);
    }
  };

  const handleSelectConfig = async (configId: string) => {
    setSelectedConfigId(configId);
    // Save selection to settings
    try {
      await SaveSettings({ selectedProfile: configId });
    } catch { }
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
        // Only consider configs with a real measured latency (>0)
        if (result.success && result.latency > 0 && result.latency < bestLatency) {
          bestLatency = result.latency;
          bestConfig = config.id;
        }
      } catch { }
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

  // Sort configs: connected first, then by ping latency
  const sortedConfigs = [...filteredConfigs].sort((a, b) => {
    // Connected config first
    if (isConnected && connectedProtocol === a.id) return -1;
    if (isConnected && connectedProtocol === b.id) return 1;
    // Then by ping result — only consider configs with a real measured latency (>0)
    const pingA = pings[a.id];
    const pingB = pings[b.id];
    const hasRealPingA = pingA?.success && pingA.latency > 0;
    const hasRealPingB = pingB?.success && pingB.latency > 0;
    if (hasRealPingA && hasRealPingB) return pingA.latency - pingB.latency;
    if (hasRealPingA) return -1;
    if (hasRealPingB) return 1;
    return 0;
  });

  const getLatencyColor = (latency: number): string => {
    if (latency <= 50) return 'text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/30';
    if (latency <= 100) return 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/30';
    if (latency <= 150) return 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/30';
    if (latency <= 250) return 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/30';
    return 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/30';
  };

  const securityBadgeColor: Record<string, string> = {
    tls: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-800',
    reality: 'bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400 border-purple-200 dark:border-purple-800',
    aead: 'bg-amber-50 dark:bg-amber-900/20 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800',
    curve25519: 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
    ipsec: 'bg-cyan-50 dark:bg-cyan-900/20 text-cyan-600 dark:text-cyan-400 border-cyan-200 dark:border-cyan-800',
    obfs: 'bg-pink-50 dark:bg-pink-900/20 text-pink-600 dark:text-pink-400 border-pink-200 dark:border-pink-800',
    plain: 'bg-slate-50 dark:bg-slate-700/40 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-600',
    default: 'bg-slate-50 dark:bg-slate-700/40 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-600',
  };

  const transportIcons: Record<string, string> = {
    websocket: '🌊',
    ws: '🌊',
    grpc: '⚙️',
    tcp: '🔌',
    udp: '📡',
    dns: '🌐',
    default: '🔗',
  };

  // Count successful pings and average latency
  const pingStats = Object.values(pings).reduce(
    (acc, p) => {
      if (!p.loading && p.success && p.latency > 0) {
        acc.count++;
        acc.totalLatency += p.latency;
      }
      if (!p.loading && !p.success) {
        acc.failed++;
      }
      return acc;
    },
    { count: 0, totalLatency: 0, failed: 0 }
  );
  const avgLatency = pingStats.count > 0 ? Math.round(pingStats.totalLatency / pingStats.count) : 0;

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

      {/* ── PING ALL BUTTON ── */}
      <div className="bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-900/20 dark:to-blue-900/20 rounded-xl p-3.5 border border-indigo-200/60 dark:border-indigo-800/40">
        <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
          <div className={`flex items-center flex-1 min-w-0 ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
            <span className="text-2xl flex-shrink-0">📡</span>
            <div className="min-w-0 flex-1">
              <p className="font-bold text-slate-800 dark:text-slate-200 text-sm">Ping All Servers</p>
              <div className="flex items-center gap-2 flex-wrap mt-0.5">
                {pingStats.count > 0 && (
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    Avg: <span className={`font-bold ${avgLatency <= 80 ? 'text-green-600 dark:text-green-400' : avgLatency <= 150 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400'}`}>{avgLatency}ms</span>
                    {' · '}{pingStats.count}✓{pingStats.failed > 0 ? ` · ${pingStats.failed}✕` : ''}
                  </span>
                )}
                {lastPingAllTime && (
                  <span className="text-[10px] text-slate-400 dark:text-slate-500">
                    Last: {lastPingAllTime}
                  </span>
                )}
              </div>
            </div>
          </div>
          <button
            onClick={handlePingAll}
            disabled={pingingAll || loading}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all active:scale-[0.96] flex items-center gap-1.5 flex-shrink-0 ${pingingAll
              ? 'bg-indigo-300 dark:bg-indigo-700 text-white cursor-wait'
              : 'bg-indigo-500 hover:bg-indigo-600 text-white shadow-sm hover:shadow-md'
              }`}
          >
            {pingingAll ? (
              <>
                <SpinnerIcon className="w-3.5 h-3.5 animate-spin" />
                Pinging...
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
                </svg>
                Ping All
              </>
            )}
          </button>
        </div>
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
              className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none ${autoPilot ? 'bg-orange-500' : 'bg-slate-200 dark:bg-slate-600'
                }`}
            >
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoPilot ? 'translate-x-6' : 'translate-x-1'
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
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${filterProtocol === 'all'
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
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${filterProtocol === proto
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
          {sortedConfigs.map((config) => {
            const ping = pings[config.id];
            const isSelected = selectedConfigId === config.id;
            const isActiveConnection = isConnected && connectedProtocol === config.id;
            const isThisConnecting = (connecting === config.id) || (isConnecting && selectedConfigId === config.id);

            return (
              <button
                key={config.id}
                onClick={() => handleSelectConfig(config.id)}
                className={`w-full p-3.5 rounded-xl border-2 transition-all duration-200 active:scale-[0.98] ${isActiveConnection
                  ? 'border-green-400 dark:border-green-500 bg-green-50 dark:bg-green-900/20 shadow-sm shadow-green-100 dark:shadow-none'
                  : isSelected
                    ? 'border-orange-400 dark:border-orange-500 bg-orange-50 dark:bg-orange-900/20 shadow-sm shadow-orange-100 dark:shadow-none'
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
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${securityBadgeColor[config.security] || securityBadgeColor.default
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
                    {/* Ping display — only show when latency > 0 (real measurement) */}
                    {ping && !ping.loading && ping.success && ping.latency > 0 && (
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${getLatencyColor(ping.latency)}`}>
                        {ping.latency}ms
                      </span>
                    )}
                    {ping && ping.loading && (
                      <SpinnerIcon className="w-4 h-4 text-blue-500 animate-spin" />
                    )}
                    {ping && !ping.loading && !ping.success && (
                      <span className="text-xs font-medium text-red-500 dark:text-red-400 bg-red-50 dark:bg-red-900/30 px-2 py-0.5 rounded-full">✕</span>
                    )}

                    {/* Status indicator */}
                    {isThisConnecting ? (
                      <SpinnerIcon className="w-5 h-5 text-orange-500 animate-spin" />
                    ) : isActiveConnection ? (
                      <span className="flex items-center space-x-1">
                        <span className="w-2.5 h-2.5 bg-green-500 rounded-full animate-pulse"></span>
                        <span className="text-xs font-bold text-green-600 dark:text-green-400">{t('connected')}</span>
                      </span>
                    ) : isSelected ? (
                      <span className="flex items-center space-x-1">
                        <span className="w-2.5 h-2.5 bg-orange-500 rounded-full"></span>
                        <span className="text-xs font-bold text-orange-600 dark:text-orange-400">Selected</span>
                      </span>
                    ) : (
                      <div className="w-5 h-5 flex items-center justify-center">
                        <div className="w-4 h-4 rounded-full border-2 border-slate-300 dark:border-slate-600"></div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Protocol badge at bottom */}
                <div className={`mt-2 flex items-center ${isRTL ? 'flex-row-reverse justify-end' : 'justify-start'} gap-1.5`}>
                  <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded-full">
                    {config.protocol}
                  </span>
                  {/* Show a single-ping button per config */}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      pingConfig(config.id);
                    }}
                    className="text-[10px] font-semibold text-indigo-500 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 bg-indigo-50 dark:bg-indigo-900/30 px-2 py-0.5 rounded-full transition-colors"
                  >
                    🏓 Ping
                  </button>
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
