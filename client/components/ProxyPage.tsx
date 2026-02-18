import React, { useState, useEffect } from 'react';
import { useLanguage } from '../contexts/LanguageContext';
import { ArrowLeftIcon, NetworkIcon, ServerIcon } from './icons';
import { LoadSettings, SaveSettings } from '../services/api';
import { Settings } from '../services/api';

interface ProxySettings {
  mode: 'TUN' | 'Proxy';
  proxyType: 'SOCKS' | 'HTTP';
  ip: string;
  port: string;
  authEnabled: boolean;
  username: string;
  password: string;
  // TUN Configuration Options
  tunInet4CIDR: string;
  tunInet6CIDR: string;
  mtu: number;
  autoRoute: boolean;
  strictRoute: boolean;
  sniff: boolean;
  stack: string;
  dnsHijack: string[];
}

interface ProxyPageProps {
  onBack: () => void;
}

const ProxyPage: React.FC<ProxyPageProps> = ({ onBack }) => {
  const { t, isRTL } = useLanguage();
  const [settings, setSettings] = useState<ProxySettings>({
    mode: 'Proxy',
    proxyType: 'SOCKS',
    ip: '127.0.0.1',
    port: '1080',
    authEnabled: false,
    username: '',
    password: '',
    // TUN Configuration defaults
    tunInet4CIDR: '172.19.0.1/30',
    tunInet6CIDR: 'fc00::1/126',
    mtu: 9000,
    autoRoute: true,
    strictRoute: false,
    sniff: true,
    stack: 'mixed',
    dnsHijack: ['8.8.8.8:53', '1.1.1.1:53']
  });
  const [backendSettings, setBackendSettings] = useState<Settings | null>(null);

  // Load settings from backend
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const loadedSettings = await LoadSettings();
        setBackendSettings(loadedSettings);

        // Map backend settings to local proxy settings
        const proxyMode = loadedSettings.proxyMode === 'tun' ? 'TUN' : 'Proxy';
        const proxyType = loadedSettings.proxyType === 'http' ? 'HTTP' : 'SOCKS';

        setSettings({
          mode: proxyMode,
          proxyType: proxyType,
          ip: loadedSettings.proxyAddress || '127.0.0.1',
          port: loadedSettings.proxyPort?.toString() || '1080',
          authEnabled: !!(loadedSettings.proxyUsername && loadedSettings.proxyPassword),
          username: loadedSettings.proxyUsername || '',
          password: loadedSettings.proxyPassword || '',
          tunInet4CIDR: loadedSettings.tunInet4CIDR || '172.19.0.1/30',
          tunInet6CIDR: loadedSettings.tunInet6CIDR || 'fc00::1/126',
          mtu: loadedSettings.mtu || 9000,
          autoRoute: loadedSettings.autoRoute !== undefined ? loadedSettings.autoRoute : true,
          strictRoute: loadedSettings.strictRoute !== undefined ? loadedSettings.strictRoute : false,
          sniff: loadedSettings.sniff !== undefined ? loadedSettings.sniff : true,
          stack: loadedSettings.stack || 'mixed',
          dnsHijack: loadedSettings.dnsHijack || ['8.8.8.8:53', '1.1.1.1:53']
        });
      } catch (error) {
        console.error('Failed to load settings:', error);
      }
    };
    loadSettings();
  }, []);

  // Save settings to backend
  const saveSettings = async (newSettings: ProxySettings) => {
    if (!backendSettings) return;

    try {
      const updatedBackendSettings: Settings = {
        ...backendSettings,
        proxyMode: newSettings.mode === 'TUN' ? 'tun' : 'proxy',
        proxyType: newSettings.proxyType === 'HTTP' ? 'http' : 'socks',
        proxyAddress: newSettings.ip,
        proxyHost: newSettings.ip,
        proxyPort: parseInt(newSettings.port) || 1080,
        proxyUsername: newSettings.username,
        proxyPassword: newSettings.password,
        tunInet4CIDR: newSettings.tunInet4CIDR,
        tunInet6CIDR: newSettings.tunInet6CIDR,
        mtu: newSettings.mtu,
        autoRoute: newSettings.autoRoute,
        strictRoute: newSettings.strictRoute,
        sniff: newSettings.sniff,
        stack: newSettings.stack,
        dnsHijack: newSettings.dnsHijack,
      };

      await SaveSettings(updatedBackendSettings);
      setBackendSettings(updatedBackendSettings);
      setSettings(newSettings);
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  };

  const handleModeChange = (mode: 'TUN' | 'Proxy') => {
    saveSettings({ ...settings, mode });
  };

  const handleProxyTypeChange = (proxyType: 'SOCKS' | 'HTTP') => {
    saveSettings({ ...settings, proxyType });
  };

  const handleInputChange = (field: keyof ProxySettings, value: string | boolean | number | string[]) => {
    saveSettings({ ...settings, [field]: value });
  };

  const handleDNSHijackChange = (value: string) => {
    const dnsArray = value.split(',').map(dns => dns.trim()).filter(dns => dns.length > 0);
    handleInputChange('dnsHijack', dnsArray);
  };

  return (
    <div className={`space-y-4 ${isRTL ? 'text-right' : 'text-left'} max-h-96 min-h-[500px] overflow-y-auto pr-4`}>
      {/* Header */}
      <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
        <div className={`flex items-center ${isRTL ? 'flex-row-reverse space-x-reverse space-x-4' : 'space-x-4'}`}>
          <button
            onClick={onBack}
            className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors"
          >
            <ArrowLeftIcon className={`w-6 h-6 ${isRTL ? 'rotate-180' : ''}`} />
          </button>
          <h2 className="text-2xl font-bold text-slate-800 dark:text-slate-200">{t('proxy')}</h2>
        </div>
      </div>

      {/* Mode Selection */}
      <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
        <div className="mb-3">
          <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-2">{t('connectionMode')}</h3>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <button
            onClick={() => handleModeChange('TUN')}
            className={`flex items-center justify-center p-3 rounded-lg border-2 transition-all ${settings.mode === 'TUN'
                ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400'
                : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 text-slate-700 dark:text-slate-300'
              }`}
          >
            <div className="text-center">
              <NetworkIcon className="w-6 h-6 mx-auto mb-1" />
              <span className="font-medium">TUN</span>
            </div>
          </button>

          <button
            onClick={() => handleModeChange('Proxy')}
            className={`flex items-center justify-center p-3 rounded-lg border-2 transition-all ${settings.mode === 'Proxy'
                ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400'
                : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 text-slate-700 dark:text-slate-300'
              }`}
          >
            <div className="text-center">
              <ServerIcon className="w-6 h-6 mx-auto mb-1" />
              <span className="font-medium">Proxy</span>
            </div>
          </button>
        </div>
      </div>

      {/* Proxy Settings - Only show when Proxy mode is selected */}
      {settings.mode === 'Proxy' && (
        <>
          {/* Proxy Type Selection */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className="mb-3">
              <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-2">{t('proxyType')}</h3>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => handleProxyTypeChange('SOCKS')}
                className={`p-3 rounded-lg border-2 transition-all text-center ${settings.proxyType === 'SOCKS'
                    ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400'
                    : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 text-slate-700 dark:text-slate-300'
                  }`}
              >
                <span className="font-medium">SOCKS</span>
              </button>

              <button
                onClick={() => handleProxyTypeChange('HTTP')}
                className={`p-3 rounded-lg border-2 transition-all text-center ${settings.proxyType === 'HTTP'
                    ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400'
                    : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 text-slate-700 dark:text-slate-300'
                  }`}
              >
                <span className="font-medium">HTTP</span>
              </button>
            </div>
          </div>

          {/* Connection Settings */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className="mb-3">
              <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-2">{t('connectionSettings')}</h3>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  {t('ipAddress')}
                </label>
                <input
                  type="text"
                  value={settings.ip}
                  onChange={(e) => handleInputChange('ip', e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                  placeholder="127.0.0.1"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  {t('port')}
                </label>
                <input
                  type="text"
                  value={settings.port}
                  onChange={(e) => handleInputChange('port', e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                  placeholder="1080"
                />
              </div>
            </div>
          </div>

          {/* Authentication Settings */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className="mb-3">
              <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
                <div>
                  <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200">{t('authentication')}</h3>

                </div>
                <button
                  onClick={() => handleInputChange('authEnabled', !settings.authEnabled)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${settings.authEnabled
                      ? 'bg-orange-500'
                      : 'bg-slate-200 dark:bg-slate-600'
                    }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.authEnabled ? 'translate-x-6' : 'translate-x-1'
                      }`}
                  />
                </button>
              </div>
            </div>

            {settings.authEnabled && (
              <div className="grid grid-cols-2 gap-3 mt-3">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('username')}
                  </label>
                  <input
                    type="text"
                    value={settings.username}
                    onChange={(e) => handleInputChange('username', e.target.value)}
                    className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                    placeholder={t('enterUsername')}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('password')}
                  </label>
                  <input
                    type="password"
                    value={settings.password}
                    onChange={(e) => handleInputChange('password', e.target.value)}
                    className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                    placeholder={t('enterPassword')}
                  />
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* TUN Configuration - Only show when TUN mode is selected */}
      {settings.mode === 'TUN' && (
        <>
          {/* TUN Network Configuration */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className="mb-3">
              <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-2">TUN Network Configuration</h3>
            </div>

            <div className="grid grid-cols-2 gap-3 mb-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  IPv4 CIDR
                </label>
                <input
                  type="text"
                  value={settings.tunInet4CIDR}
                  onChange={(e) => handleInputChange('tunInet4CIDR', e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                  placeholder="172.19.0.1/30"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  IPv6 CIDR
                </label>
                <input
                  type="text"
                  value={settings.tunInet6CIDR}
                  onChange={(e) => handleInputChange('tunInet6CIDR', e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                  placeholder="fc00::1/126"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  MTU
                </label>
                <input
                  type="number"
                  value={settings.mtu}
                  onChange={(e) => handleInputChange('mtu', parseInt(e.target.value) || 9000)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                  placeholder="9000"
                  min="1280"
                  max="9000"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  Stack
                </label>
                <select
                  value={settings.stack}
                  onChange={(e) => handleInputChange('stack', e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                >
                  <option value="system">System</option>
                  <option value="gvisor">gVisor</option>
                  <option value="mixed">Mixed</option>
                </select>
              </div>
            </div>
          </div>

          {/* TUN Routing Options */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className="mb-3">
              <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-2">TUN Routing Options</h3>
            </div>

            <div className="space-y-3">
              {/* Auto Route */}
              <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
                <div>
                  <p className="font-medium text-slate-800 dark:text-slate-200">Auto Route</p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Automatically configure system routing
                  </p>
                </div>
                <button
                  onClick={() => handleInputChange('autoRoute', !settings.autoRoute)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${settings.autoRoute
                      ? 'bg-orange-500'
                      : 'bg-slate-200 dark:bg-slate-600'
                    }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.autoRoute ? 'translate-x-6' : 'translate-x-1'
                      }`}
                  />
                </button>
              </div>

              {/* Strict Route */}
              <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
                <div>
                  <p className="font-medium text-slate-800 dark:text-slate-200">Strict Route</p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Enforce strict routing rules
                  </p>
                </div>
                <button
                  onClick={() => handleInputChange('strictRoute', !settings.strictRoute)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${settings.strictRoute
                      ? 'bg-orange-500'
                      : 'bg-slate-200 dark:bg-slate-600'
                    }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.strictRoute ? 'translate-x-6' : 'translate-x-1'
                      }`}
                  />
                </button>
              </div>

              {/* Sniff */}
              <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
                <div>
                  <p className="font-medium text-slate-800 dark:text-slate-200">Protocol Sniffing</p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Enable protocol detection and sniffing
                  </p>
                </div>
                <button
                  onClick={() => handleInputChange('sniff', !settings.sniff)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${settings.sniff
                      ? 'bg-orange-500'
                      : 'bg-slate-200 dark:bg-slate-600'
                    }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${settings.sniff ? 'translate-x-6' : 'translate-x-1'
                      }`}
                  />
                </button>
              </div>
            </div>
          </div>

          {/* DNS Hijack Configuration */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className="mb-3">
              <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-2">DNS Hijack</h3>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                DNS Servers (comma-separated)
              </label>
              <input
                type="text"
                value={settings.dnsHijack.join(', ')}
                onChange={(e) => handleDNSHijackChange(e.target.value)}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-200"
                placeholder="8.8.8.8:53, 1.1.1.1:53"
              />
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Specify DNS servers to hijack traffic for (e.g., 8.8.8.8:53, 1.1.1.1:53)
              </p>
            </div>
          </div>
        </>
      )}

    </div>
  );
};

export default ProxyPage;
