import React, { useEffect, useState } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import { useLanguage } from '../contexts/LanguageContext';
import { MoonIcon, SunIcon, ArrowLeftIcon, CpuIcon, NetworkIcon, ShieldIcon, DnsIcon } from './icons';
import LanguageSelector from './LanguageSelector';
import AutoUpdateToggle from './AutoUpdateToggle';
import { LoadSettings, SaveSettings } from '../services/api';
import { Settings } from '../services/api';

interface SettingsPageProps {
  onBack: () => void;
}

const SettingsPage: React.FC<SettingsPageProps> = ({ onBack }) => {
  const { theme, toggleTheme } = useTheme();
  const { t, isRTL } = useLanguage();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadSettingsData = async () => {
      try {
        const loadedSettings = await LoadSettings();
        setSettings(loadedSettings);
      } catch (error) {
        console.error('Failed to load settings:', error);
        setSettings({
          language: 'en',
          theme: 'light',
          autoConnect: false,
          launchAtStartup: false,
          proxyHost: '127.0.0.1',
          proxyPort: 1080,
          autoReconnect: true,
          killSwitch: false,
          dnsLeakProtection: true,
          splitTunneling: false,
        });
      } finally {
        setLoading(false);
      }
    };
    loadSettingsData();
  }, []);

  const handleSaveSettings = async (updatedSettings: Settings) => {
    try {
      await SaveSettings(updatedSettings);
      setSettings(updatedSettings);
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  };

  const handleToggle = (key: keyof Settings) => {
    if (!settings) return;
    const updatedSettings = { ...settings, [key]: !settings[key] };
    handleSaveSettings(updatedSettings);
  };

  const handleTextChange = (key: keyof Settings, value: string) => {
    if (!settings) return;
    const updatedSettings = { ...settings, [key]: value };
    handleSaveSettings(updatedSettings);
  };

  const ToggleRow: React.FC<{
    icon: React.ReactNode;
    title: string;
    desc: string;
    value: boolean;
    onToggle: () => void;
  }> = ({ icon, title, desc, value, onToggle }) => (
    <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
      <div className={`flex items-center justify-between ${isRTL ? 'flex-row-reverse' : ''}`}>
        <div className={`flex items-center flex-1 min-w-0 ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
          <div className="text-slate-600 dark:text-slate-400 flex-shrink-0">{icon}</div>
          <div className="min-w-0">
            <p className="font-medium text-slate-800 dark:text-slate-200 text-sm">{title}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400 truncate">{desc}</p>
          </div>
        </div>
        <button
          onClick={onToggle}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none ml-3 ${value ? 'bg-orange-500' : 'bg-slate-200 dark:bg-slate-600'
            }`}
        >
          <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${value ? 'translate-x-6' : 'translate-x-1'
            }`} />
        </button>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[500px]">
        <div className="text-slate-500 dark:text-slate-400">Loading...</div>
      </div>
    );
  }

  return (
    <div className={`space-y-5 ${isRTL ? 'text-right' : 'text-left'}`}>
      {/* Header */}
      <div className={`flex items-center ${isRTL ? 'flex-row-reverse space-x-reverse space-x-4' : 'space-x-4'}`}>
        <button onClick={onBack} className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors">
          <ArrowLeftIcon className={`w-6 h-6 ${isRTL ? 'rotate-180' : ''}`} />
        </button>
        <h2 className="text-2xl font-bold text-slate-800 dark:text-slate-200">{t('settings')}</h2>
      </div>

      {/* Appearance */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('appearance')}</h3>
        <ToggleRow
          icon={theme === 'light' ? <SunIcon className="w-5 h-5" /> : <MoonIcon className="w-5 h-5" />}
          title={t('theme')}
          desc={theme === 'light' ? t('lightMode') : t('darkMode')}
          value={theme === 'dark'}
          onToggle={toggleTheme}
        />
        <LanguageSelector />
      </div>

      {/* Security */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('security')}</h3>
        <ToggleRow
          icon={<ShieldIcon className="w-5 h-5" />}
          title={t('killSwitch')}
          desc={t('killSwitchDesc')}
          value={settings?.killSwitch || false}
          onToggle={() => handleToggle('killSwitch')}
        />
        <ToggleRow
          icon={<ShieldIcon className="w-5 h-5" />}
          title={t('dnsLeakProtection')}
          desc={t('dnsLeakProtectionDesc')}
          value={settings?.dnsLeakProtection || false}
          onToggle={() => handleToggle('dnsLeakProtection')}
        />
        <ToggleRow
          icon={<ShieldIcon className="w-5 h-5" />}
          title="Ad Blocking"
          desc="Block advertisements and tracking scripts"
          value={settings?.adBlocking || false}
          onToggle={() => handleToggle('adBlocking')}
        />
        <ToggleRow
          icon={<ShieldIcon className="w-5 h-5" />}
          title="Malware Protection"
          desc="Block access to known malicious websites"
          value={settings?.malwareProtection || false}
          onToggle={() => handleToggle('malwareProtection')}
        />
      </div>

      {/* Connection */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('general')}</h3>
        <AutoUpdateToggle />
      </div>

      {/* DNSTT Resolver */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('dnsttResolver')}</h3>
        <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50 space-y-4">
          <div className={`flex items-start ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
            <div className="text-slate-600 dark:text-slate-400 flex-shrink-0 mt-0.5">
              <DnsIcon className="w-5 h-5" />
            </div>
            <div className="flex-1 space-y-3">
              <div>
                <p className="font-medium text-slate-800 dark:text-slate-200 text-sm">{t('dnsttResolver')}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('dnsttResolverDesc')}</p>
              </div>
              <select
                value={settings?.dnsttResolver || 'auto'}
                onChange={(e) => handleTextChange('dnsttResolver', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all"
              >
                <option value="auto">{t('dnsttResolverAuto')}</option>
                <optgroup label="UDP">
                  <option value="udp-google">Google (8.8.8.8:53)</option>
                  <option value="udp-cloudflare">Cloudflare (1.1.1.1:53)</option>
                  <option value="udp-quad9">Quad9 (9.9.9.9:53)</option>
                  <option value="udp-opendns">OpenDNS (208.67.222.222:53)</option>
                </optgroup>
                <optgroup label="DoT (DNS over TLS)">
                  <option value="dot-google">Google (dns.google:853)</option>
                  <option value="dot-cloudflare">Cloudflare (cloudflare-dns.com:853)</option>
                  <option value="dot-quad9">Quad9 (dns.quad9.net:853)</option>
                </optgroup>
                <optgroup label="DoH (DNS over HTTPS)">
                  <option value="doh-google">Google (https://dns.google/dns-query)</option>
                  <option value="doh-cloudflare">Cloudflare (https://cloudflare-dns.com/dns-query)</option>
                  <option value="doh-quad9">Quad9 (https://dns.quad9.net/dns-query)</option>
                </optgroup>
              </select>
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase ml-1">{t('dnsttProxyPort')}</label>
            <input
              type="number"
              value={settings?.dnsttProxyPort || 7070}
              onChange={(e) => {
                const val = parseInt(e.target.value) || 7070;
                handleSaveSettings({ ...settings!, dnsttProxyPort: val });
              }}
              placeholder="7070"
              min="1024"
              max="65535"
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all"
            />
            <p className="text-xs text-slate-400 dark:text-slate-500 ml-1">{t('dnsttProxyPortDesc')}</p>
          </div>
        </div>
      </div>

      {/* L2TP / IKEv2 Settings */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('l2tpIkev2Settings')}</h3>
        <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50 space-y-4">
          {/* L2TP Pre-Shared Key */}
          <div className={`flex items-start ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
            <div className="text-slate-600 dark:text-slate-400 flex-shrink-0 mt-0.5">
              <ShieldIcon className="w-5 h-5" />
            </div>
            <div className="flex-1 space-y-1.5">
              <p className="font-medium text-slate-800 dark:text-slate-200 text-sm">{t('l2tpPsk')}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('l2tpPskDesc')}</p>
              <input
                type="password"
                value={settings?.l2tpPsk || ''}
                onChange={(e) => handleTextChange('l2tpPsk', e.target.value)}
                placeholder="••••••••"
                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all"
              />
            </div>
          </div>

          {/* IKEv2 Auth Method */}
          <div className={`flex items-start ${isRTL ? 'flex-row-reverse space-x-reverse space-x-3' : 'space-x-3'}`}>
            <div className="text-slate-600 dark:text-slate-400 flex-shrink-0 mt-0.5">
              <ShieldIcon className="w-5 h-5" />
            </div>
            <div className="flex-1 space-y-1.5">
              <p className="font-medium text-slate-800 dark:text-slate-200 text-sm">{t('ikev2AuthMethod')}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('ikev2AuthMethodDesc')}</p>
              <select
                value={settings?.ikev2AuthMethod || 'eap'}
                onChange={(e) => handleTextChange('ikev2AuthMethod', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all"
              >
                <option value="eap">{t('ikev2Eap')}</option>
                <option value="cert">{t('ikev2Certificate')}</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* DNS Settings */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">DNS Settings</h3>
        <div className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50 space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase ml-1">Primary DNS</label>
            <input
              type="text"
              value={settings?.primaryDns || ''}
              onChange={(e) => handleTextChange('primaryDns', e.target.value)}
              placeholder="8.8.8.8"
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all"
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase ml-1">Secondary DNS</label>
            <input
              type="text"
              value={settings?.secondaryDns || ''}
              onChange={(e) => handleTextChange('secondaryDns', e.target.value)}
              placeholder="1.1.1.1"
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-orange-500/50 transition-all"
            />
          </div>
        </div>
      </div>

      {/* Debug Section */}
      <div className="space-y-3 pb-8">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Debug & Testing</h3>
        <ToggleRow
          icon={<NetworkIcon className="w-5 h-5" />}
          title="Simulate Traffic (1MB/s)"
          desc="Force-add 1MB of traffic per second for tracking tests"
          value={settings?.simulateTraffic || false}
          onToggle={() => handleToggle('simulateTraffic')}
        />
      </div>
    </div>
  );
};

export default SettingsPage;
