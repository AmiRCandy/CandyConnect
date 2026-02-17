import React, { useEffect, useState } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import { useLanguage } from '../contexts/LanguageContext';
import { MoonIcon, SunIcon, ArrowLeftIcon, CpuIcon, NetworkIcon, ShieldIcon } from './icons';
import LanguageSelector from './LanguageSelector';
import AutoUpdateToggle from './AutoUpdateToggle';
import CoreSelector from './CoreSelector';
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

  const handleCoreChange = (coreType: string, value: string) => {
    if (!settings) return;
    const updatedSettings: Settings = {
      ...settings,
      [coreType === 'v2ray' ? 'v2rayCore' : 'wireguardCore']: value,
    };
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
        <ToggleRow
          icon={<NetworkIcon className="w-5 h-5" />}
          title={t('autoReconnect')}
          desc={t('autoReconnectDesc')}
          value={settings?.autoReconnect || false}
          onToggle={() => handleToggle('autoReconnect')}
        />
        <ToggleRow
          icon={<NetworkIcon className="w-5 h-5" />}
          title={t('splitTunneling')}
          desc={t('splitTunnelingDesc')}
          value={settings?.splitTunneling || false}
          onToggle={() => handleToggle('splitTunneling')}
        />
        <AutoUpdateToggle />
      </div>

      {/* Cores */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('cores')}</h3>
        <CoreSelector
          coreType="v2ray"
          icon={<CpuIcon className="w-6 h-6" />}
          title={t('v2rayCore')}
          options={[
            { value: 'sing-box', label: t('singBox') },
            { value: 'xray', label: t('xray') },
          ]}
          selectedValue={settings?.v2rayCore || 'sing-box'}
          onSelectionChange={(value) => handleCoreChange('v2ray', value)}
        />
        <CoreSelector
          coreType="wireguard"
          icon={<NetworkIcon className="w-6 h-6" />}
          title={t('wireGuard')}
          options={[
            { value: 'amnezia', label: t('amnezia') },
            { value: 'native', label: t('nativeWireGuard') },
          ]}
          selectedValue={settings?.wireguardCore || 'amnezia'}
          onSelectionChange={(value) => handleCoreChange('wireguard', value)}
        />
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
