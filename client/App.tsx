import React, { useState, useCallback, useEffect, useRef } from 'react';
import LoginPage from './components/LoginPage';
import ConnectButton from './components/ConnectButton';
import StatusDisplay from './components/StatusDisplay';
import SettingsMenu from './components/SettingsMenu';
import SettingsPage from './components/SettingsPage';
import AboutPage from './components/AboutPage';
import AccountInfo from './components/AccountInfo';
import ProxyPage from './components/ProxyPage';
import LogsPage from './components/LogsPage';
import ProfilesPage from './components/ProfilesPage';
import SpeedMonitor from './components/SpeedMonitor';
import ScrollDownArrow from './components/ScrollDownArrow';
import { ThemeProvider } from './contexts/ThemeContext';
import { LanguageProvider, useLanguage } from './contexts/LanguageContext';
import { GearIcon, InformationCircleIcon } from './components/icons';
import {
  ConnectToProtocol,
  ConnectToConfig,
  DisconnectAll,
  GetConnectionStatus,
  IsConnected,
  IsCoreRunning,
  Logout,
  GetAccountInfo,
  LoadConfigs,
  CheckSystemExecutables,
  LoadSavedCredentials,
  Login,
  IsAdmin,
  RestartAsAdmin,
} from './services/api';
import type { ServerInfo, ClientAccount, VPNConfig } from './services/api';


const AppContent: React.FC = () => {
  const { t, isRTL } = useLanguage();

  // Auth state
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null);
  const [clientAccount, setClientAccount] = useState<ClientAccount | null>(null);

  // Connection state
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectedProtocol, setConnectedProtocol] = useState<string | null>(null);
  const [connectionError, setConnectionError] = useState('');
  const [missingTools, setMissingTools] = useState<string[]>([]);
  const [isAdmin, setIsAdmin] = useState(true); // Default to true to avoid flash

  // Configs state (for resolving config names in status display)
  const [configsMap, setConfigsMap] = useState<Record<string, VPNConfig>>({});

  // Latency state
  const [pingValue, setPingValue] = useState<number | undefined>(undefined);
  const [pingSuccess, setPingSuccess] = useState(false);
  const [isPinging, setIsPinging] = useState(false);

  // Navigation state
  const [currentPage, setCurrentPage] = useState<'home' | 'settings' | 'about' | 'account' | 'proxy' | 'logs' | 'profiles'>('home');

  // Scroll container ref
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Initial Startup Actions
  useEffect(() => {
    const startup = async () => {
      // 1. Check system executables
      try {
        const missing = await CheckSystemExecutables();
        setMissingTools(missing);
      } catch (e) {
        console.error('System check failed:', e);
      }

      // 1.5 Check if admin
      try {
        const admin = await IsAdmin();
        setIsAdmin(admin);
      } catch { }

      // 2. Auto-login if we have saved credentials
      const saved = LoadSavedCredentials();
      if (saved) {
        try {
          const res = await Login(saved);
          if (res.success && res.serverInfo && res.account) {
            handleLoginSuccess(res.serverInfo, res.account);
          }
        } catch {
          // Silent fail on auto-login
        }
      }
    };
    startup();
  }, []);

  // Connection monitoring
  useEffect(() => {
    if (!isLoggedIn) return;

    const checkStatus = async () => {
      try {
        const status = await GetConnectionStatus();
        setIsConnected(status.isConnected);
        setConnectedProtocol(status.connectedProtocol);
      } catch (err) {
        console.error('Status check error:', err);
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 3000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  // Refresh account info periodically
  useEffect(() => {
    if (!isLoggedIn) return;
    const refreshAccount = async () => {
      try {
        const account = await GetAccountInfo();
        if (account) setClientAccount(account);
      } catch { }
    };
    const interval = setInterval(refreshAccount, 10000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  const handleLoginSuccess = async (server: ServerInfo, account: ClientAccount) => {
    setServerInfo(server);
    setClientAccount(account);
    setIsLoggedIn(true);
    setCurrentPage('home');

    // Preload configs map for better status labels
    try {
      const cfgs = await LoadConfigs();
      const map: Record<string, VPNConfig> = {};
      cfgs.forEach(c => { map[c.id] = c; });
      setConfigsMap(map);
    } catch { }
  };

  const handleLogout = async () => {
    try {
      await Logout();
    } catch { }
    setIsLoggedIn(false);
    setIsConnected(false);
    setIsConnecting(false);
    setConnectedProtocol(null);
    setServerInfo(null);
    setClientAccount(null);
    setCurrentPage('home');
    setPingValue(undefined);
  };

  const handlePing = async () => {
    if (isPinging) return;
    setIsPinging(true);
    try {
      const { PingConfig } = await import('./services/api');
      // If connected, ping the specific protocol config, otherwise generic server info
      const target = isConnected && connectedProtocol ? connectedProtocol : 'server';
      const result = await PingConfig(target);
      setPingValue(result.latency);
      setPingSuccess(result.success);
    } catch {
      setPingSuccess(false);
    } finally {
      setIsPinging(false);
    }
  };

  const handleConnectToProtocol = async (configId: string) => {
    setIsConnecting(true);
    setConnectionError('');
    try {
      if (isConnected) {
        await DisconnectAll();
        setIsConnected(false);
        setConnectedProtocol(null);
        // small delay before reconnecting to a different config
        await new Promise(r => setTimeout(r, 300));
      }

      // New flow: connect by config id (mocked for now)
      await ConnectToConfig(configId);
      setIsConnected(true);
      setConnectedProtocol(configId);

      // Refresh configs map in case server changed or configs updated
      try {
        const cfgs = await LoadConfigs();
        const map: Record<string, VPNConfig> = {};
        cfgs.forEach(c => { map[c.id] = c; });
        setConfigsMap(map);
      } catch { }
    } catch (error: any) {
      // Backward compatibility: if it's not a config id, try connecting by protocol id
      try {
        await ConnectToProtocol(configId);
        setIsConnected(true);
        setConnectedProtocol(configId);
      } catch {
        setConnectionError(error?.message || 'Connection failed');
        setIsConnected(false);
        setConnectedProtocol(null);
      }
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setIsConnecting(true);
    setConnectionError('');
    try {
      await DisconnectAll();
      setIsConnected(false);
      setConnectedProtocol(null);
    } catch (error: any) {
      setConnectionError(error?.message || 'Disconnect failed');
    } finally {
      setIsConnecting(false);
    }
  };

  const handleConnectToggle = async () => {
    if (isConnected) {
      await handleDisconnect();
      return;
    }

    // Connect with the last selected config (fallback to first available)
    try {
      const { LoadSettings } = await import('./services/api');
      const settings = await LoadSettings();
      const selected = (settings as any).selectedProfile as string | undefined;
      if (selected) {
        await handleConnectToProtocol(selected);
        return;
      }
    } catch { }

    try {
      const cfgs = await LoadConfigs();
      if (cfgs.length > 0) {
        await handleConnectToProtocol(cfgs[0].id);
        return;
      }
    } catch { }

    // Final fallback (legacy)
    await handleConnectToProtocol(connectedProtocol || 'v2ray');
  };

  // Render login page if not authenticated
  if (!isLoggedIn) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  const statusLocation = isConnected && connectedProtocol
    ? `${configsMap[connectedProtocol]?.name || connectedProtocol} · ${serverInfo?.ip || ''}`
    : serverInfo?.ip
      ? `${serverInfo.hostname} (${serverInfo.ip})`
      : t('disconnected');

  // Page content renderer
  const renderPage = () => {
    switch (currentPage) {
      case 'settings':
        return <SettingsPage onBack={() => setCurrentPage('home')} />;
      case 'about':
        return <AboutPage onBack={() => setCurrentPage('home')} />;
      case 'account':
        return clientAccount
          ? <AccountInfo account={clientAccount} onBack={() => setCurrentPage('home')} />
          : <div className="text-center py-10 text-slate-500">{t('connectionError')}</div>;
      case 'proxy':
        return <ProxyPage onBack={() => setCurrentPage('home')} />;
      case 'logs':
        return <LogsPage onBack={() => setCurrentPage('home')} />;
      case 'profiles':
        return (
          <ProfilesPage
            isConnected={isConnected}
            isConnecting={isConnecting}
            connectedProtocol={connectedProtocol}
            onConnect={handleConnectToProtocol}
            onDisconnect={handleDisconnect}
            onBack={() => setCurrentPage('home')}
          />
        );
      default:
        return (
          <>
            {/* Title */}
            <h1 className="text-center text-4xl font-black text-slate-800 dark:text-slate-200 tracking-tight transition-colors">
              CandyConnect
            </h1>

            {/* Server Info Bar */}
            <div className={`flex items-center justify-between bg-white/60 dark:bg-slate-700/40 rounded-xl px-3 py-2 ${isRTL ? 'flex-row-reverse' : ''}`}>
              <div className={`flex items-center ${isRTL ? 'flex-row-reverse space-x-reverse space-x-2' : 'space-x-2'}`}>
                <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-slate-400'}`}></div>
                <span className="text-xs font-medium text-slate-600 dark:text-slate-400 truncate">
                  {serverInfo?.hostname} · {serverInfo?.ip}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="text-xs text-red-500 hover:text-red-600 dark:text-red-400 dark:hover:text-red-300 font-semibold transition-colors px-2 py-1"
              >
                {t('logout')}
              </button>
            </div>

            {/* Connect Button */}
            <ConnectButton
              isConnected={isConnected}
              isConnecting={isConnecting}
              onClick={handleConnectToggle}
            />

            {/* Connection Error */}
            {connectionError && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-3">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full flex-shrink-0"></div>
                  <p className="text-red-700 dark:text-red-300 text-sm font-medium flex-1">{connectionError}</p>
                  <button
                    onClick={() => setConnectionError('')}
                    className="text-red-500 hover:text-red-700 text-xs font-medium"
                  >
                    ✕
                  </button>
                </div>
              </div>
            )}

            {/* System Check Warning */}
            {missingTools.length > 0 && (
              <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-xl p-3">
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-amber-500 rounded-full flex-shrink-0 mt-1.5"></div>
                  <div className="flex-1">
                    <p className="text-amber-700 dark:text-amber-300 text-sm font-bold">Engine Missing</p>
                    <p className="text-amber-600 dark:text-amber-400 text-xs mt-0.5">
                      The following components are missing: {missingTools.join(', ')}. Some protocols may not work.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Admin Privilege Warning */}
            {!isAdmin && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-3">
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-red-500 rounded-full flex-shrink-0 mt-1.5"></div>
                  <div className="flex-1">
                    <p className="text-red-700 dark:text-red-300 text-sm font-bold">Admin Privileges Required</p>
                    <p className="text-red-600 dark:text-red-400 text-xs mt-0.5">
                      CandyConnect needs administrator rights to manage VPN connections and system routes.
                    </p>
                    <button
                      onClick={() => RestartAsAdmin()}
                      className="mt-2 text-[10px] bg-red-600 hover:bg-red-700 text-white px-2 py-1 rounded-md font-bold uppercase tracking-wider transition-colors"
                    >
                      Restart as Admin
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Status Display */}
            <StatusDisplay
              isConnected={isConnected}
              isConnecting={isConnecting}
              location={statusLocation}
              ping={pingValue}
              pingSuccess={pingSuccess}
              isPinging={isPinging}
              onLocationClick={handlePing}
            />

            {/* Speed Monitor */}
            <SpeedMonitor />

            {/* Divider */}
            <div className="border-t border-slate-200/80 dark:border-slate-600/50 transition-colors"></div>

            {/* Settings Menu */}
            <SettingsMenu
              onProfilesClick={() => setCurrentPage('profiles')}
              onAccountClick={() => setCurrentPage('account')}
              onProxyClick={() => setCurrentPage('proxy')}
              onLogsClick={() => setCurrentPage('logs')}
            />
          </>
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#FBEFE0] dark:bg-slate-900 flex items-center justify-center transition-colors">
      <div className="w-full max-w-sm mx-auto bg-[#FBEFE0] dark:bg-slate-800 sm:rounded-2xl sm:shadow-2xl sm:shadow-orange-200/50 sm:dark:shadow-slate-900/50 transition-colors flex flex-col min-h-screen sm:min-h-0 sm:max-h-[90vh]">
        {/* Header - Draggable Title Bar */}
        <div
          className="flex justify-between items-center p-4 pb-0 flex-shrink-0"
          onMouseDown={(e) => {
            // Only start dragging from the header background, not from buttons
            if ((e.target as HTMLElement).closest('button')) return;
            e.preventDefault();
            import('@tauri-apps/api/window').then(({ getCurrentWindow }) => {
              getCurrentWindow().startDragging();
            });
          }}
        >
          <div className="flex items-center space-x-1">
            <button
              onClick={() => {
                import('@tauri-apps/api/window').then(({ getCurrentWindow }) => {
                  getCurrentWindow().close();
                });
              }}
              className="w-3 h-3 rounded-full bg-red-400 hover:bg-red-500 transition-colors border-0 p-0 cursor-pointer"
              title="Close"
            ></button>
            <button
              onClick={() => {
                import('@tauri-apps/api/window').then(({ getCurrentWindow }) => {
                  getCurrentWindow().minimize();
                });
              }}
              className="w-3 h-3 rounded-full bg-yellow-400 hover:bg-yellow-500 transition-colors border-0 p-0 cursor-pointer"
              title="Minimize"
            ></button>
            <div className="w-3 h-3 rounded-full bg-green-400"></div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage(currentPage === 'about' ? 'home' : 'about')}
              className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors p-1"
            >
              <InformationCircleIcon className="w-6 h-6" />
            </button>
            <button
              onClick={() => setCurrentPage(currentPage === 'settings' ? 'home' : 'settings')}
              className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300 transition-colors p-1"
            >
              <GearIcon className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Scrollable Content */}
        <div
          ref={scrollContainerRef}
          className="flex-1 overflow-y-auto px-5 py-4 space-y-4"
          style={{ WebkitOverflowScrolling: 'touch' }}
        >
          {renderPage()}
        </div>

        {/* Scroll Down Arrow */}
        <ScrollDownArrow containerRef={scrollContainerRef as React.RefObject<HTMLElement>} />
      </div>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <ThemeProvider>
      <LanguageProvider>
        <AppContent />
      </LanguageProvider>
    </ThemeProvider>
  );
};

export default App;
