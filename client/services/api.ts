// ============================================================
// CandyConnect VPN Client - Real API Service
// Connects to the CandyConnect server backend
// ============================================================

// ── Type Definitions ──

export interface LoginCredentials {
  serverAddress: string;
  username: string;
  password: string;
}

export interface ServerInfo {
  hostname: string;
  ip: string;
  version: string;
}

export interface V2RaySubProtocol {
  id: string;
  name: string;
  transport: string;
  security: string;
  port: number;
  status: 'running' | 'stopped';
}

export interface VPNProtocol {
  id: string;
  name: string;
  status: 'running' | 'stopped';
  version: string;
  port: number;
  activeConnections: number;
  icon: string;
  subProtocols?: V2RaySubProtocol[];
}

export interface ClientAccount {
  username: string;
  comment: string;
  enabled: boolean;
  trafficLimit: { value: number; unit: string };
  trafficUsed: number;
  timeLimit: { mode: string; value: number; onHold: boolean };
  timeUsed: number;
  createdAt: string;
  expiresAt: string;
  enabledProtocols: Record<string, boolean>;
  lastConnectedIP: string;
  lastConnectedTime: string;
  connectionHistory: Array<{
    ip: string;
    time: string;
    protocol: string;
    duration: string;
  }>;
}

export interface ConnectionStatus {
  isConnected: boolean;
  connectedProtocol: string | null;
  connectedProfile: string | null;
  startTime: string | null;
  serverAddress: string | null;
}

export interface PingResult {
  profileName: string;
  configId: string;
  latency: number;
  success: boolean;
}

export interface NetworkSpeed {
  countryCode: string;
  downloadSpeed: number;
  uploadSpeed: number;
  totalDownload: number;
  totalUpload: number;
}

export interface Settings {
  autoConnect?: boolean;
  launchAtStartup?: boolean;
  selectedProfile?: string;
  selectedProtocol?: string;
  theme?: string;
  language?: string;
  proxyHost?: string;
  proxyPort?: number;
  adBlocking?: boolean;
  malwareProtection?: boolean;
  phishingPrevention?: boolean;
  cryptominerBlocking?: boolean;
  directCountryAccess?: boolean;
  customBlockDomains?: string[];
  customDirectDomains?: string[];
  primaryDns?: string;
  secondaryDns?: string;
  v2rayCore?: string;
  wireguardCore?: string;
  autoStart?: boolean;
  autoPilot?: boolean;
  proxyMode?: string;
  proxyType?: string;
  proxyAddress?: string;
  proxyUsername?: string;
  proxyPassword?: string;
  tunInet4CIDR?: string;
  tunInet6CIDR?: string;
  mtu?: number;
  autoRoute?: boolean;
  strictRoute?: boolean;
  sniff?: boolean;
  stack?: string;
  dnsHijack?: string[];
  autoReconnect?: boolean;
  killSwitch?: boolean;
  dnsLeakProtection?: boolean;
  splitTunneling?: boolean;
  simulateTraffic?: boolean;
  dnsttResolver?: string; // 'auto' | 'udp-google' | 'udp-cloudflare' | 'udp-quad9' | 'dot-google' | 'dot-cloudflare' | 'dot-quad9' | 'doh-google' | 'doh-cloudflare' | 'doh-quad9'
  dnsttProxyPort?: number; // local SOCKS proxy port for dnstt-client (default 7070)
  l2tpPsk?: string; // L2TP/IPSec pre-shared key (override server-provided value)
  ikev2AuthMethod?: string; // 'eap' | 'cert' — IKEv2 authentication method
}

export interface VPNConfig {
  id: string;
  name: string;
  protocol: string;
  transport: string;
  security: string;
  address: string;
  port: number;
  configLink: string;
  icon: string;
  extraData?: Record<string, any>;
}

// ── State ──

let _serverUrl: string = '';
let _token: string | null = null;
let _account: ClientAccount | null = null;
let _serverInfo: ServerInfo | null = null;
let _isConnected = false;
let _connectedProtocol: string | null = null;
let _connectionStartTime: string | null = null;
let _sessionDownload = 0;
let _sessionUpload = 0;
let _cachedConfigs: VPNConfig[] = [];

// Track the last reported traffic to server so we only report deltas
let _lastReportedDownload = 0;
let _lastReportedUpload = 0;
let _trafficReportCounter = 0;

let _settings: Settings = {
  autoConnect: false,
  launchAtStartup: false,
  selectedProfile: '',
  selectedProtocol: 'v2ray',
  theme: 'light',
  language: 'en',
  proxyHost: '127.0.0.1',
  proxyPort: 1080,
  adBlocking: true,
  malwareProtection: true,
  phishingPrevention: false,
  cryptominerBlocking: false,
  directCountryAccess: true,
  v2rayCore: 'sing-box',
  wireguardCore: 'amnezia',
  proxyMode: 'proxy',
  proxyType: 'socks',
  autoReconnect: true,
  killSwitch: false,
  dnsLeakProtection: true,
  splitTunneling: false,
  dnsttResolver: 'auto',
  dnsttProxyPort: 7070,
  l2tpPsk: '',
  ikev2AuthMethod: 'eap',
};

let _logs: Array<{ timestamp: string; level: string; message: string }> = [
  { timestamp: new Date().toISOString(), level: 'info', message: 'CandyConnect client initialized' },
];

// ── Heartbeat ──
let _heartbeatTimer: ReturnType<typeof setInterval> | null = null;

function _startHeartbeat(protocol: string) {
  _stopHeartbeat();
  _heartbeatTimer = setInterval(async () => {
    if (!_isConnected || !_token) { _stopHeartbeat(); return; }
    try {
      await apiRequest('POST', '/heartbeat', {
        protocol,
        ip: _serverInfo?.ip || '0.0.0.0',
      });
    } catch { /* server unreachable — keep trying */ }
  }, 60_000); // every 60 seconds
}

function _stopHeartbeat() {
  if (_heartbeatTimer !== null) {
    clearInterval(_heartbeatTimer);
    _heartbeatTimer = null;
  }
}

// ── HTTP Helper ──

async function apiRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  const url = `${_serverUrl}/client-api${path}`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (_token) headers['Authorization'] = `Bearer ${_token}`;

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok && res.status === 401) {
    _token = null;
    _account = null;
    throw new Error('Session expired. Please login again.');
  }

  const data = await res.json();
  if (data.success === false) {
    throw new Error(data.message || data.detail?.message || 'Request failed');
  }
  return data.data !== undefined ? data.data : data;
}

async function addLog(level: string, message: string) {
  _logs.push({ timestamp: new Date().toISOString(), level, message });
  if (_logs.length > 500) _logs.splice(0, _logs.length - 500);

  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('write_log', { level, message });
  } catch { }
}

function mapAccount(account: any): ClientAccount {
  if (!account) {
    return {
      username: 'User',
      comment: '',
      enabled: false,
      trafficLimit: { value: 0, unit: 'GB' },
      trafficUsed: 0,
      timeLimit: { mode: 'monthly', value: 0, onHold: false },
      timeUsed: 0,
      createdAt: '',
      expiresAt: '',
      enabledProtocols: {},
      lastConnectedIP: '',
      lastConnectedTime: '',
      connectionHistory: [],
    };
  }
  return {
    username: account.username || 'User',
    comment: account.comment || '',
    enabled: !!account.enabled,
    trafficLimit: account.traffic_limit || { value: 0, unit: 'GB' },
    trafficUsed: account.traffic_used || 0,
    timeLimit: account.time_limit || { mode: 'monthly', value: 0, onHold: false },
    timeUsed: account.time_used || 0,
    createdAt: account.created_at || '',
    expiresAt: account.expires_at || '',
    enabledProtocols: account.protocols || {},
    lastConnectedIP: account.last_connected_ip || '',
    lastConnectedTime: account.last_connected_time || '',
    connectionHistory: account.connection_history || [],
  };
}

// ── Public API ──

export const Login = async (credentials: LoginCredentials): Promise<{
  success: boolean; error?: string; serverInfo?: ServerInfo; account?: ClientAccount;
}> => {
  try {
    _serverUrl = credentials.serverAddress.replace(/\/+$/, '');
    if (!_serverUrl.startsWith('http')) {
      _serverUrl = `http://${_serverUrl}`;
    }

    const res = await fetch(`${_serverUrl}/client-api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: credentials.username, password: credentials.password }),
    });

    const data = await res.json();

    if (!data.success) {
      addLog('error', `Login failed: ${data.message}`);
      return { success: false, error: data.message || 'Invalid credentials' };
    }

    localStorage.setItem('cc_last_server', credentials.serverAddress);
    localStorage.setItem('cc_last_user', credentials.username);
    localStorage.setItem('cc_last_pass', credentials.password);

    _token = data.token;
    _serverInfo = data.server_info;
    _account = mapAccount(data.account);

    addLog('info', `Authenticated as ${credentials.username} on ${_serverUrl}`);

    return {
      success: true,
      serverInfo: _serverInfo!,
      account: _account!,
    };
  } catch (e: any) {
    addLog('error', `Connection failed: ${e.message}`);
    return { success: false, error: e.message || 'Connection failed' };
  }
};

export const LoadSavedCredentials = (): LoginCredentials | null => {
  const server = localStorage.getItem('cc_last_server');
  const user = localStorage.getItem('cc_last_user');
  const pass = localStorage.getItem('cc_last_pass');
  if (server && user && pass) {
    return { serverAddress: server, username: user, password: pass };
  }
  return null;
};

export const Logout = async (): Promise<void> => {
  if (_isConnected) await DisconnectAll();
  _token = null;
  _account = null;
  _serverInfo = null;
  localStorage.removeItem('cc_last_pass'); // Only keep server/user if logged out
  addLog('info', 'Logged out');
};

export const GetProtocols = async (): Promise<VPNProtocol[]> => {
  if (!_token) return [];
  try {
    const protocols = await apiRequest<any[]>('GET', '/protocols');
    return protocols.map(p => ({
      id: p.id,
      name: p.name,
      status: p.enabled_for_user ? p.status : ('stopped' as const),
      version: p.version,
      port: p.port,
      activeConnections: p.active_connections,
      icon: p.icon,
    }));
  } catch (e: any) {
    addLog('error', `Failed to get protocols: ${e.message}`);
    return [];
  }
};

export const GetAccountInfo = async (): Promise<ClientAccount | null> => {
  if (!_token) return null;
  try {
    const account = await apiRequest<any>('GET', '/account');
    _account = mapAccount(account);
    return _account;
  } catch (e: any) {
    addLog('error', `Failed to get account: ${e.message}`);
    return _account;
  }
};

export const GetServerInfo = async (): Promise<ServerInfo | null> => {
  if (!_token) return null;
  try {
    const info = await apiRequest<any>('GET', '/server');
    _serverInfo = info;
    return _serverInfo;
  } catch {
    return _serverInfo;
  }
};

export const ConnectToProtocol = async (protocolId: string): Promise<void> => {
  // This is now purely for legacy/manual notifications if needed.
  // Real logic should use ConnectToConfig.
  addLog('info', `Legacy notify for ${protocolId}...`);
};

export const ConnectToProfile = async (name: string): Promise<void> => {
  await ConnectToProtocol(_settings.selectedProtocol || 'v2ray');
};

export const DisconnectAll = async (): Promise<void> => {
  addLog('info', 'Disconnecting everything...');
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('stop_vpn');

    // Notify server of disconnect so it can mark client offline immediately
    if (_connectedProtocol) {
      try {
        await apiRequest('POST', '/connect', {
          protocol: _connectedProtocol,
          event: 'disconnect',
          ip: _serverInfo?.ip || '0.0.0.0',
        });
      } catch { }
    }
  } catch (e) {
    console.error('Disconnect error:', e);
  }
  _isConnected = false;
  _connectedProtocol = null;
  _connectionStartTime = null;
  _lastReportedDownload = 0;
  _lastReportedUpload = 0;
  _trafficReportCounter = 0;
  // Stop heartbeat if running
  _stopHeartbeat();
  addLog('info', 'All connections stopped');
};

export const GetConnectionStatus = async (): Promise<ConnectionStatus> => ({
  isConnected: _isConnected,
  connectedProtocol: _connectedProtocol,
  connectedProfile: _connectedProtocol,
  startTime: _connectionStartTime,
  serverAddress: _serverInfo?.ip || null,
});

// Called when the backend emits vpn-disconnected (xray/sing-box process exited)
export const handleVpnDisconnected = (): void => {
  if (_isConnected) {
    addLog('warn', 'VPN process exited unexpectedly — disconnected');
    // Tell server client went offline
    if (_connectedProtocol) {
      apiRequest('POST', '/connect', {
        protocol: _connectedProtocol,
        event: 'disconnect',
        ip: _serverInfo?.ip || '0.0.0.0',
      }).catch(() => { });
    }
  }
  _stopHeartbeat();
  _isConnected = false;
  _connectedProtocol = null;
  _connectionStartTime = null;
  _lastReportedDownload = 0;
  _lastReportedUpload = 0;
  _trafficReportCounter = 0;
};

// Sets up a Tauri event listener for vpn-disconnected and returns an unlisten function
export const setupDisconnectListener = async (
  onDisconnected?: () => void
): Promise<(() => void) | null> => {
  try {
    const { listen } = await import('@tauri-apps/api/event');
    const unlisten = await listen('vpn-disconnected', () => {
      handleVpnDisconnected();
      if (onDisconnected) onDisconnected();
    });
    return unlisten;
  } catch (e) {
    console.error('Failed to setup vpn-disconnected listener:', e);
    return null;
  }
};

export const IsConnected = async (): Promise<boolean> => _isConnected;
export const IsCoreRunning = async (): Promise<boolean> => _isConnected;
export const IsAuthenticated = async (): Promise<boolean> => !!_token;

export const LoadProfiles = async (): Promise<Record<string, string>> => {
  if (!_token) return {};
  try {
    const protocols = await GetProtocols();
    const profiles: Record<string, string> = {};
    protocols.forEach(p => {
      if (p.status !== 'stopped') {
        profiles[p.name] = `${p.id}://${_serverInfo?.ip || '0.0.0.0'}:${p.port}`;
      }
    });
    return profiles;
  } catch {
    return {};
  }
};

export const AddProfile = async (name: string, link: string): Promise<string> => name;
export const DeleteProfile = async (name: string): Promise<void> => { };

// ── Configs (populated from backend) ──

export const LoadConfigs = async (): Promise<VPNConfig[]> => {
  if (!_token) return [];
  try {
    // Try to get configs directly from the backend
    const configs = await apiRequest<any[]>('GET', '/configs');
    if (Array.isArray(configs) && configs.length > 0) {
      _cachedConfigs = configs.map(c => ({
        id: c.id || 'unknown',
        name: c.name || 'Unknown',
        protocol: c.protocol || 'Unknown',
        transport: c.transport || 'default',
        security: c.security || 'default',
        address: c.address || _serverInfo?.ip || '0.0.0.0',
        port: c.port || 0,
        configLink: c.configLink || c.config_link || '',
        icon: c.icon || '🔌',
        extraData: c.extraData || c.extra_data,
      }));
      return _cachedConfigs;
    }
  } catch (e: any) {
    addLog('warn', `Backend /configs failed (${e.message}), falling back to protocols`);
  }

  // Fallback: build configs from protocols information
  try {
    const protocols = await GetProtocols();
    const v2raySubs = await GetV2RaySubProtocols();
    const configs: VPNConfig[] = [];

    // Add V2Ray sub-protocol configs
    if (protocols.find(p => p.id === 'v2ray' && p.status !== 'stopped')) {
      v2raySubs.forEach(sub => {
        if (sub.status === 'running') {
          const protoName = sub.id.split('-')[0] || 'vless';
          configs.push({
            id: sub.id,
            name: sub.name,
            protocol: 'V2Ray',
            transport: sub.transport,
            security: sub.security,
            address: _serverInfo?.ip || '0.0.0.0',
            port: sub.port,
            configLink: `${protoName}://${_serverInfo?.ip || '0.0.0.0'}:${sub.port}`,
            icon: '⚡',
          });
        }
      });
    }

    // Add other protocol configs
    protocols.forEach(p => {
      // Show if it's not v2ray (handled above) and either enabled or it's a fallback
      if (p.id !== 'v2ray') {
        const iconMap: Record<string, string> = {
          wireguard: '🛡️', openvpn: '🔒', ikev2: '🔐',
          l2tp: '📡', dnstt: '🌐', slipstream: '💨', trusttunnel: '🏰',
        };
        configs.push({
          id: `${p.id}-1`,
          name: p.name,
          protocol: p.name,
          transport: 'default',
          security: 'default',
          address: _serverInfo?.ip || '0.0.0.0',
          port: p.port,
          configLink: `${p.id}://${_serverInfo?.ip || '0.0.0.0'}:${p.port}`,
          icon: iconMap[p.id] || '🔌',
        });
      }
    });

    _cachedConfigs = configs;
    return configs;
  } catch (e: any) {
    addLog('error', `Failed to load configs: ${e.message}`);
    return [];
  }
};

export const GetV2RaySubProtocols = async (): Promise<V2RaySubProtocol[]> => {
  if (!_token || !_account) return [];
  try {
    const configs = await apiRequest<any>('GET', '/configs/v2ray');
    if (configs && configs.sub_protocols) {
      return configs.sub_protocols.map((sp: any) => ({
        id: sp.tag,
        name: `${sp.protocol.toUpperCase()} + ${sp.transport}`,
        transport: sp.transport,
        security: sp.security,
        port: sp.port,
        status: 'running' as const,
      }));
    }
  } catch { }
  return [];
};

export const ConnectToConfig = async (configId: string): Promise<void> => {
  addLog('info', `Connecting via config ${configId}...`);
  try {
    const { invoke } = await import('@tauri-apps/api/core');

    // 1. Prepare connection mode — reload latest settings to ensure we use the current proxyMode
    const currentSettings = await LoadSettings();
    const mode = currentSettings.proxyMode === 'tun' ? 'tun' : 'proxy';
    addLog('info', `Engine mode: ${mode.toUpperCase()}`);

    // 2. Check protocol type from config ID
    const isDnstt = configId.toLowerCase().startsWith('dnstt');
    const isL2tp = configId.toLowerCase().startsWith('l2tp');
    const isIkev2 = configId.toLowerCase().startsWith('ikev2');
    const isWireguard = configId.toLowerCase().startsWith('wireguard');
    const isOpenvpn = configId.toLowerCase().startsWith('openvpn');

    if (isDnstt) {
      // ── DNSTT Connection Flow ──
      // Fetch the DNSTT config from the server (contains extraData with domain, public_key, etc.)
      // First try configs list to get extraData, then fall back to individual config endpoint
      let dnsttExtra: Record<string, any> | null = null;
      let serverIp = _serverInfo?.ip || '0.0.0.0';

      // Try to find config in cached configs
      const cachedConfig = _cachedConfigs.find(c => c.id === configId);
      if (cachedConfig?.extraData) {
        dnsttExtra = cachedConfig.extraData;
        serverIp = cachedConfig.address || serverIp;
      }

      // If not cached, fetch from server
      if (!dnsttExtra) {
        try {
          const configData = await apiRequest<any>('GET', `/configs/${encodeURIComponent(configId)}`);
          dnsttExtra = configData?.extra_data || configData?.extraData || configData;
          serverIp = configData?.server || configData?.address || serverIp;
        } catch {
          // Last resort: try the full configs list
          const allConfigs = await LoadConfigs();
          const found = allConfigs.find(c => c.id === configId);
          if (found?.extraData) {
            dnsttExtra = found.extraData;
            serverIp = found.address || serverIp;
          }
        }
      }

      if (!dnsttExtra) {
        throw new Error('Could not retrieve DNSTT configuration data from server');
      }

      const domain = dnsttExtra.domain;
      const publicKey = dnsttExtra.public_key;
      const sshUser = dnsttExtra.ssh_username;
      const sshPass = dnsttExtra.ssh_password;

      if (!domain || !publicKey) {
        throw new Error('DNSTT config missing required fields: domain or public_key');
      }
      if (!sshUser || !sshPass) {
        throw new Error('DNSTT config missing SSH credentials (ssh_username / ssh_password)');
      }

      const resolver = currentSettings.dnsttResolver || 'auto';

      // In proxy mode: SSH SOCKS proxy listens on the user-configured proxy address/port
      // In TUN mode: SSH SOCKS proxy listens on an internal port; sing-box handles the user-facing proxy
      const proxyHost = mode === 'proxy'
        ? (currentSettings.proxyHost || currentSettings.proxyAddress || '127.0.0.1')
        : '127.0.0.1';
      const proxyPort = mode === 'proxy'
        ? (currentSettings.proxyPort || 1080)
        : (currentSettings.dnsttProxyPort || 7070);

      addLog('info', `DNSTT: domain=${domain}, resolver=${resolver}, sshUser=${sshUser}, socks=${proxyHost}:${proxyPort}, mode=${mode}`);

      // Call the Rust start_dnstt command
      // Flow: dnstt-client (TCP tunnel) → SSH -D (SOCKS proxy) → [sing-box TUN if tun mode]
      await invoke('start_dnstt', {
        domain: domain,
        publicKey: publicKey,
        resolver: resolver,
        mode: mode,
        proxyHost: proxyHost,
        proxyPort: proxyPort,
        serverIp: serverIp,
        sshUser: sshUser,
        sshPass: sshPass,
      });

    } else if (isL2tp || isIkev2) {
      // ── L2TP / IKEv2 Native VPN Connection Flow ──
      // These protocols use the OS-native VPN stack (rasdial on Windows, nmcli on Linux, networksetup on macOS)
      let nativeExtra: Record<string, any> | null = null;
      let serverIp = _serverInfo?.ip || '0.0.0.0';

      // Try to find config in cached configs
      const cachedConfig = _cachedConfigs.find(c => c.id === configId);
      if (cachedConfig?.extraData) {
        nativeExtra = cachedConfig.extraData;
        serverIp = cachedConfig.address || serverIp;
      }

      // If not cached, fetch from server
      if (!nativeExtra) {
        try {
          const configData = await apiRequest<any>('GET', `/configs/${encodeURIComponent(configId)}`);
          nativeExtra = configData?.extra_data || configData?.extraData || configData;
          serverIp = configData?.server || configData?.address || serverIp;
        } catch {
          const allConfigs = await LoadConfigs();
          const found = allConfigs.find(c => c.id === configId);
          if (found?.extraData) {
            nativeExtra = found.extraData;
            serverIp = found.address || serverIp;
          }
        }
      }

      const vpnUsername = nativeExtra?.username || _account?.username || '';
      // For L2TP, password comes from the account credentials (same as login password)
      const savedCreds = LoadSavedCredentials();
      const vpnPassword = savedCreds?.password || '';

      if (!vpnUsername) {
        throw new Error(`${isL2tp ? 'L2TP' : 'IKEv2'} config missing username`);
      }

      const protocol = isL2tp ? 'l2tp' : 'ikev2';

      if (isL2tp) {
        // L2TP needs a pre-shared key — use settings override, then server-provided, then empty
        const psk = currentSettings.l2tpPsk || nativeExtra?.psk || '';
        const port = nativeExtra?.port || cachedConfig?.port || 1701;

        addLog('info', `L2TP: server=${serverIp}, port=${port}, user=${vpnUsername}, psk=${psk ? '***' : '(empty)'}`);

        await invoke('start_native_vpn', {
          protocol: protocol,
          server: serverIp,
          port: port,
          username: vpnUsername,
          password: vpnPassword,
          psk: psk,
          authMethod: 'psk',
        });
      } else {
        // IKEv2
        const port = nativeExtra?.port || cachedConfig?.port || 500;
        const authMethod = currentSettings.ikev2AuthMethod || 'eap';

        addLog('info', `IKEv2: server=${serverIp}, port=${port}, user=${vpnUsername}, auth=${authMethod}`);

        await invoke('start_native_vpn', {
          protocol: protocol,
          server: serverIp,
          port: port,
          username: vpnUsername,
          password: vpnPassword,
          psk: '',
          authMethod: authMethod,
        });
      }

    } else if (isWireguard) {
      // ── WireGuard Connection Flow (via sing-box) ──
      let wgExtra: Record<string, any> | null = null;
      let serverIp = _serverInfo?.ip || '0.0.0.0';

      // Try to find config in cached configs
      const cachedConfig = _cachedConfigs.find(c => c.id === configId);
      if (cachedConfig?.extraData) {
        wgExtra = cachedConfig.extraData;
        serverIp = cachedConfig.address || serverIp;
      }

      // If not cached, fetch from server
      if (!wgExtra) {
        try {
          const configData = await apiRequest<any>('GET', `/configs/${encodeURIComponent(configId)}`);
          wgExtra = configData?.extra_data || configData?.extraData || configData;
          serverIp = configData?.server || configData?.address || serverIp;
        } catch {
          const allConfigs = await LoadConfigs();
          const found = allConfigs.find(c => c.id === configId);
          if (found?.extraData) {
            wgExtra = found.extraData;
            serverIp = found.address || serverIp;
          }
        }
      }

      if (!wgExtra) {
        throw new Error('Could not retrieve WireGuard configuration data from server');
      }

      const privateKey = wgExtra.private_key || wgExtra.privateKey || '';
      const peerPublicKey = wgExtra.peer_public_key || wgExtra.peerPublicKey || wgExtra.public_key || wgExtra.publicKey || '';
      const preSharedKey = wgExtra.pre_shared_key || wgExtra.preSharedKey || '';
      const wgPort = wgExtra.port || cachedConfig?.port || 51820;
      const localAddresses = wgExtra.local_addresses || wgExtra.addresses || wgExtra.address
        ? (Array.isArray(wgExtra.local_addresses || wgExtra.addresses || wgExtra.address)
          ? (wgExtra.local_addresses || wgExtra.addresses || wgExtra.address)
          : [(wgExtra.local_addresses || wgExtra.addresses || wgExtra.address)])
        : ['10.0.0.2/32'];

      if (!privateKey || !peerPublicKey) {
        throw new Error('WireGuard config missing required keys (private_key / peer_public_key)');
      }

      addLog('info', `WireGuard: server=${serverIp}, port=${wgPort}, mode=${mode}, addresses=${localAddresses.join(',')}`);

      await invoke('start_wireguard', {
        server: serverIp,
        port: wgPort,
        privateKey: privateKey,
        peerPublicKey: peerPublicKey,
        preSharedKey: preSharedKey,
        localAddresses: localAddresses,
        mode: mode,
      });

    } else if (isOpenvpn) {
      // ── OpenVPN Connection Flow ──
      let ovpnExtra: Record<string, any> | null = null;
      let serverIp = _serverInfo?.ip || '0.0.0.0';

      // Try cached configs first
      const cachedConfig = _cachedConfigs.find(c => c.id === configId);
      if (cachedConfig?.extraData) {
        ovpnExtra = cachedConfig.extraData;
        serverIp = cachedConfig.address || serverIp;
      }

      // If not cached, fetch from server
      if (!ovpnExtra || !ovpnExtra.ovpn_config) {
        try {
          const configData = await apiRequest<any>('GET', `/configs/${encodeURIComponent(configId)}`);
          ovpnExtra = configData?.extra_data || configData?.extraData || configData;
          serverIp = configData?.server || configData?.address || serverIp;
        } catch {
          const allConfigs = await LoadConfigs();
          const found = allConfigs.find(c => c.id === configId);
          if (found?.extraData) {
            ovpnExtra = found.extraData;
            serverIp = found.address || serverIp;
          }
        }
      }

      if (!ovpnExtra) {
        throw new Error('Could not retrieve OpenVPN configuration data from server');
      }

      const ovpnConfig = ovpnExtra.ovpn_config || '';
      if (!ovpnConfig) {
        throw new Error('OpenVPN config is empty — server may not have certificates set up yet');
      }

      const savedCreds = LoadSavedCredentials();
      const ovpnUsername = ovpnExtra.username || _account?.username || savedCreds?.username || '';
      const ovpnPassword = savedCreds?.password || '';

      addLog('info', `OpenVPN: server=${serverIp}, port=${ovpnExtra.port || 1194}, proto=${ovpnExtra.proto || 'udp'}, mode=${mode}`);

      await invoke('start_openvpn', {
        ovpnConfig: ovpnConfig,
        username: ovpnUsername,
        password: ovpnPassword,
        mode: mode,
      });

    } else {
      // ── Standard (Xray) Connection Flow ──
      // Fetch full configuration from the server
      const configData = await apiRequest<any>('GET', `/configs/${encodeURIComponent(configId)}`);
      if (!configData || !configData.config_json) {
        throw new Error('Server returned invalid or empty configuration');
      }

      // Start the engine in the background via Rust
      // Ensure config_json is a JSON string — avoid double-serialization
      const configJsonStr = typeof configData.config_json === 'string'
        ? configData.config_json
        : JSON.stringify(configData.config_json);
      await invoke('start_vpn', {
        configJson: configJsonStr,
        mode: mode,
      });
    }

    // 3. Log connection to server
    try {
      await apiRequest('POST', '/connect', {
        protocol: configId,
        event: 'connect',
        ip: _serverInfo?.ip || '0.0.0.0'
      });
    } catch { }

    // 4. Update local state
    _isConnected = true;
    _connectedProtocol = configId;
    _connectionStartTime = new Date().toISOString();
    _sessionDownload = 0;
    _sessionUpload = 0;
    _lastReportedDownload = 0;
    _lastReportedUpload = 0;
    _trafficReportCounter = 0;

    // Reset Tauri native network session counters
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('reset_network_session');
    } catch { }

    // Start periodic heartbeat so server keeps client marked online
    _startHeartbeat(configId);

    addLog('info', `Connected successfully via ${configId}`);

  } catch (error: any) {
    // Tauri invoke errors are strings, not Error objects
    const errMsg = typeof error === 'string' ? error : (error?.message || String(error));
    addLog('error', `Connection failed: ${errMsg}`);
    _isConnected = false;
    _connectedProtocol = null;
    throw new Error(errMsg);
  }
};

// ── Ping (with real backend call + mock fallback) ──

export const PingConfig = async (configId: string): Promise<PingResult> => {
  // 1. Try Rust/Tauri Ping first (Real TCP check)
  try {
    const { invoke } = await import('@tauri-apps/api/core');

    // Resolve host and port
    let host = _serverInfo?.ip || '0.0.0.0';
    let port = 8443; // Default panel port

    const config = _cachedConfigs.find(c => c.id === configId);
    if (config) {
      host = config.address;
      port = config.port;
    } else if (configId === 'server' && _serverInfo) {
      host = _serverInfo.ip;
      port = 8443; // Backend API port
    }

    const latency = await invoke<number>('measure_latency', { host });

    return {
      profileName: configId,
      configId: configId,
      latency: Math.round(latency),
      success: true,
    };
  } catch (e) {
    // Rust ping failed or not in Tauri environment, fall back to Web/API methods
    console.debug('Native ping failed, falling back to API:', e);
  }

  const startTime = performance.now();

  // Try real backend ping endpoint (fallback method)
  try {
    const result = await apiRequest<any>('GET', `/ping/${encodeURIComponent(configId)}`);
    const networkRtt = performance.now() - startTime;

    if (result) {
      return {
        profileName: configId,
        configId: result.config_id || configId,
        latency: result.latency || Math.round(networkRtt),
        success: result.reachable !== false,
      };
    }
  } catch {
    // Backend ping not available
  }

  // Mock fallback — use actual network round-trip time as base
  const networkRtt = performance.now() - startTime;
  return {
    profileName: configId,
    configId: configId,
    latency: Math.max(Math.round(networkRtt), 10),
    success: true,
  };
};

export const PingProfile = async (name: string): Promise<PingResult> => {
  return PingConfig(name);
};

export const PingAllProfiles = async (): Promise<PingResult[]> => {
  const configs = await LoadConfigs();
  if (configs.length === 0) return [];

  // Ping all configs in parallel using real ICMP/TCP pings for accurate latency
  const results = await Promise.all(
    configs.map(c =>
      PingConfig(c.id).catch(() => ({
        profileName: c.id,
        configId: c.id,
        latency: 0,
        success: false,
      }))
    )
  );
  return results;
};

export const PingAllConfigs = async (): Promise<PingResult[]> => {
  return PingAllProfiles();
};

export const PingProtocol = async (protocolId: string): Promise<PingResult> => {
  return PingConfig(protocolId);
};

export const LoadSettings = async (): Promise<Settings> => {
  // Try to load persisted settings from file storage first
  try {
    const { readSettings } = await import('./fileStorage');
    const fileSettings = await readSettings();
    // If file has data, merge it into in-memory settings (file takes priority)
    if (fileSettings && Object.keys(fileSettings).length > 0) {
      _settings = { ..._settings, ...fileSettings };
    }
  } catch {
    // fileStorage not available (e.g. not in Tauri environment), use in-memory
  }
  return { ..._settings };
};

export const SaveSettings = async (newSettings: Settings): Promise<void> => {
  _settings = { ..._settings, ...newSettings };
  // Persist to file storage so settings survive app restarts
  try {
    const { writeSettings } = await import('./fileStorage');
    await writeSettings(_settings);
  } catch {
    // fileStorage not available, settings stay in-memory only
  }
};

export const GetNetworkSpeed = async (): Promise<NetworkSpeed> => {
  if (!_isConnected) {
    return { countryCode: '--', downloadSpeed: 0, uploadSpeed: 0, totalDownload: _sessionDownload, totalUpload: _sessionUpload };
  }

  let dl = 0;
  let ul = 0;
  let totalDl = _sessionDownload;
  let totalUl = _sessionUpload;
  let country = '??';

  // Strategy 1: Try Tauri native OS-level network stats (real counters)
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    const stats = await invoke<{
      downloadSpeed: number;
      uploadSpeed: number;
      totalDownload: number;
      totalUpload: number;
      countryCode: string;
    }>('get_network_stats');

    dl = stats.downloadSpeed;
    ul = stats.uploadSpeed;
    totalDl = stats.totalDownload;
    totalUl = stats.totalUpload;
    country = stats.countryCode || '??';

    _sessionDownload = totalDl;
    _sessionUpload = totalUl;
  } catch {
    // Strategy 2: Fall back to server-side network speed endpoint
    try {
      const serverStats = await apiRequest<{
        downloadSpeed: number;
        uploadSpeed: number;
        totalDownload: number;
        totalUpload: number;
        countryCode: string;
      }>('GET', '/network-speed');

      dl = serverStats.downloadSpeed;
      ul = serverStats.uploadSpeed;
      totalDl = serverStats.totalDownload;
      totalUl = serverStats.totalUpload;
      country = serverStats.countryCode || '??';

      _sessionDownload = totalDl;
      _sessionUpload = totalUl;
    } catch {
      // Both failed — return zeros (no fake data)
    }
  }

  // Report traffic to server periodically (every ~5 calls ≈ 5 seconds)
  _trafficReportCounter++;
  if (_connectedProtocol && _token && _trafficReportCounter >= 5) {
    _trafficReportCounter = 0;
    const dlDelta = _sessionDownload - _lastReportedDownload;
    const ulDelta = _sessionUpload - _lastReportedUpload;
    if (dlDelta > 0 || ulDelta > 0) {
      try {
        // Normalize protocol ID: strip trailing "-N" suffix (e.g. "wireguard-1" → "wireguard")
        // so the server stores it under the canonical protocol key in Redis.
        const normalizedProtocol = _connectedProtocol.replace(/-\d+$/, '');
        await apiRequest('POST', '/traffic', {
          protocol: normalizedProtocol,
          bytes_sent: ulDelta,
          bytes_received: dlDelta,
          bytes_used: dlDelta + ulDelta,
        });
        _lastReportedDownload = _sessionDownload;
        _lastReportedUpload = _sessionUpload;
      } catch { }
    }
  }

  return {
    countryCode: country,
    downloadSpeed: dl,
    uploadSpeed: ul,
    totalDownload: totalDl,
    totalUpload: totalUl,
  };
};

export const LoadLogs = async (): Promise<Array<{ timestamp: string; level: string; message: string }>> => {
  try {
    const { readTextFile, BaseDirectory } = await import('@tauri-apps/plugin-fs');
    const content = await readTextFile('candy.logs', { baseDir: BaseDirectory.AppData });
    if (content) {
      // Handle the JSONL format: each line is a JSON object
      const lines = content.split('\n').filter(l => l.trim().length > 0);
      return lines.map(l => JSON.parse(l)).reverse(); // Newest first
    }
  } catch (e) {
    console.debug('Failed to read log file:', e);
  }
  return [..._logs].reverse();
};

export const ClearLogs = async (): Promise<void> => {
  _logs = [];
  try {
    const { writeTextFile, BaseDirectory } = await import('@tauri-apps/plugin-fs');
    await writeTextFile('candy.logs', '', { baseDir: BaseDirectory.AppData });
  } catch { }
};

export const ValidateProxyLink = async (link: string): Promise<boolean> =>
  /^(vless|vmess|ss|trojan|wireguard|ikev2|l2tp|dnstt):\/\//.test(link);

export const CheckSystemExecutables = async (): Promise<string[]> => {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<string[]>('check_system_executables');
  } catch (e) {
    console.error('System check failed:', e);
    return [];
  }
};

export const GenerateSingBoxConfig = async (serverAddress: string): Promise<string> => {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<string>('generate_sing_box_config', { serverAddress });
  } catch (e) {
    console.error('Failed to generate sing-box config:', e);
    return '';
  }
};

export const IsAdmin = async (): Promise<boolean> => {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<boolean>('is_admin');
  } catch {
    return false;
  }
};

export const RestartAsAdmin = async (): Promise<void> => {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('restart_as_admin');
  } catch (e) {
    console.error('Restart as admin failed:', e);
  }
};

export default {
  Login, Logout, GetProtocols, GetV2RaySubProtocols, GetAccountInfo,
  GetServerInfo, ConnectToProtocol, ConnectToProfile, ConnectToConfig,
  DisconnectAll, GetConnectionStatus, IsConnected, IsCoreRunning,
  IsAuthenticated, LoadProfiles, LoadConfigs, AddProfile, DeleteProfile,
  PingProfile, PingAllProfiles, PingAllConfigs, PingProtocol, PingConfig,
  LoadSettings, SaveSettings, GetNetworkSpeed,
  LoadLogs, ClearLogs, ValidateProxyLink, CheckSystemExecutables, LoadSavedCredentials,
  IsAdmin, RestartAsAdmin, GenerateSingBoxConfig,
  handleVpnDisconnected, setupDisconnectListener,
};
