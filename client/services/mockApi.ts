
// ============================================================
// CandyConnect VPN Client - Mock API
// Simulates connecting to a CandyConnect VPN server panel
// ============================================================

// --- Types ---

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
  trafficUsed: number; // in GB
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
  // Security rules
  adBlocking?: boolean;
  malwareProtection?: boolean;
  phishingPrevention?: boolean;
  cryptominerBlocking?: boolean;
  directCountryAccess?: boolean;
  // Custom domain lists
  customBlockDomains?: string[];
  customDirectDomains?: string[];
  // Cores
  v2rayCore?: string;
  wireguardCore?: string;
  autoStart?: boolean;
  autoPilot?: boolean;
  // Proxy options
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
  // Client-specific settings
  autoReconnect?: boolean;
  killSwitch?: boolean;
  dnsLeakProtection?: boolean;
  splitTunneling?: boolean;
}

// --- Mock Server Data (mirrors the server panel's MockData) ---

const MOCK_USERS: Record<string, { password: string; account: ClientAccount }> = {
  vault_dweller: {
    password: 'Pip3000Boy!',
    account: {
      username: 'vault_dweller',
      comment: 'Primary admin user',
      enabled: true,
      trafficLimit: { value: 100, unit: 'GB' },
      trafficUsed: 34.7,
      timeLimit: { mode: 'days', value: 30, onHold: false },
      timeUsed: 12,
      createdAt: '2026-01-15 08:30:00',
      expiresAt: '2026-02-14 08:30:00',
      enabledProtocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: true, dnstt: true, slipstream: true, trusttunnel: true },
      lastConnectedIP: '94.182.44.128',
      lastConnectedTime: '2026-02-10 11:45:02',
      connectionHistory: [
        { ip: '94.182.44.128', time: '2026-02-10 11:45:02', protocol: 'V2Ray', duration: 'Active' },
        { ip: '94.182.44.128', time: '2026-02-10 08:12:30', protocol: 'WireGuard', duration: '3h 22m' },
        { ip: '91.108.56.200', time: '2026-02-09 22:10:15', protocol: 'OpenVPN', duration: '1h 45m' },
      ],
    },
  },
  nuka_cola: {
    password: 'QuantumFizz#42',
    account: {
      username: 'nuka_cola',
      comment: 'Office network user',
      enabled: true,
      trafficLimit: { value: 50, unit: 'GB' },
      trafficUsed: 22.1,
      timeLimit: { mode: 'months', value: 3, onHold: false },
      timeUsed: 1,
      createdAt: '2026-01-20 14:00:00',
      expiresAt: '2026-04-20 14:00:00',
      enabledProtocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: false, dnstt: false, slipstream: true, trusttunnel: true },
      lastConnectedIP: '78.39.152.44',
      lastConnectedTime: '2026-02-10 11:44:58',
      connectionHistory: [
        { ip: '78.39.152.44', time: '2026-02-10 11:44:58', protocol: 'WireGuard', duration: 'Active' },
        { ip: '78.39.152.44', time: '2026-02-09 18:30:00', protocol: 'V2Ray', duration: '5h 10m' },
      ],
    },
  },
  power_armor: {
    password: 'T60-Fusion!',
    account: {
      username: 'power_armor',
      comment: 'Mobile user',
      enabled: true,
      trafficLimit: { value: 500, unit: 'MB' },
      trafficUsed: 0.312,
      timeLimit: { mode: 'days', value: 7, onHold: true },
      timeUsed: 0,
      createdAt: '2026-02-08 10:00:00',
      expiresAt: '2026-02-15 10:00:00',
      enabledProtocols: { v2ray: true, wireguard: false, openvpn: true, ikev2: true, l2tp: true, dnstt: false, slipstream: false, trusttunnel: false },
      lastConnectedIP: '5.200.67.88',
      lastConnectedTime: '2026-02-10 11:43:15',
      connectionHistory: [
        { ip: '5.200.67.88', time: '2026-02-10 11:43:15', protocol: 'OpenVPN', duration: 'Active' },
      ],
    },
  },
};

const MOCK_V2RAY_SUB_PROTOCOLS: V2RaySubProtocol[] = [
  { id: 'vless-ws', name: 'VLESS + WebSocket', transport: 'websocket', security: 'tls', port: 443, status: 'running' },
  { id: 'vless-grpc', name: 'VLESS + gRPC', transport: 'grpc', security: 'tls', port: 2053, status: 'running' },
  { id: 'vless-tcp', name: 'VLESS + TCP', transport: 'tcp', security: 'reality', port: 443, status: 'running' },
  { id: 'vmess-ws', name: 'VMess + WebSocket', transport: 'websocket', security: 'tls', port: 443, status: 'running' },
  { id: 'vmess-tcp', name: 'VMess + TCP', transport: 'tcp', security: 'tls', port: 8443, status: 'stopped' },
  { id: 'trojan-ws', name: 'Trojan + WebSocket', transport: 'websocket', security: 'tls', port: 443, status: 'running' },
  { id: 'trojan-grpc', name: 'Trojan + gRPC', transport: 'grpc', security: 'tls', port: 2083, status: 'running' },
  { id: 'shadowsocks', name: 'Shadowsocks', transport: 'tcp', security: 'aead', port: 8388, status: 'running' },
];

const MOCK_PROTOCOLS: VPNProtocol[] = [
  { id: 'v2ray', name: 'V2Ray (Xray)', status: 'running', version: '1.8.24', port: 443, activeConnections: 47, icon: '⚡', subProtocols: MOCK_V2RAY_SUB_PROTOCOLS },
  { id: 'wireguard', name: 'WireGuard', status: 'running', version: '1.0.20210914', port: 51820, activeConnections: 23, icon: '🛡️' },
  { id: 'openvpn', name: 'OpenVPN', status: 'running', version: '2.6.8', port: 1194, activeConnections: 15, icon: '🔒' },
  { id: 'ikev2', name: 'IKEv2/IPSec', status: 'running', version: '5.9.14', port: 500, activeConnections: 8, icon: '🔐' },
  { id: 'l2tp', name: 'L2TP/IPSec', status: 'stopped', version: '1.5.4', port: 1701, activeConnections: 0, icon: '📡' },
  { id: 'dnstt', name: 'DNSTT', status: 'running', version: '0.20231205', port: 53, activeConnections: 3, icon: '🌐' },
  { id: 'slipstream', name: 'SlipStream', status: 'running', version: '2.1.0', port: 8388, activeConnections: 12, icon: '💨' },
  { id: 'trusttunnel', name: 'TrustTunnel', status: 'running', version: '3.0.2', port: 9443, activeConnections: 6, icon: '🏰' },
];

const MOCK_SERVER: ServerInfo = {
  hostname: 'CC-VAULT-42',
  ip: '185.220.101.47',
  version: '1.4.2',
};

// --- Mock State ---

let isAuthenticated = false;
let currentUser: ClientAccount | null = null;
let currentServer: ServerInfo | null = null;
let isConnected = false;
let connectedProtocol: string | null = null;
let connectionStartTime: string | null = null;
let sessionTotalDownload = 0;
let sessionTotalUpload = 0;

let settings: Settings = {
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
};

let logs: Array<{ timestamp: string; level: string; message: string }> = [
  { timestamp: new Date().toISOString(), level: 'info', message: 'CandyConnect client initialized' },
  { timestamp: new Date().toISOString(), level: 'info', message: 'Ready to connect to server' },
];

// --- Mock Configs (individual connection configs per user) ---

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
}

const MOCK_CONFIGS: VPNConfig[] = [
  { id: 'vless-ws-tls', name: 'VLESS + WebSocket', protocol: 'V2Ray', transport: 'websocket', security: 'tls', address: '185.220.101.47', port: 443, configLink: 'vless://abc123@185.220.101.47:443?type=ws&security=tls#VLESS-WS', icon: '⚡' },
  { id: 'vless-grpc-tls', name: 'VLESS + gRPC', protocol: 'V2Ray', transport: 'grpc', security: 'tls', address: '185.220.101.47', port: 2053, configLink: 'vless://def456@185.220.101.47:2053?type=grpc&security=tls#VLESS-gRPC', icon: '⚡' },
  { id: 'vless-tcp-reality', name: 'VLESS + TCP (Reality)', protocol: 'V2Ray', transport: 'tcp', security: 'reality', address: '185.220.101.47', port: 443, configLink: 'vless://ghi789@185.220.101.47:443?type=tcp&security=reality#VLESS-Reality', icon: '⚡' },
  { id: 'vmess-ws-tls', name: 'VMess + WebSocket', protocol: 'V2Ray', transport: 'websocket', security: 'tls', address: '185.220.101.47', port: 443, configLink: 'vmess://eyJhZGQiOiIxODUuMjIwLjEwMS40NyJ9#VMess-WS', icon: '⚡' },
  { id: 'trojan-ws-tls', name: 'Trojan + WebSocket', protocol: 'V2Ray', transport: 'websocket', security: 'tls', address: '185.220.101.47', port: 443, configLink: 'trojan://pass123@185.220.101.47:443?type=ws#Trojan-WS', icon: '⚡' },
  { id: 'trojan-grpc-tls', name: 'Trojan + gRPC', protocol: 'V2Ray', transport: 'grpc', security: 'tls', address: '185.220.101.47', port: 2083, configLink: 'trojan://pass456@185.220.101.47:2083?type=grpc#Trojan-gRPC', icon: '⚡' },
  { id: 'shadowsocks', name: 'Shadowsocks', protocol: 'V2Ray', transport: 'tcp', security: 'aead', address: '185.220.101.47', port: 8388, configLink: 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@185.220.101.47:8388#Shadowsocks', icon: '⚡' },
  { id: 'wireguard-1', name: 'WireGuard', protocol: 'WireGuard', transport: 'udp', security: 'curve25519', address: '185.220.101.47', port: 51820, configLink: 'wireguard://key123@185.220.101.47:51820', icon: '🛡️' },
  { id: 'openvpn-1', name: 'OpenVPN (UDP)', protocol: 'OpenVPN', transport: 'udp', security: 'tls', address: '185.220.101.47', port: 1194, configLink: 'openvpn://185.220.101.47:1194?proto=udp', icon: '🔒' },
  { id: 'ikev2-1', name: 'IKEv2/IPSec', protocol: 'IKEv2', transport: 'udp', security: 'ipsec', address: '185.220.101.47', port: 500, configLink: 'ikev2://185.220.101.47:500', icon: '🔐' },
  { id: 'dnstt-1', name: 'DNSTT Tunnel', protocol: 'DNSTT', transport: 'dns', security: 'obfs', address: '185.220.101.47', port: 53, configLink: 'dnstt://185.220.101.47:53', icon: '🌐' },
  { id: 'slipstream-1', name: 'SlipStream', protocol: 'SlipStream', transport: 'tcp', security: 'tls', address: '185.220.101.47', port: 8388, configLink: 'slipstream://185.220.101.47:8388', icon: '💨' },
  { id: 'trusttunnel-1', name: 'TrustTunnel', protocol: 'TrustTunnel', transport: 'tcp', security: 'tls', address: '185.220.101.47', port: 9443, configLink: 'trusttunnel://185.220.101.47:9443', icon: '🏰' },
];

// Map user protocols to which configs they can access
const PROTOCOL_TO_CONFIG_PREFIX: Record<string, string[]> = {
  v2ray: ['vless-', 'vmess-', 'trojan-', 'shadowsocks'],
  wireguard: ['wireguard-'],
  openvpn: ['openvpn-'],
  ikev2: ['ikev2-'],
  l2tp: [],  // no configs for stopped protocol
  dnstt: ['dnstt-'],
  slipstream: ['slipstream-'],
  trusttunnel: ['trusttunnel-'],
};

// --- API Functions ---

export const Login = async (credentials: LoginCredentials): Promise<{ success: boolean; error?: string; serverInfo?: ServerInfo; account?: ClientAccount }> => {
  console.log('Mock: Login', credentials.serverAddress, credentials.username);
  await new Promise(r => setTimeout(r, 800)); // simulate network delay

  const user = MOCK_USERS[credentials.username];
  if (!user || user.password !== credentials.password) {
    logs.push({ timestamp: new Date().toISOString(), level: 'error', message: `Login failed for user: ${credentials.username}` });
    return { success: false, error: 'Invalid username or password' };
  }

  if (!user.account.enabled) {
    logs.push({ timestamp: new Date().toISOString(), level: 'error', message: `Account disabled: ${credentials.username}` });
    return { success: false, error: 'Account is disabled. Contact administrator.' };
  }

  isAuthenticated = true;
  currentUser = { ...user.account };
  currentServer = { ...MOCK_SERVER, ip: credentials.serverAddress || MOCK_SERVER.ip };

  logs.push({ timestamp: new Date().toISOString(), level: 'info', message: `Successfully authenticated as ${credentials.username} on ${credentials.serverAddress}` });

  return {
    success: true,
    serverInfo: currentServer,
    account: currentUser,
  };
};

export const Logout = async (): Promise<void> => {
  console.log('Mock: Logout');
  if (isConnected) {
    await DisconnectAll();
  }
  isAuthenticated = false;
  currentUser = null;
  currentServer = null;
  logs.push({ timestamp: new Date().toISOString(), level: 'info', message: 'Logged out from server' });
};

export const GetProtocols = async (): Promise<VPNProtocol[]> => {
  if (!isAuthenticated || !currentUser) return [];
  // Filter protocols based on user's enabled protocols
  return MOCK_PROTOCOLS.map(p => ({
    ...p,
    // Mark as unavailable if user doesn't have access
    status: currentUser!.enabledProtocols[p.id] ? p.status : 'stopped' as const,
  }));
};

export const GetAccountInfo = async (): Promise<ClientAccount | null> => {
  if (!isAuthenticated || !currentUser) return null;
  return { ...currentUser };
};

export const GetServerInfo = async (): Promise<ServerInfo | null> => {
  if (!isAuthenticated) return null;
  return currentServer ? { ...currentServer } : null;
};

export const ConnectToProtocol = async (protocolId: string): Promise<void> => {
  console.log('Mock: ConnectToProtocol', protocolId);
  await new Promise(r => setTimeout(r, 1200)); // simulate connection delay

  const protocol = MOCK_PROTOCOLS.find(p => p.id === protocolId);
  if (!protocol || protocol.status === 'stopped') {
    throw new Error(`Protocol ${protocolId} is not available`);
  }

  if (currentUser && !currentUser.enabledProtocols[protocolId]) {
    throw new Error(`You don't have access to ${protocol.name}`);
  }

  isConnected = true;
  connectedProtocol = protocolId;
  connectionStartTime = new Date().toISOString();
  sessionTotalDownload = 0;
  sessionTotalUpload = 0;

  logs.push({ timestamp: new Date().toISOString(), level: 'info', message: `Connected via ${protocol.name} on port ${protocol.port}` });
};

// Keep backward compatibility
export const ConnectToProfile = async (name: string): Promise<void> => {
  await ConnectToProtocol(settings.selectedProtocol || 'v2ray');
};

export const DisconnectAll = async (): Promise<void> => {
  console.log('Mock: DisconnectAll');
  await new Promise(r => setTimeout(r, 300));
  const prevProtocol = connectedProtocol;
  isConnected = false;
  connectedProtocol = null;
  connectionStartTime = null;
  logs.push({ timestamp: new Date().toISOString(), level: 'info', message: `Disconnected from ${prevProtocol || 'server'}` });
};

export const GetConnectionStatus = async (): Promise<ConnectionStatus> => {
  return {
    isConnected,
    connectedProtocol,
    connectedProfile: connectedProtocol,
    startTime: connectionStartTime,
    serverAddress: currentServer?.ip || null,
  };
};

export const IsConnected = async (): Promise<boolean> => isConnected;

export const IsCoreRunning = async (): Promise<boolean> => isConnected;

export const IsAuthenticated = async (): Promise<boolean> => isAuthenticated;

// Profile functions (backward compat — now maps to protocols)
export const LoadProfiles = async (): Promise<Record<string, string>> => {
  if (!isAuthenticated) return {};
  const profiles: Record<string, string> = {};
  MOCK_PROTOCOLS.forEach(p => {
    if (currentUser?.enabledProtocols[p.id]) {
      profiles[p.name] = `${p.id}://${currentServer?.ip || '0.0.0.0'}:${p.port}`;
    }
  });
  return profiles;
};

export const AddProfile = async (name: string, link: string): Promise<string> => {
  console.log('Mock: AddProfile', name, link);
  return name;
};

export const DeleteProfile = async (name: string): Promise<void> => {
  console.log('Mock: DeleteProfile', name);
};

export const PingProfile = async (name: string): Promise<PingResult> => {
  console.log('Mock: PingProfile', name);
  await new Promise(r => setTimeout(r, 300 + Math.random() * 500));
  return {
    profileName: name,
    configId: name,
    latency: Math.floor(Math.random() * 200) + 30,
    success: Math.random() > 0.1,
  };
};

export const PingAllProfiles = async (): Promise<PingResult[]> => {
  console.log('Mock: PingAllProfiles');
  const protocols = await GetProtocols();
  const results: PingResult[] = [];
  for (const p of protocols) {
    await new Promise(r => setTimeout(r, 100 + Math.random() * 200));
    results.push({
      profileName: p.name,
      configId: `${p.id}-1`,
      latency: p.status === 'running' ? Math.floor(Math.random() * 200) + 30 : 0,
      success: p.status === 'running' && Math.random() > 0.1,
    });
  }
  return results;
};

export const PingAllConfigs = async (): Promise<PingResult[]> => {
  return PingAllProfiles();
};

export const GetV2RaySubProtocols = async (): Promise<V2RaySubProtocol[]> => {
  if (!isAuthenticated || !currentUser) return [];
  if (!currentUser.enabledProtocols['v2ray']) return [];
  return [...MOCK_V2RAY_SUB_PROTOCOLS];
};

export const LoadConfigs = async (): Promise<VPNConfig[]> => {
  if (!isAuthenticated || !currentUser) return [];
  // Filter configs based on which protocols the user has enabled
  const enabledPrefixes: string[] = [];
  Object.entries(currentUser.enabledProtocols).forEach(([proto, enabled]) => {
    if (enabled && PROTOCOL_TO_CONFIG_PREFIX[proto]) {
      enabledPrefixes.push(...PROTOCOL_TO_CONFIG_PREFIX[proto]);
    }
  });
  return MOCK_CONFIGS.filter(config =>
    enabledPrefixes.some(prefix => config.id.startsWith(prefix))
  ).map(config => ({
    ...config,
    address: currentServer?.ip || config.address,
  }));
};

export const ConnectToConfig = async (configId: string): Promise<void> => {
  console.log('Mock: ConnectToConfig', configId);
  await new Promise(r => setTimeout(r, 1200)); // simulate connection delay

  const config = MOCK_CONFIGS.find(c => c.id === configId);
  if (!config) {
    throw new Error(`Config ${configId} not found`);
  }

  isConnected = true;
  connectedProtocol = configId;
  connectionStartTime = new Date().toISOString();
  sessionTotalDownload = 0;
  sessionTotalUpload = 0;

  logs.push({ timestamp: new Date().toISOString(), level: 'info', message: `Connected via ${config.name} (${config.protocol}) on port ${config.port}` });
};

export const PingConfig = async (configId: string): Promise<PingResult> => {
  console.log('Mock: PingConfig', configId);
  await new Promise(r => setTimeout(r, 200 + Math.random() * 600));
  const config = MOCK_CONFIGS.find(c => c.id === configId);
  return {
    profileName: config?.name || configId,
    configId: configId,
    latency: config ? Math.floor(Math.random() * 180) + 20 : 0,
    success: config ? Math.random() > 0.1 : false,
  };
};

export const PingProtocol = async (protocolId: string): Promise<PingResult> => {
  console.log('Mock: PingProtocol', protocolId);
  await new Promise(r => setTimeout(r, 200 + Math.random() * 600));
  const protocol = MOCK_PROTOCOLS.find(p => p.id === protocolId);
  return {
    profileName: protocol?.name || protocolId,
    configId: protocolId,
    latency: protocol?.status === 'running' ? Math.floor(Math.random() * 180) + 20 : 0,
    success: protocol?.status === 'running' ? Math.random() > 0.1 : false,
  };
};

export const LoadSettings = async (): Promise<Settings> => {
  // Try to load persisted settings from file storage first
  try {
    const { readSettings } = await import('./fileStorage');
    const fileSettings = await readSettings();
    if (fileSettings && Object.keys(fileSettings).length > 0) {
      settings = { ...settings, ...fileSettings };
    }
  } catch {
    // fileStorage not available (e.g. not in Tauri environment), use in-memory
  }
  return { ...settings };
};

export const SaveSettings = async (newSettings: Settings): Promise<void> => {
  settings = { ...settings, ...newSettings };
  // Persist to file storage so settings survive app restarts
  try {
    const { writeSettings } = await import('./fileStorage');
    await writeSettings(settings);
  } catch {
    // fileStorage not available, settings stay in-memory only
  }
};

// Simulated speed state for smooth mock traffic curves
let _mockBaseDown = 0;
let _mockBaseUp = 0;

export const GetNetworkSpeed = async (): Promise<NetworkSpeed> => {
  if (!isConnected) {
    _mockBaseDown = 0;
    _mockBaseUp = 0;
    return { countryCode: '--', downloadSpeed: 0, uploadSpeed: 0, totalDownload: sessionTotalDownload, totalUpload: sessionTotalUpload };
  }

  // Simulate realistic smooth speed with gradual ramp-up and random fluctuation
  if (_mockBaseDown === 0) {
    // First call after connect — ramp up from zero
    _mockBaseDown = 200 + Math.random() * 300;
    _mockBaseUp = 50 + Math.random() * 100;
  }

  // Gradual random walk (smooth, not jumpy)
  _mockBaseDown += (Math.random() - 0.48) * 150; // slight upward bias
  _mockBaseUp += (Math.random() - 0.48) * 40;

  // Clamp to realistic ranges
  _mockBaseDown = Math.max(100, Math.min(6000, _mockBaseDown));
  _mockBaseUp = Math.max(20, Math.min(1500, _mockBaseUp));

  const dl = Math.round(_mockBaseDown * 10) / 10;
  const ul = Math.round(_mockBaseUp * 10) / 10;

  sessionTotalDownload += dl * 1024; // accumulate bytes
  sessionTotalUpload += ul * 1024;

  return {
    countryCode: 'DE',
    downloadSpeed: dl,
    uploadSpeed: ul,
    totalDownload: sessionTotalDownload,
    totalUpload: sessionTotalUpload,
  };
};

export const LoadLogs = async (): Promise<Array<{ timestamp: string; level: string; message: string }>> => {
  return [...logs];
};

export const ClearLogs = async (): Promise<void> => {
  logs = [];
};

export const ValidateProxyLink = async (link: string): Promise<boolean> => {
  return /^(vless|vmess|ss|trojan|wireguard|ikev2|l2tp|dnstt):\/\//.test(link);
};

export default {
  Login,
  Logout,
  GetProtocols,
  GetV2RaySubProtocols,
  GetAccountInfo,
  GetServerInfo,
  ConnectToProtocol,
  ConnectToProfile,
  ConnectToConfig,
  DisconnectAll,
  GetConnectionStatus,
  IsConnected,
  IsCoreRunning,
  IsAuthenticated,
  LoadProfiles,
  LoadConfigs,
  AddProfile,
  DeleteProfile,
  PingProfile,
  PingAllProfiles,
  PingAllConfigs,
  PingProtocol,
  PingConfig,
  LoadSettings,
  SaveSettings,
  GetNetworkSpeed,
  LoadLogs,
  ClearLogs,
  ValidateProxyLink,
};
