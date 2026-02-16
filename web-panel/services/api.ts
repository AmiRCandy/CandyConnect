// ============================================================
// CandyConnect Server Panel - API Service
// Connects the web panel to the real server backend
// ============================================================

const API_BASE = '/api';

interface ApiResponse<T> {
  success: boolean;
  message: string;
  data?: T;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<ApiResponse<T>> {
  const token = sessionStorage.getItem('cc_token');
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok && res.status === 401) {
    sessionStorage.removeItem('cc_auth');
    sessionStorage.removeItem('cc_token');
    window.location.reload();
  }

  return res.json();
}

// ── Auth ──

export interface LoginResponse {
  success: boolean;
  message: string;
  token?: string;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  return res.json();
}

// ── Dashboard ──

export interface ServerInfo {
  hostname: string; ip: string; os: string; kernel: string; uptime: number;
  cpu: { model: string; cores: number; usage: number };
  ram: { total: number; used: number };
  disk: { total: number; used: number };
  network: { total_in: number; total_out: number; speed_in: number; speed_out: number };
}

export interface VpnCore {
  id: string; name: string; status: string; version: string;
  uptime: number; port: number; active_connections: number;
  total_traffic: { in: number; out: number };
}

export interface LogEntry {
  time: string; level: string; source: string; message: string;
}

export interface DashboardData {
  server: ServerInfo;
  vpn_cores: VpnCore[];
  logs: LogEntry[];
  stats: {
    total_clients: number;
    active_connections: number;
    running_cores: number;
    total_cores: number;
  };
}

export async function getDashboard(limit: number = 10): Promise<DashboardData> {
  const res = await request<DashboardData>('GET', `/dashboard?limit=${limit}`);
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

// ── Clients ──

export interface ClientProtocols {
  v2ray: boolean; wireguard: boolean; openvpn: boolean; ikev2: boolean;
  l2tp: boolean; dnstt: boolean; slipstream: boolean; trusttunnel: boolean;
}

export interface ConnectionHistoryEntry {
  ip: string; time: string; protocol: string; duration: string;
}

export interface Client {
  id: string; username: string; password: string; comment: string; enabled: boolean;
  group?: string;
  traffic_limit: { value: number; unit: string };
  traffic_used: number;
  protocol_traffic?: Record<string, number>;
  time_limit: { mode: string; value: number; on_hold: boolean };
  time_used: number;
  created_at: string; expires_at: string;
  protocols: ClientProtocols;
  protocol_data: Record<string, any>;
  last_connected_ip: string | null; last_connected_time: string | null;
  connection_history: ConnectionHistoryEntry[];
}

export async function getClients(): Promise<Client[]> {
  const res = await request<Client[]>('GET', '/clients');
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export async function getClient(id: string): Promise<Client> {
  const res = await request<Client>('GET', `/clients/${id}`);
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export interface CreateClientRequest {
  username: string; password: string; comment: string; enabled: boolean;
  group?: string;
  traffic_limit: { value: number; unit: string };
  time_limit: { mode: string; value: number; on_hold: boolean };
  protocols: ClientProtocols;
}

export async function createClient(data: CreateClientRequest): Promise<Client> {
  const res = await request<Client>('POST', '/clients', data);
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export interface UpdateClientRequest {
  password?: string; comment?: string; enabled?: boolean;
  group?: string;
  traffic_limit?: { value: number; unit: string };
  time_limit?: { mode: string; value: number; on_hold: boolean };
  protocols?: ClientProtocols;
}

export async function updateClient(id: string, data: UpdateClientRequest): Promise<Client> {
  const res = await request<Client>('PUT', `/clients/${id}`, data);
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export async function deleteClient(id: string): Promise<void> {
  const res = await request<void>('DELETE', `/clients/${id}`);
  if (!res.success) throw new Error(res.message);
}

// ── Logs ──

export async function getLogs(limit: number = 100): Promise<LogEntry[]> {
  const res = await request<LogEntry[]>('GET', `/logs?limit=${limit}`);
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

// ── VPN Cores ──

export async function getCores(): Promise<VpnCore[]> {
  const res = await request<VpnCore[]>('GET', '/cores');
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export async function startCore(id: string): Promise<string> {
  const res = await request<void>('POST', `/cores/${id}/start`);
  if (!res.success) throw new Error(res.message);
  return res.message;
}

export async function stopCore(id: string): Promise<string> {
  const res = await request<void>('POST', `/cores/${id}/stop`);
  if (!res.success) throw new Error(res.message);
  return res.message;
}

export async function restartCore(id: string): Promise<string> {
  const res = await request<void>('POST', `/cores/${id}/restart`);
  if (!res.success) throw new Error(res.message);
  return res.message;
}

// ── Core Configs ──

export interface CoreConfigs {
  candyconnect: {
    panel_domain: string; ssl_enabled: boolean; ssl_cert_path: string; ssl_key_path: string;
    max_clients: number; log_level: string; auto_backup: boolean; backup_interval: number;
    api_enabled: boolean; api_port: number;
  };
  wireguard: {
    listen_port: number;
    dns: string;
    address: string;
    private_key: string;
    public_key: string;
    mtu: number;
    post_up: string;
    post_down: string;
  };
  v2ray: { config_json: string };
  openvpn: {
    port: number; protocol: string; device: string; cipher: string; auth: string; dh: string;
    tls_crypt: boolean; dns1: string; dns2: string; subnet: string; max_clients: number;
    keepalive: string; comp_lzo: boolean;
  };
  ikev2: {
    port: number; nat_port: number; cipher: string; lifetime: string; margintime: string;
    dns: string; subnet: string; cert_validity: number;
  };
  l2tp: {
    port: number; ipsec_port: number; psk: string; local_ip: string; remote_range: string;
    dns: string; mtu: number; mru: number;
  };
  dnstt: {
    listen_port: number;
    domain: string;
    public_key: string;
    tunnel_mode: string;
    mtu: number;
  };
  slipstream: {
    port: number; method: string; obfs: string; obfs_host: string;
    fast_open: boolean; no_delay: boolean; udp_relay: boolean; timeout: number;
  };
  trusttunnel: {
    port: number; protocol: string; camouflage: string; fragment_size: number;
    fragment_interval: number; sni: string; alpn: string; padding: boolean; timeout: number;
  };
}

export async function getCoreConfigs(): Promise<CoreConfigs> {
  const res = await request<CoreConfigs>('GET', '/configs');
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export async function updateCoreConfig(section: string, data: unknown): Promise<string> {
  const res = await request<void>('PUT', `/configs/${section}`, data);
  if (!res.success) throw new Error(res.message);
  return res.message;
}

// ── Panel ──

export interface PanelData {
  config: { panel_port: number; panel_path: string; version: string; build_date: string };
  server: ServerInfo;
  admin_username: string;
  total_cores: number;
  total_clients: number;
}

export async function getPanel(): Promise<PanelData> {
  const res = await request<PanelData>('GET', '/panel');
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export async function updatePanel(data: { panel_port?: number; panel_path?: string }): Promise<string> {
  const res = await request<void>('PUT', '/panel', data);
  if (!res.success) throw new Error(res.message);
  return res.message;
}

export async function changePassword(current_password: string, new_password: string, confirm_password: string): Promise<string> {
  const res = await request<void>('PUT', '/panel/password', { current_password, new_password, confirm_password });
  if (!res.success) throw new Error(res.message);
  return res.message;
}

export async function restartPanel(): Promise<string> {
  const res = await request<void>('POST', '/panel/restart');
  if (!res.success) throw new Error(res.message);
  return res.message;
}
