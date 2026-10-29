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

  let json: any = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }

  // 401 = invalid/expired token; 403 "Not authenticated" = missing bearer header
  if (res.status === 401 || (res.status === 403 && json?.message === 'Not authenticated')) {
    sessionStorage.removeItem('cc_auth');
    sessionStorage.removeItem('cc_token');
    window.location.reload();
  }

  return normalizeResponse<T>(res, json);
}

// Server errors normally come back as {success: false, message}, but FastAPI
// validation errors (422) use {detail: [...]} and proxies may return non-JSON.
function normalizeResponse<T>(res: Response, json: any): ApiResponse<T> {
  if (json && typeof json === 'object' && typeof json.success === 'boolean') {
    if (!json.success && !json.message) json.message = `Request failed (HTTP ${res.status})`;
    return json;
  }
  if (json && typeof json === 'object' && json.detail !== undefined) {
    const detail = Array.isArray(json.detail)
      ? json.detail.map((d: any) => d?.msg ? `${(d.loc || []).slice(1).join('.')}: ${d.msg}` : String(d)).join('; ')
      : String(json.detail);
    return { success: false, message: detail || `Request failed (HTTP ${res.status})` };
  }
  if (!res.ok) return { success: false, message: `Request failed (HTTP ${res.status})` };
  return { success: true, message: '', ...(json && typeof json === 'object' ? json : {}) };
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
  let json: any = null;
  try { json = await res.json(); } catch { json = null; }
  return normalizeResponse<never>(res, json) as LoginResponse;
}

// ── Dashboard ──

export interface ServerInfo {
  hostname: string; domain?: string; ip: string; os: string; kernel: string; uptime: number;
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
    online_clients: number;
    total_traffic: number;
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
  ip: string; time: string; protocol: string; event?: string; duration?: string;
}

export interface Client {
  id: string; username: string; password: string; comment: string; enabled: boolean;
  is_online: boolean;
  group?: string;
  traffic_limit: { value: number; unit: string };
  traffic_used: number;
  protocol_traffic?: Record<string, number>;
  time_limit: { mode: string; value: number; on_hold: boolean };
  time_used: number;
  created_at: string; expires_at: string;
  created_ts?: number | null; expires_ts?: number | null;   // unix seconds
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

export async function getLogs(limit: number = 100, source?: string): Promise<LogEntry[]> {
  const query = new URLSearchParams({ limit: limit.toString() });
  if (source) query.set('source', source);

  const res = await request<LogEntry[]>('GET', `/logs?${query.toString()}`);
  if (!res.success || !res.data) throw new Error(res.message);
  return res.data;
}

export type TunnelTransport = 'tcp' | 'tcpmux' | 'ws' | 'wsmux';
export type TunnelStatus = 'pending' | 'installing' | 'installed' | 'failed';

export interface Tunnel {
  id: string; name: string; ip: string; port: number; status: TunnelStatus | string;
  username?: string; type?: string; created_at?: number;
  transport?: TunnelTransport | string; tunnel_port?: number;
  ports?: string[]; accept_udp?: boolean;
  error?: string | null; has_password?: boolean; local_running?: boolean;
}

export interface AddTunnelRequest {
  name: string; ip: string;
  port: number;            // SSH port of the relay
  username: string;
  password?: string;       // if given, the server installs the relay over SSH
  tunnel_type: 'backhaul';
  transport: TunnelTransport;
  tunnel_port: number;     // Backhaul port on the relay
  ports?: string;          // "443, 8080" or "8443=443"; empty = all VPN TCP ports
  accept_udp: boolean;
}

export async function getTunnels(): Promise<Tunnel[]> {
  const res = await request<Tunnel[]>('GET', '/tunnels');
  return res.data || [];
}

export async function addTunnel(data: AddTunnelRequest): Promise<{ message: string; install_command: string; data?: Tunnel }> {
  const res = await request<Tunnel>('POST', '/tunnels', data);
  if (!res.success) throw new Error(res.message);
  const r = res as ApiResponse<Tunnel> & { install_command?: string };
  return { message: r.message, install_command: r.install_command || '', data: r.data };
}

export async function reinstallTunnel(id: string): Promise<string> {
  const res = await request<void>('POST', `/tunnels/${id}/reinstall`);
  if (!res.success) throw new Error(res.message);
  return res.message;
}

export async function deleteTunnel(id: string): Promise<void> {
  const res = await request<void>('DELETE', `/tunnels/${id}`);
  if (!res.success) throw new Error(res.message);
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
    bind_interface?: string;
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
    domain: string;               // NS-delegated tunnel domain, e.g. s.example.com
    dns_listen_port: number;      // default 5301
    congestion_control: 'bbr' | 'dcubic' | string;
  };
  trusttunnel: {
    port: number;                 // default 9443
    hostname: string;             // TLS SNI / certificate name
    cert_path: string;            // cert_path + key_path empty = auto self-signed
    key_path: string;
    enable_http1: boolean; enable_http2: boolean; enable_quic: boolean;
    ipv6_available: boolean; allow_private_network_connections: boolean;
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

export interface UpdatePanelResult { message: string; restart_required: boolean }

export async function updatePanel(data: { panel_port?: number; panel_path?: string }): Promise<UpdatePanelResult> {
  const res = await request<void>('PUT', '/panel', data);
  if (!res.success) throw new Error(res.message);
  return { message: res.message, restart_required: !!(res as any).restart_required };
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
