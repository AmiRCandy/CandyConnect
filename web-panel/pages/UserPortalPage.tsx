import React, { useState, useEffect } from 'react';
import {
  Candy, User, Lock, Eye, EyeOff, Loader2, LogOut,
  Copy, Download, CheckCircle2, XCircle, Clock, Wifi,
  ChevronDown, ChevronUp, Shield,
} from 'lucide-react';

// ── Client API helpers ──────────────────────────────────────────────────────
const CLIENT_API = '/client-api';

async function clientRequest<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${CLIENT_API}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (data.success === false) throw new Error(data.message || 'Request failed');
  return data.data !== undefined ? data.data : data;
}

interface Account {
  username: string;
  comment: string;
  enabled: boolean;
  traffic_limit: { value: number; unit: string };
  traffic_used: number;
  time_limit: { mode: string; value: number; onHold?: boolean };
  time_used: number;
  created_at: string;
  expires_at: string;
  protocols: Record<string, boolean>;
  last_connected_ip: string;
  last_connected_time: string;
}

interface VPNConfig {
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

// ── Format helpers ───────────────────────────────────────────────────────────
function fmtTraffic(gb: number): string {
  if (gb < 1) return `${(gb * 1024).toFixed(0)} MB`;
  return `${gb.toFixed(2)} GB`;
}

function fmtTrafficLimit(used: number, limit: { value: number; unit: string }): string {
  const usedFmt = fmtTraffic(used);
  const limitFmt = limit.unit === 'MB' ? `${limit.value} MB` : `${limit.value} GB`;
  return `${usedFmt} / ${limitFmt}`;
}

function trafficPct(used: number, limit: { value: number; unit: string }): number {
  const limitGB = limit.unit === 'MB' ? limit.value / 1024 : limit.value;
  if (limitGB <= 0) return 0;
  return Math.min(100, Math.round((used / limitGB) * 100));
}

// ── Copy helper ──────────────────────────────────────────────────────────────
function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch { }
  };
  return { copied, copy };
}

// ── WireGuard config builder ─────────────────────────────────────────────────
function buildWireguardConfig(cfg: VPNConfig): string {
  const e = cfg.extraData || {};
  return [
    '[Interface]',
    `PrivateKey = ${e.private_key || ''}`,
    `Address = ${e.address || '10.0.0.2/32'}`,
    `DNS = ${e.dns || '1.1.1.1'}`,
    `MTU = ${e.mtu || 1420}`,
    '',
    '[Peer]',
    `PublicKey = ${e.public_key || ''}`,
    `AllowedIPs = 0.0.0.0/0, ::/0`,
    `Endpoint = ${cfg.address}:${cfg.port}`,
    'PersistentKeepalive = 25',
  ].join('\n');
}

// ── Download helper ──────────────────────────────────────────────────────────
function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Config Card ──────────────────────────────────────────────────────────────
const ConfigCard: React.FC<{ cfg: VPNConfig }> = ({ cfg }) => {
  const { copied, copy } = useCopy();
  const [expanded, setExpanded] = useState(false);

  const isWireguard = cfg.protocol.toLowerCase() === 'wireguard';
  const isOpenvpn = cfg.protocol.toLowerCase() === 'openvpn';
  const isL2tp = cfg.protocol.toLowerCase() === 'l2tp';
  const isIkev2 = cfg.protocol.toLowerCase() === 'ikev2';
  const e = cfg.extraData || {};

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-sm">
      {/* Header row */}
      <div className="flex items-center justify-between px-4 py-3 gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-2xl flex-shrink-0">{cfg.icon}</span>
          <div className="min-w-0">
            <p className="font-semibold text-slate-800 dark:text-slate-100 text-sm truncate">{cfg.name}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">{cfg.address}:{cfg.port}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Copy config link */}
          {cfg.configLink && (
            <button
              onClick={() => copy(cfg.configLink, `link-${cfg.id}`)}
              title="Copy connection link"
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400 hover:bg-orange-100 dark:hover:bg-orange-900/40 transition-colors"
            >
              {copied === `link-${cfg.id}` ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copied === `link-${cfg.id}` ? 'Copied!' : 'Copy'}
            </button>
          )}
          {/* WireGuard: download .conf */}
          {isWireguard && e.private_key && (
            <button
              onClick={() => downloadText(`wg-${cfg.address}.conf`, buildWireguardConfig(cfg))}
              title="Download WireGuard config"
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-100 dark:hover:bg-emerald-900/40 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              .conf
            </button>
          )}
          {/* OpenVPN: download .ovpn */}
          {isOpenvpn && e.ovpn_config && (
            <button
              onClick={() => downloadText(`candyconnect-${cfg.address}.ovpn`, e.ovpn_config)}
              title="Download OpenVPN config"
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              .ovpn
            </button>
          )}
          {/* Expand for details */}
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-slate-100 dark:border-slate-700 px-4 py-3 bg-slate-50 dark:bg-slate-800/50 space-y-2 text-xs">
          <div className="flex flex-wrap gap-2">
            <span className="px-2 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800 font-semibold">
              {cfg.security.toUpperCase()}
            </span>
            <span className="px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 font-medium">
              {cfg.transport}
            </span>
          </div>

          {/* VLESS/VMess link */}
          {cfg.configLink && (cfg.configLink.startsWith('vless://') || cfg.configLink.startsWith('vmess://') || cfg.configLink.startsWith('trojan://')) && (
            <div>
              <p className="text-slate-500 dark:text-slate-400 mb-1 font-semibold">Connection Link</p>
              <div className="flex items-center gap-2 bg-white dark:bg-slate-700 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600">
                <p className="text-slate-600 dark:text-slate-300 flex-1 break-all font-mono text-[10px]">{cfg.configLink}</p>
                <button onClick={() => copy(cfg.configLink, `full-${cfg.id}`)} className="flex-shrink-0 text-slate-400 hover:text-orange-500 transition-colors">
                  {copied === `full-${cfg.id}` ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          )}

          {/* L2TP / IKEv2 credentials */}
          {(isL2tp || isIkev2) && (
            <div className="space-y-1.5">
              <p className="text-slate-500 dark:text-slate-400 font-semibold">Connection Details</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-white dark:bg-slate-700 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600">
                  <p className="text-slate-400 dark:text-slate-500 text-[10px] mb-0.5">Server</p>
                  <p className="text-slate-700 dark:text-slate-200 font-mono">{cfg.address}</p>
                </div>
                <div className="bg-white dark:bg-slate-700 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600">
                  <p className="text-slate-400 dark:text-slate-500 text-[10px] mb-0.5">Port</p>
                  <p className="text-slate-700 dark:text-slate-200 font-mono">{cfg.port}</p>
                </div>
                {e.username && (
                  <div className="bg-white dark:bg-slate-700 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600 col-span-2">
                    <p className="text-slate-400 dark:text-slate-500 text-[10px] mb-0.5">Username</p>
                    <div className="flex items-center gap-2">
                      <p className="text-slate-700 dark:text-slate-200 font-mono flex-1">{e.username}</p>
                      <button onClick={() => copy(e.username, `user-${cfg.id}`)} className="text-slate-400 hover:text-orange-500 transition-colors">
                        {copied === `user-${cfg.id}` ? <CheckCircle2 className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* WireGuard key info */}
          {isWireguard && (
            <div className="space-y-1.5">
              <p className="text-slate-500 dark:text-slate-400 font-semibold">WireGuard Details</p>
              {e.address && (
                <div className="bg-white dark:bg-slate-700 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600">
                  <p className="text-slate-400 dark:text-slate-500 text-[10px] mb-0.5">Tunnel Address</p>
                  <p className="text-slate-700 dark:text-slate-200 font-mono">{e.address}</p>
                </div>
              )}
              {e.dns && (
                <div className="bg-white dark:bg-slate-700 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-600">
                  <p className="text-slate-400 dark:text-slate-500 text-[10px] mb-0.5">DNS</p>
                  <p className="text-slate-700 dark:text-slate-200 font-mono">{e.dns}</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ── Main User Portal ─────────────────────────────────────────────────────────
const UserPortalPage: React.FC = () => {
  const [dark, setDark] = useState(() => localStorage.getItem('cc-theme') === 'dark');
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem('cc_user_token'));
  const [account, setAccount] = useState<Account | null>(null);
  const [configs, setConfigs] = useState<VPNConfig[]>([]);

  // Login form state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loginError, setLoginError] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);

  // Loading state after login
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('cc-theme', dark ? 'dark' : 'light');
  }, [dark]);

  useEffect(() => {
    if (token) loadData(token);
  }, [token]);

  const loadData = async (t: string) => {
    setDataLoading(true);
    try {
      const [acc, cfgs] = await Promise.all([
        clientRequest<Account>('GET', '/account', undefined, t),
        clientRequest<VPNConfig[]>('GET', '/configs', undefined, t),
      ]);
      setAccount(acc);
      setConfigs(Array.isArray(cfgs) ? cfgs : []);
    } catch (e: any) {
      // Token invalid — force re-login
      sessionStorage.removeItem('cc_user_token');
      setToken(null);
    } finally {
      setDataLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginLoading(true);
    setLoginError('');
    try {
      const res = await fetch(`${CLIENT_API}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (data.success && data.token) {
        sessionStorage.setItem('cc_user_token', data.token);
        setToken(data.token);
      } else {
        setLoginError(data.message || 'Invalid username or password');
        setLoginLoading(false);
      }
    } catch {
      setLoginError('Connection failed. Is the server running?');
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    sessionStorage.removeItem('cc_user_token');
    setToken(null);
    setAccount(null);
    setConfigs([]);
    setUsername('');
    setPassword('');
  };

  const pct = account ? trafficPct(account.traffic_used, account.traffic_limit) : 0;

  // ── Login Screen ─────────────────────────────────────────────────────────
  if (!token) {
    return (
      <div className="min-h-screen bg-[#FBEFE0] dark:bg-slate-900 flex items-center justify-center p-4 transition-colors">
        <div className="w-full max-w-sm mx-auto">
          <div className="text-center mb-8">
            <div className="w-20 h-20 bg-gradient-to-br from-orange-400 to-orange-600 rounded-3xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-orange-300/40">
              <Candy className="w-10 h-10 text-white" strokeWidth={2} />
            </div>
            <h1 className="text-3xl font-black text-slate-800 dark:text-slate-200 tracking-tight">CandyConnect</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">User Portal</p>
          </div>

          <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-xl shadow-orange-200/30 dark:shadow-slate-900/50 p-6 space-y-5 border border-slate-200/50 dark:border-slate-700/50">
            {loginError && (
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-3 flex items-center gap-2.5">
                <div className="w-2 h-2 bg-red-500 rounded-full flex-shrink-0" />
                <p className="text-red-700 dark:text-red-300 text-sm font-medium">{loginError}</p>
              </div>
            )}
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Username</label>
                <div className="relative">
                  <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400">
                    <User className="w-[18px] h-[18px]" strokeWidth={1.8} />
                  </span>
                  <input
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="Your username"
                    className="w-full pl-11 pr-4 py-3 border border-slate-300 dark:border-slate-600 rounded-xl focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-base transition-colors"
                    disabled={loginLoading}
                    autoComplete="username"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Password</label>
                <div className="relative">
                  <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400">
                    <Lock className="w-[18px] h-[18px]" strokeWidth={1.8} />
                  </span>
                  <input
                    type={showPass ? 'text' : 'password'}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="Your password"
                    className="w-full pl-11 pr-12 py-3 border border-slate-300 dark:border-slate-600 rounded-xl focus:ring-2 focus:ring-orange-500 focus:border-transparent bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-base transition-colors"
                    disabled={loginLoading}
                    autoComplete="current-password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPass(!showPass)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 p-1 transition-colors"
                    tabIndex={-1}
                  >
                    {showPass ? <EyeOff className="w-[18px] h-[18px]" strokeWidth={1.8} /> : <Eye className="w-[18px] h-[18px]" strokeWidth={1.8} />}
                  </button>
                </div>
              </div>
              <button
                type="submit"
                disabled={loginLoading}
                className={`w-full py-3.5 rounded-xl text-white font-bold text-lg transition-all duration-200 ${loginLoading ? 'bg-orange-400 cursor-not-allowed' : 'bg-orange-500 hover:bg-orange-600 active:scale-[0.98] shadow-lg shadow-orange-300/40'}`}
              >
                {loginLoading ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 className="w-5 h-5 animate-spin" />
                    <span>Signing in...</span>
                  </span>
                ) : 'Login'}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  // ── Loading ───────────────────────────────────────────────────────────────
  if (dataLoading || !account) {
    return (
      <div className="min-h-screen bg-[#FBEFE0] dark:bg-slate-900 flex items-center justify-center">
        <Loader2 className="w-10 h-10 text-orange-500 animate-spin" />
      </div>
    );
  }

  // ── Portal Dashboard ──────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#FBEFE0] dark:bg-slate-900 transition-colors">
      {/* Top bar */}
      <header className="sticky top-0 z-30 bg-[#FBEFE0]/90 dark:bg-slate-900/90 backdrop-blur border-b border-slate-200/50 dark:border-slate-700/50 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-orange-400 to-orange-600 rounded-lg flex items-center justify-center shadow-sm">
            <Candy className="w-5 h-5 text-white" strokeWidth={2} />
          </div>
          <div>
            <p className="font-bold text-slate-800 dark:text-slate-200 leading-none">CandyConnect</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">User Portal</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setDark(!dark)}
            className="p-2 rounded-lg text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-white dark:hover:bg-slate-800 transition-colors"
            title="Toggle theme"
          >
            {dark ? '☀️' : '🌙'}
          </button>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-4 py-6 space-y-5">
        {/* Account info card */}
        <div className="bg-white dark:bg-slate-800 rounded-2xl p-5 shadow-sm border border-slate-200 dark:border-slate-700 space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900/30 rounded-xl flex items-center justify-center">
                <User className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="font-bold text-slate-800 dark:text-slate-100 text-lg">{account.username}</p>
                {account.comment && <p className="text-xs text-slate-500 dark:text-slate-400">{account.comment}</p>}
              </div>
            </div>
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold ${account.enabled ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400' : 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400'}`}>
              {account.enabled ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
              {account.enabled ? 'Active' : 'Disabled'}
            </div>
          </div>

          {/* Traffic */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <p className="text-sm font-semibold text-slate-600 dark:text-slate-400 flex items-center gap-1.5">
                <Wifi className="w-3.5 h-3.5" /> Traffic Usage
              </p>
              <p className="text-sm font-bold text-slate-800 dark:text-slate-200">
                {fmtTrafficLimit(account.traffic_used, account.traffic_limit)}
              </p>
            </div>
            <div className="w-full h-2.5 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-orange-500' : 'bg-green-500'}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">{pct}% used</p>
          </div>

          {/* Time / Expiry */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-slate-50 dark:bg-slate-700/50 rounded-xl p-3">
              <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1 mb-1">
                <Clock className="w-3 h-3" /> Created
              </p>
              <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">{account.created_at.split(' ')[0]}</p>
            </div>
            <div className="bg-slate-50 dark:bg-slate-700/50 rounded-xl p-3">
              <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1 mb-1">
                <Clock className="w-3 h-3" /> Expires
              </p>
              <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">{account.expires_at.split(' ')[0]}</p>
            </div>
          </div>

          {/* Last connection */}
          {account.last_connected_ip && (
            <div className="bg-slate-50 dark:bg-slate-700/50 rounded-xl p-3">
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Last Connection</p>
              <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">
                {account.last_connected_ip} · {account.last_connected_time}
              </p>
            </div>
          )}
        </div>

        {/* Configs section */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-orange-500" />
            <h2 className="text-lg font-bold text-slate-800 dark:text-slate-100">
              VPN Configurations
            </h2>
            <span className="px-2 py-0.5 bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400 text-xs font-bold rounded-full">
              {configs.length}
            </span>
          </div>

          {configs.length === 0 ? (
            <div className="text-center py-12 bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700">
              <p className="text-4xl mb-3">📭</p>
              <p className="text-slate-500 dark:text-slate-400 font-medium">No configurations available</p>
              <p className="text-slate-400 dark:text-slate-500 text-sm mt-1">Contact your administrator to enable protocols for your account.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {configs.map(cfg => (
                <ConfigCard key={cfg.id} cfg={cfg} />
              ))}
            </div>
          )}
        </div>

        <p className="text-center text-xs text-slate-400 dark:text-slate-500 pb-4">
          🍬 CandyConnect User Portal
        </p>
      </main>
    </div>
  );
};

export default UserPortalPage;
