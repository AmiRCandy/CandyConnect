import React, { useState, useEffect } from 'react';
import { getDashboard, type DashboardData } from '../services/api';
import { formatUptime, formatTraffic } from '../utils/format';
import ProgressBar from '../components/ProgressBar';
import { Users, Link2, Cpu, Clock, Monitor, Zap, Shield, Lock, KeyRound, Radio, Globe, Wind, Castle, ArrowDownCircle, ArrowUpCircle, Activity, Server, Loader2, ExternalLink, ArrowDownUp } from 'lucide-react';

const coreIcons: Record<string, React.ReactNode> = {
  v2ray: <Zap className="w-4.5 h-4.5 text-yellow-500" strokeWidth={2} />,
  wireguard: <Shield className="w-4.5 h-4.5 text-blue-500" strokeWidth={2} />,
  openvpn: <Lock className="w-4.5 h-4.5 text-green-500" strokeWidth={2} />,
  ikev2: <KeyRound className="w-4.5 h-4.5 text-purple-500" strokeWidth={2} />,
  l2tp: <Radio className="w-4.5 h-4.5 text-slate-400" strokeWidth={2} />,
  amnezia: <Globe className="w-4.5 h-4.5 text-cyan-500" strokeWidth={2} />,
  slipstream: <Wind className="w-4.5 h-4.5 text-teal-500" strokeWidth={2} />,
  trusttunnel: <Castle className="w-4.5 h-4.5 text-indigo-500" strokeWidth={2} />,
};

const logLevelIcon = (level: string) => {
  if (level === 'ERROR') return <div className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0 mt-1.5" />;
  if (level === 'WARN') return <div className="w-2 h-2 rounded-full bg-amber-500 flex-shrink-0 mt-1.5" />;
  return <div className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0 mt-1.5" />;
};

const logLevelColor = (level: string) => {
  if (level === 'ERROR') return 'text-red-500';
  if (level === 'WARN') return 'text-amber-500';
  return 'text-green-600 dark:text-green-400';
};

const DashboardPage: React.FC = () => {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [logLimit, setLogLimit] = useState(10);

  const fetchData = async () => {
    try {
      const d = await getDashboard(logLimit);
      setData(d);
      setError('');
    } catch (e: any) {
      setError(e.message || 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [logLimit]);

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>;
  if (error || !data) return <div className="text-center py-20 text-red-500 font-medium">{error || 'Failed to load'}</div>;

  const s = data.server;
  const cpuPct = s.cpu.usage;
  const ramPct = parseFloat(((s.ram.used / s.ram.total) * 100).toFixed(1));
  const diskPct = parseFloat(((s.disk.used / s.disk.total) * 100).toFixed(1));
  const totalClients = data.stats.total_clients;
  const totalConnections = data.stats.active_connections;
  const runningCores = data.stats.running_cores;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 flex items-center gap-2.5">
            <LayoutDashboardIcon />
            Dashboard
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 flex items-center gap-1.5">
            <Server className="w-3 h-3" strokeWidth={2} />
            {s.hostname} &middot; {s.domain || s.ip}
            {s.domain && s.ip && <span className="opacity-60 ml-1">({s.ip})</span>}
          </p>
        </div>
        <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
          {s.os}
        </span>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { icon: <Users className="w-5 h-5" strokeWidth={1.8} />, value: `${data.stats.online_clients}/${data.stats.total_clients}`, label: 'Clients Online', color: 'text-blue-500', bg: 'bg-blue-50 dark:bg-blue-900/20' },
          { icon: <ArrowDownUp className="w-5 h-5" strokeWidth={1.8} />, value: formatTraffic(data.stats.total_traffic), label: 'Traffic Used', color: 'text-cyan-500', bg: 'bg-cyan-50 dark:bg-cyan-900/20' },
          { icon: <Link2 className="w-5 h-5" strokeWidth={1.8} />, value: totalConnections, label: 'Active Connections', color: 'text-green-500', bg: 'bg-green-50 dark:bg-green-900/20' },
          { icon: <Cpu className="w-5 h-5" strokeWidth={1.8} />, value: `${runningCores}/${data.stats.total_cores}`, label: 'Cores Online', color: 'text-orange-500', bg: 'bg-orange-50 dark:bg-orange-900/20' },
        ].map((st, i) => (
          <div key={i} className="bg-white dark:bg-slate-800 rounded-xl p-4 shadow-sm border border-slate-200/50 dark:border-slate-700/50">
            <div className={`w-9 h-9 rounded-lg ${st.bg} flex items-center justify-center mb-3`}>
              <span className={st.color}>{st.icon}</span>
            </div>
            <div className="text-xl font-black text-slate-800 dark:text-slate-200">{st.value}</div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold mt-0.5">{st.label}</div>
          </div>
        ))}
      </div>

      {/* Server Resources */}
      <div className="bg-white dark:bg-slate-800 rounded-xl p-5 shadow-sm border border-slate-200/50 dark:border-slate-700/50 space-y-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Monitor className="w-4 h-4 text-slate-500" strokeWidth={2} />
            Server Resources
          </h2>
          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">{s.kernel}</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
          {[
            { label: 'CPU', sub: `${s.cpu.model.split(' ').slice(0, 3).join(' ')} · ${s.cpu.cores} Cores`, pct: cpuPct, icon: <Cpu className="w-4 h-4" strokeWidth={2} /> },
            { label: 'Memory', sub: `${(s.ram.used / 1024).toFixed(1)} / ${(s.ram.total / 1024).toFixed(1)} GB`, pct: ramPct, icon: <Activity className="w-4 h-4" strokeWidth={2} /> },
            { label: 'Disk', sub: `${s.disk.used} / ${s.disk.total} GB`, pct: diskPct, icon: <Server className="w-4 h-4" strokeWidth={2} /> },
          ].map((r, i) => (
            <div key={i} className="bg-slate-50 dark:bg-slate-700/30 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                  <span className="text-slate-400 dark:text-slate-500">{r.icon}</span>
                  {r.label}
                </span>
                <span className={`text-xs font-bold ${r.pct > 80 ? 'text-red-500' : r.pct > 60 ? 'text-amber-500' : 'text-green-500'}`}>{r.pct}%</span>
              </div>
              <ProgressBar percent={r.pct} showLabel={false} />
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1.5">{r.sub}</p>
            </div>
          ))}
        </div>
        <div className="border-t border-slate-200 dark:border-slate-700 pt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-green-50 dark:bg-green-900/20 flex items-center justify-center flex-shrink-0">
              <ArrowDownCircle className="w-4 h-4 text-green-500" strokeWidth={2} />
            </div>
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase">Network Transfer</p>
              <p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">
                In: <span className="text-green-600 dark:text-green-400 font-bold">{formatTraffic(s.network.total_in)}</span>
                <span className="text-slate-300 dark:text-slate-600 mx-1.5">|</span>
                Out: <span className="text-orange-500 font-bold">{formatTraffic(s.network.total_out)}</span>
              </p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center flex-shrink-0">
              <Activity className="w-4 h-4 text-blue-500" strokeWidth={2} />
            </div>
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase">Current Speed</p>
              <p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">
                <span className="text-green-600 dark:text-green-400 font-bold">{s.network.speed_in} Mbps</span>
                <span className="text-slate-300 dark:text-slate-600 mx-1.5">|</span>
                <span className="text-orange-500 font-bold">{s.network.speed_out} Mbps</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* VPN Cores */}
      <div className="bg-white dark:bg-slate-800 rounded-xl p-5 shadow-sm border border-slate-200/50 dark:border-slate-700/50 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Zap className="w-4 h-4 text-orange-500" strokeWidth={2} />
            VPN Cores
          </h2>
          <span className="px-2.5 py-1 rounded-full text-[10px] font-bold bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 flex items-center gap-1">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500" />
            {runningCores} Running
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {data.vpn_cores.map(core => (
            <div key={core.id} className={`rounded-xl p-4 border transition-colors ${core.status === 'running' ? 'border-slate-200/80 dark:border-slate-700/50 bg-slate-50/80 dark:bg-slate-700/30' : 'border-slate-200/40 dark:border-slate-700/30 bg-slate-100/50 dark:bg-slate-800/50 opacity-50'}`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${core.status === 'running' ? 'bg-white dark:bg-slate-600' : 'bg-slate-200 dark:bg-slate-700'}`}>
                    {coreIcons[core.id]}
                  </div>
                  <span className="font-bold text-sm text-slate-800 dark:text-slate-200">{core.name.split(' ')[0]}</span>
                </div>
                <div className={`w-2.5 h-2.5 rounded-full ${core.status === 'running' ? 'bg-green-500 shadow-sm shadow-green-500/50' : 'bg-red-400'}`} />
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="bg-white dark:bg-slate-600/30 rounded-lg px-2.5 py-1.5">
                  <span className="text-slate-400 dark:text-slate-500 block text-[10px]">Uptime</span>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">{formatUptime(core.uptime)}</span>
                </div>
                <div className="bg-white dark:bg-slate-600/30 rounded-lg px-2.5 py-1.5">
                  <span className="text-slate-400 dark:text-slate-500 block text-[10px]">Port</span>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">{core.port}</span>
                </div>
                <div className="bg-white dark:bg-slate-600/30 rounded-lg px-2.5 py-1.5">
                  <span className="text-slate-400 dark:text-slate-500 block text-[10px]">Connections</span>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">{core.active_connections}</span>
                </div>
                <div className="bg-white dark:bg-slate-600/30 rounded-lg px-2.5 py-1.5">
                  <span className="text-slate-400 dark:text-slate-500 block text-[10px]">Traffic Out</span>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">{formatTraffic(core.total_traffic?.out || 0)}</span>
                </div>
              </div>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-2 font-mono">v{core.version}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Logs */}
      <div className="bg-white dark:bg-slate-800 rounded-xl p-5 shadow-sm border border-slate-200/50 dark:border-slate-700/50 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-500" strokeWidth={2} />
            Recent Logs
            <button
              onClick={() => (window as any).ccNavigate('logs')}
              className="ml-2 p-1 text-[10px] text-orange-500 hover:text-orange-600 dark:hover:text-orange-400 flex items-center gap-0.5 border border-orange-200 dark:border-orange-800/50 rounded-md transition-colors"
            >
              <ExternalLink className="w-2.5 h-2.5" />
              View All
            </button>
          </h2>
          <div className="flex items-center gap-3">
            <select
              value={logLimit}
              onChange={(e) => setLogLimit(Number(e.target.value))}
              className="text-[10px] font-bold bg-slate-50 dark:bg-slate-700 border-none rounded-lg px-2 py-1 text-slate-500 dark:text-slate-400 focus:ring-1 focus:ring-orange-500 outline-none cursor-pointer"
            >
              <option value={10}>10 Entries</option>
              <option value={50}>50 Entries</option>
              <option value={100}>100 Entries</option>
            </select>
            <span className="text-[10px] text-slate-400 font-medium">{data.logs.length} entries</span>
          </div>
        </div>
        <div className="max-h-80 overflow-y-auto space-y-0.5 custom-scrollbar">
          {data.logs.map((log, i) => (
            <div key={i} className="flex items-start gap-3 py-2 border-b border-slate-100 dark:border-slate-700/50 last:border-b-0 text-xs hover:bg-slate-50 dark:hover:bg-slate-700/20 rounded px-1 transition-colors">
              {logLevelIcon(log.level)}
              <span className="text-slate-400 dark:text-slate-500 whitespace-nowrap font-mono w-16 flex-shrink-0">{log.time.split(' ')[1]}</span>
              <span className={`font-bold uppercase w-11 flex-shrink-0 ${logLevelColor(log.level)}`}>{log.level}</span>
              <span className="text-orange-500 dark:text-orange-400 font-semibold flex-shrink-0">{log.source}</span>
              <span className="text-slate-600 dark:text-slate-400 flex-1 min-w-0">{log.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const LayoutDashboardIcon = () => (
  <div className="w-8 h-8 rounded-lg bg-orange-50 dark:bg-orange-900/20 flex items-center justify-center">
    <svg className="w-4.5 h-4.5 text-orange-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <rect width="7" height="9" x="3" y="3" rx="1" /><rect width="7" height="5" x="14" y="3" rx="1" /><rect width="7" height="9" x="14" y="12" rx="1" /><rect width="7" height="5" x="3" y="16" rx="1" />
    </svg>
  </div>
);

export default DashboardPage;
