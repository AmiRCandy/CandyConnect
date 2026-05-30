import React, { useState, useEffect } from 'react';
import { getPanel, updatePanel, changePassword as apiChangePassword, restartPanel as apiRestartPanel, type PanelData } from '../services/api';
import { useNotify } from '../components/Notification';
import { Wrench, Globe, AlertTriangle, Key, Lock, Info, Flame, Loader2 } from 'lucide-react';

const Card: React.FC<{ children: React.ReactNode; danger?: boolean }> = ({ children, danger }) => (
  <div className={`bg-white dark:bg-slate-800 rounded-xl p-5 shadow-sm border ${danger ? 'border-red-200 dark:border-red-800/50' : 'border-slate-200/50 dark:border-slate-700/50'}`}>{children}</div>
);

const PanelConfigsPage: React.FC = () => {
  const { notify } = useNotify();
  const [data, setData] = useState<PanelData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [port, setPort] = useState(8443);
  const [path, setPath] = useState('/candyconnect');
  const [curPass, setCurPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [confPass, setConfPass] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const d = await getPanel();
        setData(d);
        setPort(d.config.panel_port);
        setPath(d.config.panel_path);
      } catch (e: any) {
        notify(e.message || 'Failed to load panel config', 'error');
      } finally { setLoading(false); }
    })();
  }, []);

  const strength = (() => {
    if (!newPass) return null;
    let score = 0;
    if (newPass.length >= 8) score++;
    if (newPass.length >= 12) score++;
    if (/[A-Z]/.test(newPass)) score++;
    if (/[0-9]/.test(newPass)) score++;
    if (/[^A-Za-z0-9]/.test(newPass)) score++;
    const levels = [
      { label: 'Very Weak', color: 'bg-red-500', text: 'text-red-600' },
      { label: 'Weak', color: 'bg-red-400', text: 'text-red-500' },
      { label: 'Fair', color: 'bg-amber-500', text: 'text-amber-600' },
      { label: 'Strong', color: 'bg-green-400', text: 'text-green-600' },
      { label: 'Very Strong', color: 'bg-green-500', text: 'text-green-600' },
    ];
    const lv = levels[Math.min(score, 4)];
    return { ...lv, pct: ((score + 1) / 5) * 100 };
  })();

  const savePanelAccess = async () => {
    if (port < 1 || port > 65535) { notify('Port must be 1-65535', 'error'); return; }
    if (!path.startsWith('/')) { notify('Path must start with /', 'error'); return; }
    setSaving(true);
    try {
      const msg = await updatePanel({ panel_port: port, panel_path: path });
      notify(msg, 'success');
    } catch (e: any) {
      notify(e.message || 'Failed to save', 'error');
    } finally { setSaving(false); }
  };

  const resetPassword = async () => {
    if (!curPass || !newPass || !confPass) { notify('All fields required', 'error'); return; }
    if (newPass.length < 8) { notify('Min 8 characters', 'error'); return; }
    if (newPass !== confPass) { notify('Passwords do not match', 'error'); return; }
    setSaving(true);
    try {
      const msg = await apiChangePassword(curPass, newPass, confPass);
      notify(msg, 'success');
      setCurPass(''); setNewPass(''); setConfPass('');
    } catch (e: any) {
      notify(e.message || 'Failed to change password', 'error');
    } finally { setSaving(false); }
  };

  const handleRestart = async () => {
    notify('Restarting panel...', 'warn');
    try {
      await apiRestartPanel();
      notify('Panel restart initiated', 'success');
    } catch (e: any) {
      notify(e.message || 'Failed to restart', 'error');
    }
  };

  if (loading || !data) return <div className="flex items-center justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>;

  const cfg = data.config;
  const s = data.server;

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 flex items-center gap-2"><Wrench className="w-8 h-8 text-orange-500" /> Panel Configs</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">Panel settings & administration</p>
      </div>

      {/* Panel Access */}
      <Card>
        <h3 className="font-bold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2"><Globe className="w-5 h-5 text-blue-500" /> Panel Access Settings</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Panel Port</label>
            <input type="number" value={port} onChange={e => setPort(+e.target.value)} min={1} max={65535} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
            <p className="text-[10px] text-slate-400 mt-1">https://{s.ip}:{port}{path}</p>
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Panel Path</label>
            <input type="text" value={path} onChange={e => setPath(e.target.value)} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
            <p className="text-[10px] text-slate-400 mt-1">Must start with /</p>
          </div>
        </div>
        <div className="flex items-center justify-between mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
          <p className="text-[10px] text-slate-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Changing port/path requires reconnection</p>
          <button onClick={savePanelAccess} disabled={saving} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-orange-500 hover:bg-orange-600 transition-colors disabled:opacity-50">Save</button>
        </div>
      </Card>

      {/* Admin Password */}
      <Card>
        <h3 className="font-bold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2"><Key className="w-5 h-5 text-orange-500" /> Admin Password</h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Current Password</label>
            <input type="password" value={curPass} onChange={e => setCurPass(e.target.value)} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">New Password</label>
            <input type="password" value={newPass} onChange={e => setNewPass(e.target.value)} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Confirm Password</label>
            <input type="password" value={confPass} onChange={e => setConfPass(e.target.value)} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
          </div>
        </div>
        {strength && (
          <div className="flex items-center gap-3 mt-3">
            <div className="flex-1 max-w-[200px] h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
              <div className={`h-full rounded-full transition-all ${strength.color}`} style={{ width: `${strength.pct}%` }} />
            </div>
            <span className={`text-xs font-bold ${strength.text}`}>{strength.label}</span>
          </div>
        )}
        <div className="flex items-center justify-between mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
          <p className="text-[10px] text-slate-400 flex items-center gap-1"><Lock className="w-3 h-3" /> Minimum 8 characters</p>
          <button onClick={resetPassword} disabled={saving} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-orange-500 hover:bg-orange-600 transition-colors disabled:opacity-50">Change Password</button>
        </div>
      </Card>

      {/* Panel Info */}
      <Card>
        <h3 className="font-bold text-slate-800 dark:text-slate-200 mb-4 flex items-center gap-2"><Info className="w-5 h-5 text-blue-500" /> Panel Information</h3>
        <div className="space-y-0">
          {[
            ['Panel Name', 'CandyConnect'],
            ['Version', `v${cfg.version}`],
            ['Build Date', cfg.build_date],
            ['Server IP', s.ip],
            ['Hostname', s.hostname],
            ['OS', s.os],
            ['Kernel', s.kernel],
            ['Admin', data.admin_username],
            ['Protocols', `${data.total_cores}`],
            ['Clients', `${data.total_clients}`],
          ].map(([k, v], i) => (
            <div key={i} className="flex justify-between py-2.5 border-b border-slate-100 dark:border-slate-700/50 last:border-b-0">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wide">{k}</span>
              <span className="text-sm font-medium text-slate-800 dark:text-slate-200">{v}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* Danger Zone */}
      <Card danger>
        <h3 className="font-bold text-red-600 dark:text-red-400 mb-4 flex items-center gap-2"><Flame className="w-5 h-5" /> Danger Zone</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">Restart the entire panel. All active sessions will be terminated.</p>
            <button onClick={handleRestart} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-red-500 hover:bg-red-600 transition-colors">Restart Panel</button>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default PanelConfigsPage;
