import React, { useState, useEffect } from 'react';
import { getClients, createClient, updateClient, deleteClient as apiDeleteClient, downloadOpenVpnConfig, generateWireGuardQr, type Client, type ClientProtocols } from '../services/api';
import { formatClientTraffic, getTrafficPercent, protocolName, protocolIcon } from '../utils/format';
import ProgressBar from '../components/ProgressBar';
import Modal from '../components/Modal';
import { useNotify } from '../components/Notification';
import { Users, Search, ClipboardList, Pencil, Trash2, CheckCircle2, XCircle, Plus, AlertTriangle, PauseCircle, Clock, ArrowDownUp, Loader2, Activity } from 'lucide-react';

const ALL_PROTOCOLS = ['v2ray', 'wireguard', 'openvpn', 'ikev2', 'l2tp', 'amnezia', 'slipstream', 'trusttunnel'] as const;

// Helper to adapt snake_case API client to display
const fmtTimeLimit = (c: Client) => {
  const r = c.time_limit.value - c.time_used;
  if (c.time_limit.on_hold) return `On Hold (${c.time_limit.value} ${c.time_limit.mode})`;
  return `${r} ${c.time_limit.mode} left`;
};

const fmtTraffic = (c: Client) => formatClientTraffic(c.traffic_used, { value: c.traffic_limit.value, unit: c.traffic_limit.unit });
const trafficPct = (c: Client) => getTrafficPercent(c.traffic_used, { value: c.traffic_limit.value, unit: c.traffic_limit.unit });

const genPassword = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
  return Array.from({ length: 12 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
};

const ClientsPage: React.FC = () => {
  const { notify } = useNotify();
  const [search, setSearch] = useState('');
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailClient, setDetailClient] = useState<Client | null>(null);
  const [editClient, setEditClient] = useState<Client | null>(null);
  const [isAddMode, setIsAddMode] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<Client | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<string>('All');
  const [saving, setSaving] = useState(false);
  const [wgQrData, setWgQrData] = useState<{ qr_data_url: string; wg_config: string } | null>(null);
  const [wgQrLoading, setWgQrLoading] = useState(false);

  // Form state
  const [fUsername, setFUsername] = useState('');
  const [fPassword, setFPassword] = useState('');
  const [fComment, setFComment] = useState('');
  const [fTrafficVal, setFTrafficVal] = useState(50);
  const [fTrafficUnit, setFTrafficUnit] = useState<'GB' | 'MB'>('GB');
  const [fTimeVal, setFTimeVal] = useState(30);
  const [fTimeMode, setFTimeMode] = useState<'days' | 'months'>('days');
  const [fOnHold, setFOnHold] = useState(false);
  const [fEnabled, setFEnabled] = useState(true);
  const [fGroup, setFGroup] = useState('');
  const [fProtocols, setFProtocols] = useState<Record<string, boolean>>({});

  const fetchClients = async () => {
    try {
      const data = await getClients();
      setClients(data);
    } catch (e: any) {
      notify(e.message || 'Failed to load clients', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchClients(); }, []);

  const groups = ['All', ...Array.from(new Set(clients.map(c => c.group).filter(Boolean) as string[]))];

  const filtered = clients.filter(c => {
    const matchesGroup = selectedGroup === 'All' || c.group === selectedGroup;
    if (!search && matchesGroup) return true;
    const q = search.toLowerCase();
    return matchesGroup && (c.username.toLowerCase().includes(q) || c.comment.toLowerCase().includes(q) || c.last_connected_ip?.includes(q));
  });

  const openAddModal = () => {
    setIsAddMode(true); setEditClient(null);
    setFUsername(''); setFPassword(''); setFComment('');
    setFTrafficVal(50); setFTrafficUnit('GB'); setFTimeVal(30); setFTimeMode('days');
    setFOnHold(false); setFEnabled(true); setFGroup('');
    const p: Record<string, boolean> = {};
    ALL_PROTOCOLS.forEach(k => p[k] = true);
    setFProtocols(p);
  };

  const openEditModal = (client: Client) => {
    setIsAddMode(false); setEditClient(client);
    setFUsername(client.username); setFPassword(client.password); setFComment(client.comment);
    setFTrafficVal(client.traffic_limit.value); setFTrafficUnit(client.traffic_limit.unit as any);
    setFTimeVal(client.time_limit.value); setFTimeMode(client.time_limit.mode as any);
    setFOnHold(client.time_limit.on_hold); setFEnabled(client.enabled); setFGroup(client.group || '');
    setFProtocols({ ...client.protocols });
  };

  const handleSave = async () => {
    if (!fUsername.trim() || !fPassword.trim()) { notify('Username and password required', 'error'); return; }
    if (fTrafficVal <= 0 || fTimeVal <= 0) { notify('Traffic and time must be positive', 'error'); return; }
    setSaving(true);
    try {
      if (isAddMode) {
        await createClient({
          username: fUsername.trim(), password: fPassword.trim(), comment: fComment.trim(),
          enabled: fEnabled, group: fGroup.trim() || undefined,
          traffic_limit: { value: fTrafficVal, unit: fTrafficUnit },
          time_limit: { mode: fTimeMode, value: fTimeVal, on_hold: fOnHold },
          protocols: fProtocols as unknown as ClientProtocols,
        });
        notify(`Client "${fUsername}" created`, 'success');
      } else if (editClient) {
        await updateClient(editClient.id, {
          password: fPassword.trim(), comment: fComment.trim(), enabled: fEnabled,
          group: fGroup.trim() || undefined,
          traffic_limit: { value: fTrafficVal, unit: fTrafficUnit },
          time_limit: { mode: fTimeMode, value: fTimeVal, on_hold: fOnHold },
          protocols: fProtocols as unknown as ClientProtocols,
        });
        notify(`Client "${fUsername}" updated`, 'success');
      }
      await fetchClients();
      setEditClient(null); setIsAddMode(false);
    } catch (e: any) {
      notify(e.message || 'Failed to save', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) return;
    setSaving(true);
    try {
      await apiDeleteClient(confirmDelete.id);
      notify(`Client "${confirmDelete.username}" deleted`, 'success');
      await fetchClients();
    } catch (e: any) {
      notify(e.message || 'Failed to delete', 'error');
    } finally {
      setSaving(false); setConfirmDelete(null);
    }
  };



  const handleDownloadOpenVpn = async (client: Client) => {
    try {
      const content = await downloadOpenVpnConfig(client.id);
      const blob = new Blob([content], { type: 'application/x-openvpn-profile' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${client.username}.ovpn`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      notify('OpenVPN config downloaded', 'success');
    } catch (e: any) {
      notify(e.message || 'Failed to download OpenVPN config', 'error');
    }
  };

  const handleGenerateWireGuardQr = async (client: Client) => {
    try {
      setWgQrLoading(true);
      const data = await generateWireGuardQr(client.id);
      setWgQrData({ qr_data_url: data.qr_data_url, wg_config: data.wg_config });
      await fetchClients();
      const fresh = await getClients();
      const updated = fresh.find(c => c.id === client.id);
      if (updated) setDetailClient(updated);
    } catch (e: any) {
      notify(e.message || 'Failed to generate WireGuard QR', 'error');
    } finally {
      setWgQrLoading(false);
    }
  };

  const showForm = isAddMode || !!editClient;

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 flex items-center gap-2"><Users className="w-8 h-8 text-blue-500" /> Clients</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">{filtered.length} client(s)</p>
        </div>
        <button onClick={openAddModal} className="px-4 py-2.5 bg-orange-500 hover:bg-orange-600 text-white font-bold rounded-xl text-sm transition-colors active:scale-[0.98] shadow-md shadow-orange-300/30 flex items-center gap-2">
          <Plus className="w-4 h-4" strokeWidth={3} /> Add Client
        </button>
      </div>

      {/* Controls */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1 sm:max-w-xs">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search clients..." className="w-full pl-10 pr-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors" />
        </div>
        <select value={selectedGroup} onChange={e => setSelectedGroup(e.target.value)} className="px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors sm:w-40">
          {groups.map(g => <option key={g} value={g}>{g}</option>)}
        </select>
      </div>

      {/* Client Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-6 xl:grid-cols-8 gap-3">
        {filtered.map(client => {
          const tPct = trafficPct(client);
          return (
            <div key={client.id} className={`bg-white dark:bg-slate-800 rounded-xl p-3 shadow-sm border border-slate-200/50 dark:border-slate-700/50 flex flex-col justify-between aspect-square group relative ${!client.enabled ? 'opacity-60 grayscale' : ''}`}>
              <div>
                <div className="flex justify-between items-start mb-2">
                  <div className={`w-2.5 h-2.5 rounded-full ${client.is_online ? 'bg-green-500 shadow-sm shadow-green-500/50 animate-pulse' : !client.enabled ? 'bg-red-500' : 'bg-slate-300 dark:bg-slate-600'}`} title={client.is_online ? 'Online' : !client.enabled ? 'Disabled' : 'Offline'} />
                  {client.time_limit.on_hold && <PauseCircle className="w-3 h-3 text-amber-500" />}
                </div>
                <h3 className="font-bold text-slate-800 dark:text-slate-200 text-sm truncate" title={client.username}>{client.username}</h3>
                {client.group && <span className="text-[10px] px-1.5 py-0.5 bg-slate-100 dark:bg-slate-700 rounded text-slate-500 dark:text-slate-400 inline-block mt-1 truncate max-w-full">{client.group}</span>}
              </div>
              <div className="space-y-1.5 pt-2">
                <div>
                  <div className="flex justify-between items-end text-[9px] text-slate-500 dark:text-slate-400 mb-0.5">
                    <span className="flex items-center gap-1"><Clock className="w-2.5 h-2.5" /> {fmtTimeLimit(client)}</span>
                    <span>{Math.round((client.time_used / client.time_limit.value) * 100)}%</span>
                  </div>
                  <ProgressBar percent={(client.time_used / client.time_limit.value) * 100} height="h-1" showLabel={false} />
                </div>
                <div>
                  <div className="flex justify-between items-end text-[9px] text-slate-500 dark:text-slate-400 mb-0.5">
                    <span className="flex items-center gap-1"><ArrowDownUp className="w-2.5 h-2.5" /> {fmtTraffic(client)}</span>
                    <span>{Math.round(tPct)}%</span>
                  </div>
                  <ProgressBar percent={tPct} height="h-1" showLabel={false} />
                </div>
              </div>
              <div className="absolute inset-0 bg-black/60 backdrop-blur-[1px] rounded-xl opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center gap-2">
                <button onClick={() => setDetailClient(client)} className="p-2 rounded-full bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 shadow-lg hover:scale-110 transition-transform"><ClipboardList className="w-4 h-4" /></button>
                <button onClick={() => openEditModal(client)} className="p-2 rounded-full bg-orange-500 text-white shadow-lg hover:scale-110 transition-transform"><Pencil className="w-4 h-4" /></button>
                <button onClick={() => setConfirmDelete(client)} className="p-2 rounded-full bg-red-500 text-white shadow-lg hover:scale-110 transition-transform"><Trash2 className="w-4 h-4" /></button>
              </div>
            </div>
          );
        })}
        {filtered.length === 0 && <div className="col-span-full py-10 text-center text-slate-400 text-sm">No clients found</div>}
      </div>

      {/* Detail Modal */}
      <Modal open={!!detailClient} title={<span className="flex items-center gap-2"><ClipboardList className="w-5 h-5 text-slate-500" /> {detailClient?.username || ''}</span>} onClose={() => { setDetailClient(null); setWgQrData(null); }} wide>
        {detailClient && (
          <div className="space-y-4 text-sm">
            {[
              ['Username', detailClient.username], ['Password', detailClient.password],
              ['Status', detailClient.is_online ? <span className="flex items-center gap-1.5 align-middle text-green-600 dark:text-green-400 font-bold"><Activity className="w-3.5 h-3.5" /> Online</span> : !detailClient.enabled ? <span className="flex items-center gap-1.5 align-middle text-red-500 font-bold"><XCircle className="w-3.5 h-3.5" /> Disabled</span> : <span className="flex items-center gap-1.5 align-middle text-slate-500 font-bold"><PauseCircle className="w-3.5 h-3.5" /> Offline</span>],
              ['Group', detailClient.group || 'None'],
              ['Comment', detailClient.comment || '-'],
              ['Traffic', fmtTraffic(detailClient)],
              ['Time', fmtTimeLimit(detailClient)],
              ['Created', detailClient.created_at], ['Expires', detailClient.expires_at],
              ['Last IP', detailClient.last_connected_ip || 'Never'], ['Last Connected', detailClient.last_connected_time || 'Never'],
            ].map(([k, v], i) => (
              <div key={i} className="flex justify-between py-1.5 border-b border-slate-100 dark:border-slate-700/50">
                <span className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wide">{k}</span>
                <span className="text-slate-800 dark:text-slate-200 font-medium text-right max-w-[60%] break-all">{v}</span>
              </div>
            ))}
            <h4 className="text-xs font-bold text-orange-500 uppercase tracking-wider pt-2">Protocols</h4>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(detailClient.protocols).map(([k, v]) => (
                <span key={k} className={`text-xs px-2 py-1 rounded-full border font-medium ${v ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800' : 'bg-slate-100 dark:bg-slate-700 text-slate-400 dark:text-slate-500 border-slate-200 dark:border-slate-600'}`}>{protocolIcon(k)} {protocolName(k)}</span>
              ))}
            </div>
            <h4 className="text-xs font-bold text-orange-500 uppercase tracking-wider pt-2">Connection History</h4>
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {detailClient.connection_history.map((h, i) => (
                <div key={i} className="flex items-center justify-between bg-slate-50 dark:bg-slate-700/50 rounded-lg p-2 text-xs">
                  <div><p className="font-medium text-slate-700 dark:text-slate-300">{h.protocol}</p><p className="text-slate-400">{h.time}</p></div>
                  <div className="text-right"><p className="text-slate-400">{h.ip}</p><p className={h.duration === 'Active' ? 'text-green-600 dark:text-green-400 font-bold' : 'text-slate-500'}>{h.duration}</p></div>
                </div>
              ))}
            </div>
            {/* Per-Protocol Traffic */}
            {detailClient.protocol_traffic && Object.keys(detailClient.protocol_traffic).length > 0 && (
              <>
                <h4 className="text-xs font-bold text-orange-500 uppercase tracking-wider pt-2">Protocol Traffic</h4>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(detailClient.protocol_traffic).map(([proto, bytes]: [string, any]) => {
                    const gb = Number(bytes) / (1024 ** 3);
                    const mb = Number(bytes) / (1024 ** 2);
                    const display = gb >= 1 ? `${gb.toFixed(2)} GB` : mb >= 1 ? `${mb.toFixed(1)} MB` : `${(Number(bytes) / 1024).toFixed(1)} KB`;
                    return (
                      <div key={proto} className="flex items-center justify-between bg-slate-50 dark:bg-slate-700/50 rounded-lg px-2.5 py-1.5 text-xs">
                        <span className="text-slate-500 dark:text-slate-400 font-medium flex items-center gap-1">{protocolIcon(proto)} {protocolName(proto)}</span>
                        <span className="text-orange-500 font-bold font-mono">{display}</span>
                      </div>
                    );
                  })}
                </div>
              </>
            )}

            <h4 className="text-xs font-bold text-orange-500 uppercase tracking-wider pt-2">Protocol Details</h4>
            <div className="bg-slate-50 dark:bg-slate-700/30 rounded-lg p-3 text-xs space-y-2 break-all">
              {Object.entries(detailClient.protocol_data).map(([pid, data]: [string, any]) => (
                <div key={pid} className="space-y-1">
                  <p className="font-bold text-slate-400 border-b border-slate-200 dark:border-slate-700/50 pb-0.5 mb-1 flex items-center gap-1.5">
                    {protocolIcon(pid)} {protocolName(pid)}
                  </p>
                  {pid === 'v2ray' && <p><span className="text-slate-400">UUID:</span> <span className="text-orange-500 font-mono">{data.uuid}</span></p>}
                  {pid === 'wireguard' && (<>
                    <p><span className="text-slate-400">Public Key:</span> <span className="text-orange-500 font-mono">{data.public_key || 'Not generated yet'}</span></p>
                    <button onClick={() => handleGenerateWireGuardQr(detailClient)} disabled={wgQrLoading} className="mt-1 px-2 py-1 rounded-lg text-[11px] font-bold bg-orange-500 text-white hover:bg-orange-600 disabled:opacity-60">{wgQrLoading ? 'Generating...' : 'QR Code'}</button>
                  </>)}
                  {pid === 'amnezia' && (
                    <>
                      <p><span className="text-slate-400">Domain:</span> <span className="text-orange-500 font-mono">{data.domain || '-'}</span></p>
                      <p><span className="text-slate-400">Obfuscation:</span> <span className="text-orange-500 font-mono">{data.obfuscation || 'on'}</span></p>
                    </>
                  )}
                  {pid === 'openvpn' && <p><span className="text-slate-400">Config:</span> <button onClick={() => handleDownloadOpenVpn(detailClient)} className="text-orange-500 font-mono underline">{detailClient.username}.ovpn</button></p>}
                  {pid === 'ikev2' && <p><span className="text-slate-400">Auth:</span> <span className="text-green-500 font-bold">EAP-MSCHAPv2 Active</span></p>}
                  {pid === 'l2tp' && data.psk && <p><span className="text-slate-400">IPSec PSK:</span> <span className="text-orange-500 font-mono">{data.psk}</span></p>}
                  {['slipstream', 'trusttunnel'].includes(pid) && <p className="text-slate-400 italic">Experimental protocol</p>}
                </div>
              ))}
              {Object.keys(detailClient.protocol_data).length === 0 && <p className="text-slate-400 italic">No protocol data generated yet.</p>}
            </div>
          </div>
        )}
      </Modal>

      <Modal open={!!wgQrData} title={<span className="flex items-center gap-2">WireGuard QR</span>} onClose={() => setWgQrData(null)}>
        {wgQrData && (
          <div className="space-y-3">
            {wgQrData.qr_data_url ? <img src={wgQrData.qr_data_url} alt="WireGuard QR" className="mx-auto w-56 h-56" /> : <p className="text-xs text-slate-400">QR image unavailable. Use config text below.</p>}
            <textarea readOnly value={wgQrData.wg_config} className="w-full h-40 p-2 text-xs rounded-lg border border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-800" />
          </div>
        )}
      </Modal>


      {/* Add/Edit Modal */}
      <Modal open={showForm} title={isAddMode ? <span className="flex items-center gap-2"><Plus className="w-5 h-5" /> New Client</span> : <span className="flex items-center gap-2"><Pencil className="w-4 h-4 text-orange-500" /> Edit: {editClient?.username || ''}</span>} onClose={() => { setEditClient(null); setIsAddMode(false); }} wide
        footer={<>
          <button onClick={() => { setEditClient(null); setIsAddMode(false); }} className="px-4 py-2 rounded-xl text-sm font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors">Cancel</button>
          <button onClick={handleSave} disabled={saving} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-orange-500 hover:bg-orange-600 transition-colors disabled:opacity-50">{saving ? 'Saving...' : isAddMode ? 'Create' : 'Save'}</button>
        </>}
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Username</label>
              <input type="text" value={fUsername} onChange={e => setFUsername(e.target.value)} readOnly={!isAddMode} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Password</label>
              <div className="flex gap-2">
                <input type="text" value={fPassword} onChange={e => setFPassword(e.target.value)} className="flex-1 px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
                <button onClick={() => setFPassword(genPassword())} className="px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-600 text-xs font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-500 transition-colors whitespace-nowrap">Random</button>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Group</label>
              <input type="text" value={fGroup} onChange={e => setFGroup(e.target.value)} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" list="group-list" placeholder="Select or type..." />
              <datalist id="group-list">{groups.filter(g => g !== 'All').map(g => <option key={g} value={g} />)}</datalist>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Comment</label>
              <input type="text" value={fComment} onChange={e => setFComment(e.target.value)} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" placeholder="Optional description" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Traffic Limit</label>
              <div className="flex gap-2">
                <input type="number" value={fTrafficVal} onChange={e => setFTrafficVal(+e.target.value)} min={1} className="flex-1 px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
                <select value={fTrafficUnit} onChange={e => setFTrafficUnit(e.target.value as any)} className="px-2 py-2 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm">
                  <option value="GB">GB</option><option value="MB">MB</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Time Limit</label>
              <div className="flex gap-2">
                <input type="number" value={fTimeVal} onChange={e => setFTimeVal(+e.target.value)} min={1} className="flex-1 px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm" />
                <select value={fTimeMode} onChange={e => setFTimeMode(e.target.value as any)} className="px-2 py-2 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm">
                  <option value="days">Days</option><option value="months">Months</option>
                </select>
              </div>
            </div>
          </div>
          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <button type="button" onClick={() => setFOnHold(!fOnHold)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${fOnHold ? 'bg-amber-500' : 'bg-slate-300 dark:bg-slate-600'}`}><span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${fOnHold ? 'translate-x-4' : 'translate-x-0.5'}`} /></button>
              <span className="text-sm text-slate-600 dark:text-slate-400">On Hold</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <button type="button" onClick={() => setFEnabled(!fEnabled)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${fEnabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'}`}><span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${fEnabled ? 'translate-x-4' : 'translate-x-0.5'}`} /></button>
              <span className="text-sm text-slate-600 dark:text-slate-400">Enabled</span>
            </label>
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold text-slate-600 dark:text-slate-400">VPN Protocols</label>
              <div className="flex gap-2">
                <button onClick={() => { const p: Record<string, boolean> = {}; ALL_PROTOCOLS.forEach(k => p[k] = true); setFProtocols(p); }} className="text-[10px] text-orange-500 font-bold">All</button>
                <button onClick={() => { const p: Record<string, boolean> = {}; ALL_PROTOCOLS.forEach(k => p[k] = false); setFProtocols(p); }} className="text-[10px] text-slate-400 font-bold">None</button>
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {ALL_PROTOCOLS.map(p => (
                <button key={p} type="button" onClick={() => setFProtocols(prev => ({ ...prev, [p]: !prev[p] }))}
                  className={`flex items-center gap-1.5 px-2.5 py-2 rounded-lg border text-xs font-medium transition-colors ${fProtocols[p] ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-300 dark:border-green-700' : 'bg-slate-50 dark:bg-slate-700 text-slate-400 border-slate-200 dark:border-slate-600'}`}>
                  {protocolIcon(p)} {protocolName(p)}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      {/* Delete Confirm */}
      <Modal open={!!confirmDelete} title={<span className="flex items-center gap-2 text-red-500"><AlertTriangle className="w-5 h-5" /> Confirm Delete</span>} onClose={() => setConfirmDelete(null)}
        footer={<>
          <button onClick={() => setConfirmDelete(null)} className="px-4 py-2 rounded-xl text-sm font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors">Cancel</button>
          <button onClick={handleDelete} disabled={saving} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-red-500 hover:bg-red-600 transition-colors disabled:opacity-50">{saving ? 'Deleting...' : 'Delete'}</button>
        </>}>
        <p className="text-sm text-slate-700 dark:text-slate-300">Delete client <strong>"{confirmDelete?.username}"</strong>? This cannot be undone.</p>
      </Modal>
    </div>
  );
};

export default ClientsPage;
