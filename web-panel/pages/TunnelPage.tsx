import React, { useState, useEffect } from 'react';
import { getTunnels, addTunnel, deleteTunnel, reinstallTunnel, type Tunnel, type TunnelTransport } from '../services/api';
import { useNotify } from '../components/Notification';
import { Network, Server, Plus, Trash2, Copy, Loader2, RefreshCw, Info, AlertTriangle } from 'lucide-react';
import { BtnSecondary } from '../components/UI';
import Modal from '../components/Modal';

const Card: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
    <div className={`bg-white dark:bg-slate-800 rounded-xl p-5 shadow-sm border border-slate-200/50 dark:border-slate-700/50 ${className}`}>{children}</div>
);
const Label: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1 uppercase tracking-wide">{children}</label>
);
const Input: React.FC<React.InputHTMLAttributes<HTMLInputElement>> = (props) => (
    <input {...props} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors" />
);
const BtnPrimary: React.FC<{ children: React.ReactNode; onClick: () => void; disabled?: boolean }> = ({ children, onClick, disabled }) => (
    <button onClick={onClick} disabled={disabled} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-orange-500 hover:bg-orange-600 active:scale-[0.98] transition-all disabled:opacity-50 flex items-center justify-center">{children}</button>
);

const Select: React.FC<React.SelectHTMLAttributes<HTMLSelectElement>> = (props) => (
    <select {...props} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors" />
);

const TRANSPORTS: { value: TunnelTransport; label: string }[] = [
    { value: 'tcp', label: 'TCP' },
    { value: 'tcpmux', label: 'TCP Mux' },
    { value: 'ws', label: 'WebSocket' },
    { value: 'wsmux', label: 'WebSocket Mux' },
];

const EMPTY_FORM = {
    name: '', ip: '', port: 22, username: 'root', password: '',
    transport: 'tcp' as TunnelTransport, tunnel_port: 3080, ports: '', accept_udp: false,
};

const STATUS_STYLE: Record<string, string> = {
    installed: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
    failed: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
    installing: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400',
    pending: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400',
};

const TunnelPage: React.FC = () => {
    const { notify } = useNotify();
    const [tunnels, setTunnels] = useState<Tunnel[]>([]);
    const [loading, setLoading] = useState(true);
    const [adding, setAdding] = useState(false);
    const [showAddModal, setShowAddModal] = useState(false);
    const [installCmd, setInstallCmd] = useState<string | null>(null);

    const [formData, setFormData] = useState(EMPTY_FORM);
    const [reinstalling, setReinstalling] = useState<string | null>(null);

    useEffect(() => {
        fetchTunnels();
        // SSH installation runs in the background on the server; poll for status changes
        const interval = setInterval(fetchTunnels, 10000);
        return () => clearInterval(interval);
    }, []);

    const fetchTunnels = async () => {
        try {
            const data = await getTunnels();
            setTunnels(data);
        } catch (e: any) {
            notify(e.message, 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleAdd = async () => {
        if (!formData.name.trim() || !formData.ip.trim()) return notify('Server name and IP are required', 'warn');
        if (!formData.port || formData.port < 1 || formData.port > 65535) return notify('SSH port must be 1-65535', 'warn');
        if (!formData.tunnel_port || formData.tunnel_port < 1 || formData.tunnel_port > 65535) return notify('Tunnel port must be 1-65535', 'warn');
        setAdding(true);
        try {
            const res = await addTunnel({
                name: formData.name.trim(),
                ip: formData.ip.trim(),
                port: +formData.port,
                username: formData.username.trim() || 'root',
                password: formData.password || undefined,
                tunnel_type: 'backhaul',
                transport: formData.transport,
                tunnel_port: +formData.tunnel_port,
                ports: formData.ports.trim() || undefined,
                accept_udp: formData.accept_udp,
            });
            notify(res.message || 'Tunnel added', 'success');
            // With a password the server installs the relay over SSH itself;
            // otherwise the admin has to run the script on the relay manually.
            if (!formData.password && res.install_command) setInstallCmd(res.install_command);
            fetchTunnels();
            setShowAddModal(false);
            setFormData(EMPTY_FORM);
        } catch (e: any) {
            notify(e.message, 'error');
        } finally {
            setAdding(false);
        }
    };

    const handleReinstall = async (t: Tunnel) => {
        const what = t.has_password ? 'reinstall Backhaul on the relay over SSH and restart the local client' : 'restart the local Backhaul client (no SSH password is stored, the relay itself is not touched)';
        if (!confirm(`This will ${what}. Continue?`)) return;
        setReinstalling(t.id);
        try {
            notify(await reinstallTunnel(t.id), 'success');
            setTunnels(prev => prev.map(x => x.id === t.id ? { ...x, status: 'installing', error: '' } : x));
            setTimeout(fetchTunnels, 3000);
        } catch (e: any) {
            notify(e.message, 'error');
        } finally {
            setReinstalling(null);
        }
    };

    const handleDelete = async (t: Tunnel) => {
        const id = t.id;
        const extra = t.has_password ? ' Backhaul will also be uninstalled from the relay over SSH.' : ' Backhaul on the relay server has to be removed manually.';
        if (!confirm(`Delete tunnel "${t.name}"?${extra}`)) return;
        try {
            await deleteTunnel(id);
            notify('Tunnel deleted', 'success');
            setTunnels(prev => prev.filter(t => t.id !== id));
        } catch (e: any) {
            notify(e.message, 'error');
        }
    };

    const copyCmd = async () => {
        if (!installCmd) return;
        try {
            // navigator.clipboard only exists in secure contexts (HTTPS/localhost);
            // the panel is often served over plain HTTP, so fall back to execCommand.
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(installCmd);
            } else {
                const ta = document.createElement('textarea');
                ta.value = installCmd;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                const ok = document.execCommand('copy');
                document.body.removeChild(ta);
                if (!ok) throw new Error('copy failed');
            }
            notify('Script copied to clipboard', 'success');
        } catch {
            notify('Could not copy automatically, please copy the script manually', 'warn');
        }
    };

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 flex items-center gap-2">
                        <Network className="w-8 h-8 text-orange-500" /> Tunnels
                    </h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400">Backhaul relay servers that forward traffic to this server</p>
                </div>
                <BtnPrimary onClick={() => setShowAddModal(true)}><Plus className="w-4 h-4 mr-2" /> Add Tunnel</BtnPrimary>
            </div>

            <div className="flex gap-3 p-4 rounded-xl bg-blue-50 dark:bg-blue-900/20 border border-blue-200/60 dark:border-blue-800/50 text-sm text-blue-800 dark:text-blue-300">
                <Info className="w-5 h-5 shrink-0 mt-0.5" />
                <div className="space-y-1">
                    <p>A tunnel turns another server (the <b>relay</b>) into an entry point: users connect to the <b>relay IP</b> and Backhaul forwards the traffic to this server.</p>
                    <p>V2Ray configs named <b>&quot;via &lt;relay name&gt;&quot;</b> appear automatically in the clients once the tunnel is installed.</p>
                </div>
            </div>

            {loading ? (
                <div className="py-20 flex justify-center"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>
            ) : tunnels.length === 0 ? (
                <div className="py-20 text-center text-slate-500 bg-slate-50 dark:bg-slate-800/50 rounded-2xl border border-slate-200 dark:border-slate-700 border-dashed">
                    <Server className="w-12 h-12 mx-auto mb-3 opacity-20" />
                    <p>No tunnels configured yet.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {tunnels.map(t => {
                        const status = t.status || 'pending';
                        const ports = t.ports || [];
                        return (
                        <Card key={t.id} className="relative group flex flex-col">
                            <div className="flex items-center gap-3 mb-3">
                                <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-blue-500"><Server size={20} /></div>
                                <div className="min-w-0">
                                    <h3 className="font-bold text-slate-800 dark:text-slate-200 truncate">{t.name}</h3>
                                    <div className="text-xs text-slate-500 font-mono">{t.ip}</div>
                                </div>
                            </div>
                            <div className="space-y-1.5 text-xs">
                                {[
                                    ['Transport', (TRANSPORTS.find(x => x.value === t.transport)?.label || t.transport || 'tcp')],
                                    ['Tunnel Port', String(t.tunnel_port ?? 3080)],
                                    ['SSH', `${t.username || 'root'}@${t.ip}:${t.port}${t.has_password ? '' : ' (manual install)'}`],
                                    ['UDP', t.accept_udp ? 'Accepted' : 'Off'],
                                ].map(([k, v]) => (
                                    <div key={k} className="flex justify-between gap-2">
                                        <span className="text-slate-500 dark:text-slate-400">{k}</span>
                                        <span className="font-mono text-slate-700 dark:text-slate-300 text-right truncate">{v}</span>
                                    </div>
                                ))}
                                <div>
                                    <div className="text-slate-500 dark:text-slate-400 mb-1">Forwarded Ports</div>
                                    <div className="flex flex-wrap gap-1">
                                        {ports.length === 0
                                            ? <span className="text-slate-400 italic">none</span>
                                            : ports.map(p => <span key={p} className="px-1.5 py-0.5 rounded-md bg-slate-100 dark:bg-slate-700 font-mono text-[10px] text-slate-600 dark:text-slate-300">{p}</span>)}
                                    </div>
                                </div>
                            </div>
                            {status === 'failed' && t.error && (
                                <div className="mt-3 p-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200/60 dark:border-red-800/50 text-[11px] text-red-700 dark:text-red-400 font-mono whitespace-pre-wrap break-all max-h-32 overflow-y-auto flex gap-1.5">
                                    <AlertTriangle size={12} className="shrink-0 mt-0.5" /><span>{t.error}</span>
                                </div>
                            )}
                            <div className="flex-1" />
                            <div className="flex items-center gap-2 mt-4 pt-4 border-t border-slate-100 dark:border-slate-700/50">
                                <div className={`px-2 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 ${STATUS_STYLE[status] || STATUS_STYLE.pending}`}>
                                    {status === 'installing' && <Loader2 size={10} className="animate-spin" />}
                                    {status.toUpperCase()}
                                </div>
                                <div
                                    title="Backhaul client on this server"
                                    className={`px-2 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 ${t.local_running ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400'}`}
                                >
                                    <span className={`w-1.5 h-1.5 rounded-full ${t.local_running ? 'bg-green-500' : 'bg-slate-400'}`} />
                                    {t.local_running ? 'LOCAL RUNNING' : 'LOCAL STOPPED'}
                                </div>
                                <div className="flex-1" />
                                <button
                                    onClick={() => handleReinstall(t)}
                                    disabled={reinstalling === t.id || status === 'installing'}
                                    title={t.has_password ? 'Reinstall on the relay over SSH' : 'Restart the local client (no SSH password stored)'}
                                    className="p-1.5 text-slate-400 hover:text-orange-500 hover:bg-orange-50 dark:hover:bg-orange-900/20 rounded-lg transition-colors disabled:opacity-40 flex items-center gap-1 text-xs font-bold"
                                >
                                    <RefreshCw size={14} className={reinstalling === t.id ? 'animate-spin' : ''} /> Reinstall
                                </button>
                                <button onClick={() => handleDelete(t)} title="Delete tunnel" className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"><Trash2 size={16} /></button>
                            </div>
                        </Card>
                        );
                    })}
                </div>
            )}

            {/* Add Modal */}
            <Modal open={showAddModal} onClose={() => setShowAddModal(false)} title="Add Tunnel Server">
                <div className="space-y-4">
                    <div><Label>Server Name</Label><Input value={formData.name} placeholder="e.g. EU Bridge" onChange={e => setFormData({ ...formData, name: e.target.value })} /></div>
                    <div className="grid grid-cols-2 gap-4">
                        <div><Label>Relay IP</Label><Input value={formData.ip} placeholder="1.2.3.4" onChange={e => setFormData({ ...formData, ip: e.target.value })} /></div>
                        <div><Label>SSH Port</Label><Input type="number" value={formData.port} onChange={e => setFormData({ ...formData, port: +e.target.value })} /></div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <div><Label>SSH Username</Label><Input value={formData.username} placeholder="root" onChange={e => setFormData({ ...formData, username: e.target.value })} /></div>
                        <div><Label>SSH Password</Label><Input type="password" value={formData.password} placeholder="Optional" onChange={e => setFormData({ ...formData, password: e.target.value })} /></div>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 -mt-2">With a password the relay is installed automatically over SSH. Without one you get an install script to run on the relay yourself.</p>
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <Label>Transport</Label>
                            <Select value={formData.transport} onChange={e => setFormData({ ...formData, transport: e.target.value as TunnelTransport })}>
                                {TRANSPORTS.map(tr => <option key={tr.value} value={tr.value}>{tr.label}</option>)}
                            </Select>
                        </div>
                        <div><Label>Tunnel Port</Label><Input type="number" value={formData.tunnel_port} onChange={e => setFormData({ ...formData, tunnel_port: +e.target.value })} /></div>
                    </div>
                    <div>
                        <Label>Forwarded Ports</Label>
                        <Input value={formData.ports} placeholder="e.g. 443, 8080 or 8443=443 (empty = all VPN TCP ports)" onChange={e => setFormData({ ...formData, ports: e.target.value })} />
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Tunnel port is the Backhaul port on the relay and must differ from the forwarded ports.</p>
                    </div>
                    <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300 cursor-pointer">
                        <input type="checkbox" className="accent-orange-500 w-4 h-4" checked={formData.accept_udp} onChange={e => setFormData({ ...formData, accept_udp: e.target.checked })} />
                        Accept UDP traffic
                    </label>
                    <div className="pt-4 flex justify-end gap-2">
                        <BtnSecondary onClick={() => setShowAddModal(false)}>Cancel</BtnSecondary>
                        <BtnPrimary onClick={handleAdd} disabled={adding}>{adding ? 'Adding...' : 'Add Server'}</BtnPrimary>
                    </div>
                </div>
            </Modal>

            {/* Install Command Modal */}
            <Modal open={!!installCmd} onClose={() => setInstallCmd(null)} title="Install Relay" wide>
                <div className="space-y-4">
                    <p className="text-sm text-slate-600 dark:text-slate-300">
                        No SSH password was given, so run this script <b>on the relay server as root</b>. For example, save it as <code className="font-mono text-xs px-1 rounded bg-slate-100 dark:bg-slate-700">install-relay.sh</code> and run <code className="font-mono text-xs px-1 rounded bg-slate-100 dark:bg-slate-700">sudo bash install-relay.sh</code>.
                    </p>
                    <div className="relative group">
                        <pre className="bg-slate-900 text-slate-300 p-4 rounded-xl font-mono text-xs whitespace-pre overflow-auto max-h-[50vh] pr-12">{installCmd}</pre>
                        <button onClick={copyCmd} className="absolute right-2 top-2 p-2 hover:bg-white/10 rounded-lg text-white transition-colors">
                            <Copy size={16} />
                        </button>
                    </div>
                    <div className="pt-2 flex justify-end">
                        <BtnPrimary onClick={() => setInstallCmd(null)}>Done</BtnPrimary>
                    </div>
                </div>
            </Modal>
        </div>
    );
};

export default TunnelPage;
