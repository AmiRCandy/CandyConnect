import React, { useState, useEffect } from 'react';
import { getTunnels, addTunnel, deleteTunnel, type Tunnel } from '../services/api';
import { useNotify } from '../components/Notification';
import { Network, Server, Plus, Trash2, Terminal, Copy, Loader2, Check } from 'lucide-react';
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

const TunnelPage: React.FC = () => {
    const { notify } = useNotify();
    const [tunnels, setTunnels] = useState<Tunnel[]>([]);
    const [loading, setLoading] = useState(true);
    const [adding, setAdding] = useState(false);
    const [showAddModal, setShowAddModal] = useState(false);
    const [installCmd, setInstallCmd] = useState<string | null>(null);

    const [formData, setFormData] = useState({ name: '', ip: '', port: 22, username: 'root', password: '', tunnel_type: 'backhaul' });

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
        setAdding(true);
        try {
            const res = await addTunnel({ ...formData, name: formData.name.trim(), ip: formData.ip.trim(), port: +formData.port, password: formData.password || undefined });
            notify(formData.password ? 'Tunnel added, SSH installation started' : 'Tunnel added successfully', 'success');
            setInstallCmd(res.install_command);
            fetchTunnels();
            setShowAddModal(false);
            setFormData({ name: '', ip: '', port: 22, username: 'root', password: '', tunnel_type: 'backhaul' });
        } catch (e: any) {
            notify(e.message, 'error');
        } finally {
            setAdding(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!confirm('Are you sure you want to delete this tunnel?')) return;
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
            notify('Command copied to clipboard', 'success');
        } catch {
            notify('Could not copy automatically, please copy the command manually', 'warn');
        }
    };

    return (
        <div className="space-y-6 animate-fade-in">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 flex items-center gap-2">
                        <Network className="w-8 h-8 text-orange-500" /> Tunnels
                    </h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400">Manage remote tunnel servers and bridges</p>
                </div>
                <BtnPrimary onClick={() => setShowAddModal(true)}><Plus className="w-4 h-4 mr-2" /> Add Tunnel</BtnPrimary>
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
                    {tunnels.map(t => (
                        <Card key={t.id} className="relative group">
                            <div className="flex items-center gap-3 mb-3">
                                <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-blue-500"><Server size={20} /></div>
                                <div>
                                    <h3 className="font-bold text-slate-800 dark:text-slate-200">{t.name}</h3>
                                    <div className="text-xs text-slate-500 font-mono">{t.ip}:{t.port}</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-2 mt-4 pt-4 border-t border-slate-100 dark:border-slate-700/50">
                                <div className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${t.status === 'installed' ? 'bg-green-100 dark:bg-green-900/30 text-green-700' : t.status === 'failed' ? 'bg-red-100 dark:bg-red-900/30 text-red-700' : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700'}`}>
                                    {(t.status || 'pending').toUpperCase()}
                                </div>
                                <div className="flex-1" />
                                <button onClick={() => handleDelete(t.id)} className="p-1.5 text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"><Trash2 size={16} /></button>
                            </div>
                        </Card>
                    ))}
                </div>
            )}

            {/* Add Modal */}
            <Modal open={showAddModal} onClose={() => setShowAddModal(false)} title="Add Tunnel Server">
                <div className="space-y-4">
                    <div><Label>Server Name</Label><Input value={formData.name} placeholder="e.g. EU Bridge" onChange={e => setFormData({ ...formData, name: e.target.value })} /></div>
                    <div className="grid grid-cols-2 gap-4">
                        <div><Label>Server IP</Label><Input value={formData.ip} placeholder="1.2.3.4" onChange={e => setFormData({ ...formData, ip: e.target.value })} /></div>
                        <div><Label>SSH Port</Label><Input type="number" value={formData.port} onChange={e => setFormData({ ...formData, port: +e.target.value })} /></div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <div><Label>SSH Username</Label><Input value={formData.username} placeholder="root" onChange={e => setFormData({ ...formData, username: e.target.value })} /></div>
                        <div><Label>SSH Password</Label><Input type="password" value={formData.password} placeholder="Optional" onChange={e => setFormData({ ...formData, password: e.target.value })} /></div>
                    </div>
                    <div>
                        <Label>Tunnel Type</Label>
                        <select
                            className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors"
                            value={formData.tunnel_type}
                            onChange={e => setFormData({ ...formData, tunnel_type: e.target.value })}
                        >
                            <option value="backhaul">Backhaul</option>
                            <option value="dekoomo-door">Dekoomo Door</option>
                            <option value="rathole">Rathole</option>
                            <option value="paqet">Paqet</option>
                        </select>
                    </div>
                    <div className="pt-4 flex justify-end gap-2">
                        <BtnSecondary onClick={() => setShowAddModal(false)}>Cancel</BtnSecondary>
                        <BtnPrimary onClick={handleAdd} disabled={adding}>{adding ? 'Adding...' : 'Add Server'}</BtnPrimary>
                    </div>
                </div>
            </Modal>

            {/* Install Command Modal */}
            <Modal open={!!installCmd} onClose={() => setInstallCmd(null)} title="Install Tunnel">
                <div className="space-y-4">
                    <p className="text-sm text-slate-600 dark:text-slate-300">Run this command on your remote server to install the tunnel agent:</p>
                    <div className="relative group">
                        <div className="bg-slate-900 text-slate-300 p-4 rounded-xl font-mono text-xs break-all pr-12">
                            {installCmd}
                        </div>
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
