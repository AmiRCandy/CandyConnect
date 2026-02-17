import React, { useState, useEffect } from 'react';
import { getCoreConfigs, updateCoreConfig, restartCore, getCores, type CoreConfigs, type VpnCore } from '../services/api';
import { useNotify } from '../components/Notification';
import { Candy, Zap, Shield, Lock, KeyRound, Radio, Globe, Wind, Castle, Settings, Circle, Loader2 } from 'lucide-react';

const TABS = [
  { id: 'candyconnect', name: 'CandyConnect', icon: <Candy size={14} /> },
  { id: 'v2ray', name: 'V2Ray', icon: <Zap size={14} /> },
  { id: 'wireguard', name: 'WireGuard', icon: <Shield size={14} /> },
  { id: 'openvpn', name: 'OpenVPN', icon: <Lock size={14} /> },
  { id: 'ikev2', name: 'IKEv2', icon: <KeyRound size={14} /> },
  { id: 'l2tp', name: 'L2TP', icon: <Radio size={14} /> },
  { id: 'dnstt', name: 'DNSTT', icon: <Globe size={14} /> },
  { id: 'slipstream', name: 'SlipStream', icon: <Wind size={14} /> },
  { id: 'trusttunnel', name: 'TrustTunnel', icon: <Castle size={14} /> },
];

const Card: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => (
  <div className={`bg-white dark:bg-slate-800 rounded-xl p-5 shadow-sm border border-slate-200/50 dark:border-slate-700/50 ${className}`}>{children}</div>
);
const Label: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1 uppercase tracking-wide">{children}</label>
);
const Input: React.FC<React.InputHTMLAttributes<HTMLInputElement>> = (props) => (
  <input {...props} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors" />
);
const Select: React.FC<React.SelectHTMLAttributes<HTMLSelectElement> & { options: string[] }> = ({ options, ...props }) => (
  <select {...props} className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 text-sm focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors">
    {options.map(o => <option key={o} value={o}>{o}</option>)}
  </select>
);
const Toggle: React.FC<{ label: string; checked: boolean; onChange: () => void }> = ({ label, checked, onChange }) => (
  <label className="flex items-center gap-2.5 cursor-pointer">
    <button type="button" onClick={onChange} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${checked ? 'bg-orange-500' : 'bg-slate-300 dark:bg-slate-600'}`}>
      <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
    <span className="text-sm text-slate-700 dark:text-slate-300">{label}</span>
  </label>
);
const BtnPrimary: React.FC<{ children: React.ReactNode; onClick: () => void; disabled?: boolean }> = ({ children, onClick, disabled }) => (
  <button onClick={onClick} disabled={disabled} className="px-4 py-2 rounded-xl text-sm font-bold text-white bg-orange-500 hover:bg-orange-600 active:scale-[0.98] transition-all disabled:opacity-50">{children}</button>
);
const BtnWarn: React.FC<{ children: React.ReactNode; onClick: () => void; disabled?: boolean }> = ({ children, onClick, disabled }) => (
  <button onClick={onClick} disabled={disabled} className="px-4 py-2 rounded-xl text-sm font-bold text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/40 transition-colors disabled:opacity-50">{children}</button>
);

// Extracted as a proper component to avoid React hooks violation
const WireGuardConfigPanel: React.FC<{
  cfg: CoreConfigs; saving: boolean;
  save: (section: string, data: unknown, name: string) => Promise<void>;
  restart: (id: string, name: string) => Promise<void>;
}> = ({ cfg, saving, save, restart }) => {
  const [formData, setFormData] = useState({ ...cfg.wireguard });

  useEffect(() => {
    setFormData({ ...cfg.wireguard });
  }, [cfg.wireguard]);

  return (
    <Card className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
          <Shield className="w-5 h-5 text-blue-500" /> WireGuard Config (wg0)
        </h3>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
        <div><Label>Listen Port</Label><Input type="number" value={formData.listen_port} onChange={e => setFormData({ ...formData, listen_port: +e.target.value })} /></div>
        <div><Label>DNS Servers</Label><Input value={formData.dns} onChange={e => setFormData({ ...formData, dns: e.target.value })} /></div>
        <div><Label>Internal Address</Label><Input value={formData.address} onChange={e => setFormData({ ...formData, address: e.target.value })} /></div>
        <div><Label>MTU</Label><Input type="number" value={formData.mtu} onChange={e => setFormData({ ...formData, mtu: +e.target.value })} /></div>
        <div className="sm:col-span-2">
          <Label>Public Key (Read Only)</Label>
          <Input value={formData.public_key} readOnly className="bg-slate-100 dark:bg-slate-800 opacity-70 font-mono text-[10px]" />
        </div>
        <div className="sm:col-span-2"><Label>Post Up Command</Label><Input value={formData.post_up} onChange={e => setFormData({ ...formData, post_up: e.target.value })} /></div>
        <div className="sm:col-span-2"><Label>Post Down Command</Label><Input value={formData.post_down} onChange={e => setFormData({ ...formData, post_down: e.target.value })} /></div>
      </div>
      <div className="border-t border-slate-200 dark:border-slate-700 pt-4 flex flex-wrap gap-3">
        <BtnPrimary disabled={saving} onClick={() => save('wireguard', formData, 'WireGuard')}>Save Config</BtnPrimary>
        <BtnWarn onClick={() => restart('wireguard', 'WireGuard')}>Restart Service</BtnWarn>
      </div>
    </Card>
  );
};

// Extracted as a proper component to handle mutable form state correctly
const SimpleConfigPanel: React.FC<{
  id: string; title: string; cfg: CoreConfigs; cores: VpnCore[]; saving: boolean;
  fields: { label: string; key: string; type?: string; options?: string[]; value: any; readOnly?: boolean }[];
  toggles: { label: string; key: string; value: boolean }[];
  save: (section: string, data: unknown, name: string) => Promise<void>;
  restart: (id: string, name: string) => Promise<void>;
}> = ({ id, title, cfg, cores, saving, fields, toggles, save, restart }) => {
  const sectionKey = id as keyof CoreConfigs;
  const [formData, setFormData] = useState<Record<string, any>>({ ...(cfg[sectionKey] as any) });

  useEffect(() => {
    setFormData({ ...(cfg[sectionKey] as any) });
  }, [cfg, sectionKey]);

  const core = cores.find(c => c.id === id);
  const icons: any = { openvpn: Lock, ikev2: KeyRound, l2tp: Radio, dnstt: Globe, slipstream: Wind, trusttunnel: Castle };
  const Icon = icons[id] || Circle;

  return (
    <Card className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2"><Icon className="w-5 h-5 text-slate-500" /> {title}</h3>
        {core && <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${core.status === 'running' ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'}`}>{core.status === 'running' ? 'Online' : 'Offline'}</span>}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {fields.map(f => (
          <div key={f.key}>
            <Label>{f.label}</Label>
            {f.options
              ? <Select value={formData[f.key] ?? f.value} options={f.options} onChange={e => setFormData(prev => ({ ...prev, [f.key]: e.target.value }))} />
              : <Input type={f.type || 'text'} value={formData[f.key] ?? f.value} readOnly={f.readOnly} onChange={e => !f.readOnly && setFormData(prev => ({ ...prev, [f.key]: f.type === 'number' ? +e.target.value : e.target.value }))} />
            }
          </div>
        ))}
      </div>
      {toggles.length > 0 && (
        <div className="flex flex-wrap gap-4 pt-1">
          {toggles.map(t => <Toggle key={t.key} label={t.label} checked={formData[t.key] ?? t.value} onChange={() => setFormData(prev => ({ ...prev, [t.key]: !(prev[t.key] ?? t.value) }))} />)}
        </div>
      )}
      <div className="border-t border-slate-200 dark:border-slate-700 pt-4 flex flex-wrap gap-3">
        <BtnPrimary disabled={saving} onClick={() => save(id, formData, title)}>Save Config</BtnPrimary>
        <BtnWarn onClick={() => restart(id, title.split(' ')[0])}>Restart Service</BtnWarn>
      </div>
    </Card>
  );
};

const CoreConfigsPage: React.FC = () => {
  const { notify } = useNotify();
  const [activeTab, setActiveTab] = useState('candyconnect');
  const [cfg, setCfg] = useState<CoreConfigs | null>(null);
  const [cores, setCores] = useState<VpnCore[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Editable state
  const [ccDomain, setCcDomain] = useState('');
  const [ccMaxClients, setCcMaxClients] = useState(500);
  const [ccLogLevel, setCcLogLevel] = useState('info');
  const [ccSsl, setCcSsl] = useState(true);
  const [ccAutoBackup, setCcAutoBackup] = useState(true);
  const [ccApi, setCcApi] = useState(true);
  const [v2rayJson, setV2rayJson] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const [c, co] = await Promise.all([getCoreConfigs(), getCores()]);
        setCfg(c); setCores(co);
        setCcDomain(c.candyconnect.panel_domain);
        setCcMaxClients(c.candyconnect.max_clients);
        setCcLogLevel(c.candyconnect.log_level);
        setCcSsl(c.candyconnect.ssl_enabled);
        setCcAutoBackup(c.candyconnect.auto_backup);
        setCcApi(c.candyconnect.api_enabled);
        setV2rayJson(c.v2ray.config_json);
      } catch (e: any) {
        notify(e.message || 'Failed to load configs', 'error');
      } finally { setLoading(false); }
    })();
  }, []);

  if (loading || !cfg) return <div className="flex items-center justify-center py-20"><Loader2 className="w-8 h-8 animate-spin text-orange-500" /></div>;

  const save = async (section: string, data: unknown, name: string) => {
    setSaving(true);
    try {
      await updateCoreConfig(section, data);
      notify(`${name} configuration saved`, 'success');
      // Reload configs
      const updated = await getCoreConfigs();
      setCfg(updated);
    } catch (e: any) {
      notify(e.message || 'Failed to save', 'error');
    } finally { setSaving(false); }
  };

  const restart = async (id: string, name: string) => {
    notify(`Restarting ${name}...`, 'warn');
    try {
      await restartCore(id);
      notify(`${name} restarted`, 'success');
    } catch (e: any) {
      notify(e.message || `Failed to restart ${name}`, 'error');
    }
  };

  const renderCandyConnect = () => (
    <Card className="space-y-4">
      <div className="flex items-center justify-between"><h3 className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2"><Candy className="w-5 h-5 text-orange-500" /> CandyConnect Config</h3><span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400">Active</span></div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div><Label>Panel Domain</Label><Input value={ccDomain} onChange={e => setCcDomain(e.target.value)} /></div>
        <div><Label>Max Clients</Label><Input type="number" value={ccMaxClients} onChange={e => setCcMaxClients(+e.target.value)} /></div>
        <div><Label>SSL Cert Path</Label><Input value={cfg.candyconnect.ssl_cert_path} readOnly /></div>
        <div><Label>SSL Key Path</Label><Input value={cfg.candyconnect.ssl_key_path} readOnly /></div>
        <div><Label>Log Level</Label><Select value={ccLogLevel} onChange={e => setCcLogLevel(e.target.value)} options={['debug', 'info', 'warn', 'error']} /></div>
        <div><Label>Backup Interval (hrs)</Label><Input type="number" value={cfg.candyconnect.backup_interval} readOnly /></div>
      </div>
      <div className="flex flex-wrap gap-4 pt-2">
        <Toggle label="SSL Enabled" checked={ccSsl} onChange={() => setCcSsl(!ccSsl)} />
        <Toggle label="Auto Backup" checked={ccAutoBackup} onChange={() => setCcAutoBackup(!ccAutoBackup)} />
        <Toggle label={`API Enabled (Port: ${cfg.candyconnect.api_port})`} checked={ccApi} onChange={() => setCcApi(!ccApi)} />
      </div>
      <div className="border-t border-slate-200 dark:border-slate-700 pt-4 flex flex-wrap gap-3">
        <BtnPrimary disabled={saving} onClick={() => save('candyconnect', { ...cfg.candyconnect, panel_domain: ccDomain, max_clients: ccMaxClients, log_level: ccLogLevel, ssl_enabled: ccSsl, auto_backup: ccAutoBackup, api_enabled: ccApi }, 'CandyConnect')}>Save Config</BtnPrimary>
      </div>
    </Card>
  );

  const renderV2Ray = () => (
    <Card className="space-y-4">
      <div className="flex items-center justify-between"><h3 className="font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2"><Zap className="w-5 h-5 text-yellow-500" /> V2Ray / Xray Config</h3></div>
      <p className="text-xs text-slate-500 dark:text-slate-400">Edit the xray.json configuration.</p>
      <div>
        <Label>XRAY.JSON</Label>
        <textarea value={v2rayJson} onChange={e => setV2rayJson(e.target.value)} className="w-full min-h-[300px] px-4 py-3 border border-slate-300 dark:border-slate-600 rounded-xl bg-slate-50 dark:bg-slate-700 text-slate-900 dark:text-slate-200 font-mono text-xs focus:ring-2 focus:ring-orange-500 focus:border-transparent transition-colors resize-y" spellCheck={false} />
      </div>
      <div className="flex flex-wrap gap-2">
        <button onClick={() => { try { setV2rayJson(JSON.stringify(JSON.parse(v2rayJson), null, 2)); notify('JSON formatted', 'success'); } catch (e: any) { notify('Invalid JSON: ' + e.message, 'error'); } }} className="px-3 py-1.5 rounded-lg text-xs font-bold text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-600 hover:bg-slate-200 dark:hover:bg-slate-500 transition-colors">🔧 Format</button>
        <button onClick={() => { try { JSON.parse(v2rayJson); notify('✓ JSON is valid', 'success'); } catch (e: any) { notify('✗ ' + e.message, 'error'); } }} className="px-3 py-1.5 rounded-lg text-xs font-bold text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-600 hover:bg-slate-200 dark:hover:bg-slate-500 transition-colors">✓ Validate</button>
      </div>
      <div className="border-t border-slate-200 dark:border-slate-700 pt-4 flex flex-wrap gap-3">
        <BtnPrimary disabled={saving} onClick={() => { try { JSON.parse(v2rayJson); save('v2ray', { config_json: v2rayJson }, 'V2Ray'); } catch (e: any) { notify('Invalid JSON: ' + e.message, 'error'); } }}>Save Config</BtnPrimary>
        <BtnWarn onClick={() => restart('v2ray', 'Xray')}>Restart Xray</BtnWarn>
      </div>
    </Card>
  );

  const renderWireGuard = () => (
    <WireGuardConfigPanel cfg={cfg} saving={saving} save={save} restart={restart} />
  );

  const renderSimpleConfig = (id: string, title: string, fields: { label: string; key: string; type?: string; options?: string[]; value: any; readOnly?: boolean }[], toggles: { label: string; key: string; value: boolean }[] = []) => (
    <SimpleConfigPanel key={id} id={id} title={title} cfg={cfg} cores={cores} saving={saving} fields={fields} toggles={toggles} save={save} restart={restart} />
  );

  const renderTab = () => {
    switch (activeTab) {
      case 'candyconnect': return renderCandyConnect();
      case 'v2ray': return renderV2Ray();
      case 'wireguard': return renderWireGuard();
      case 'openvpn': return renderSimpleConfig('openvpn', 'OpenVPN', [
        { label: 'Port', key: 'port', type: 'number', value: cfg.openvpn.port },
        { label: 'Protocol', key: 'protocol', options: ['udp', 'tcp'], value: cfg.openvpn.protocol },
        { label: 'Device', key: 'device', options: ['tun', 'tap'], value: cfg.openvpn.device },
        { label: 'Cipher', key: 'cipher', options: ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'], value: cfg.openvpn.cipher },
        { label: 'Auth', key: 'auth', options: ['SHA512', 'SHA256', 'SHA1'], value: cfg.openvpn.auth },
        { label: 'DNS 1', key: 'dns1', value: cfg.openvpn.dns1 },
        { label: 'DNS 2', key: 'dns2', value: cfg.openvpn.dns2 },
        { label: 'Subnet', key: 'subnet', value: cfg.openvpn.subnet },
        { label: 'Max Clients', key: 'max_clients', type: 'number', value: cfg.openvpn.max_clients },
        { label: 'Keepalive', key: 'keepalive', value: cfg.openvpn.keepalive },
      ], [{ label: 'TLS-Crypt', key: 'tls_crypt', value: cfg.openvpn.tls_crypt }, { label: 'Comp-LZO', key: 'comp_lzo', value: cfg.openvpn.comp_lzo }]);
      case 'ikev2': return renderSimpleConfig('ikev2', 'IKEv2/IPSec', [
        { label: 'Port', key: 'port', type: 'number', value: cfg.ikev2.port },
        { label: 'NAT Port', key: 'nat_port', type: 'number', value: cfg.ikev2.nat_port },
        { label: 'Cipher Suite', key: 'cipher', value: cfg.ikev2.cipher },
        { label: 'SA Lifetime', key: 'lifetime', value: cfg.ikev2.lifetime },
        { label: 'Margin Time', key: 'margintime', value: cfg.ikev2.margintime },
        { label: 'DNS', key: 'dns', value: cfg.ikev2.dns },
        { label: 'Subnet', key: 'subnet', value: cfg.ikev2.subnet },
        { label: 'Cert Validity (days)', key: 'cert_validity', type: 'number', value: cfg.ikev2.cert_validity },
      ]);
      case 'l2tp': return renderSimpleConfig('l2tp', 'L2TP/IPSec', [
        { label: 'Port', key: 'port', type: 'number', value: cfg.l2tp.port },
        { label: 'IPSec Port', key: 'ipsec_port', type: 'number', value: cfg.l2tp.ipsec_port },
        { label: 'Pre-Shared Key', key: 'psk', value: cfg.l2tp.psk },
        { label: 'Local IP', key: 'local_ip', value: cfg.l2tp.local_ip },
        { label: 'Remote Range', key: 'remote_range', value: cfg.l2tp.remote_range },
        { label: 'DNS', key: 'dns', value: cfg.l2tp.dns },
        { label: 'MTU', key: 'mtu', type: 'number', value: cfg.l2tp.mtu },
        { label: 'MRU', key: 'mru', type: 'number', value: cfg.l2tp.mru },
      ]);
      case 'dnstt': return renderSimpleConfig('dnstt', 'DNSTT', [
        { label: 'Listen Port', key: 'listen_port', type: 'number', value: cfg.dnstt.listen_port },
        { label: 'Domain', key: 'domain', value: cfg.dnstt.domain },
        { label: 'Tunnel Mode', key: 'tunnel_mode', options: ['ssh', 'socks'], value: cfg.dnstt.tunnel_mode },
        { label: 'MTU', key: 'mtu', type: 'number', value: cfg.dnstt.mtu },
        { label: 'Public Key', key: 'public_key', value: cfg.dnstt.public_key, readOnly: true },
      ]);
      case 'slipstream': return renderSimpleConfig('slipstream', 'SlipStream', [
        { label: 'Port', key: 'port', type: 'number', value: cfg.slipstream.port },
        { label: 'Method', key: 'method', options: ['aes-256-cfb', 'aes-256-gcm', 'chacha20-ietf-poly1305'], value: cfg.slipstream.method },
        { label: 'Obfuscation', key: 'obfs', options: ['tls', 'http', 'none'], value: cfg.slipstream.obfs },
        { label: 'Obfs Host', key: 'obfs_host', value: cfg.slipstream.obfs_host },
        { label: 'Timeout (s)', key: 'timeout', type: 'number', value: cfg.slipstream.timeout },
      ], [{ label: 'TCP Fast Open', key: 'fast_open', value: cfg.slipstream.fast_open }, { label: 'No Delay', key: 'no_delay', value: cfg.slipstream.no_delay }, { label: 'UDP Relay', key: 'udp_relay', value: cfg.slipstream.udp_relay }]);
      case 'trusttunnel': return renderSimpleConfig('trusttunnel', 'TrustTunnel', [
        { label: 'Port', key: 'port', type: 'number', value: cfg.trusttunnel.port },
        { label: 'Protocol', key: 'protocol', options: ['https', 'http', 'quic'], value: cfg.trusttunnel.protocol },
        { label: 'Camouflage', key: 'camouflage', options: ['cloudflare', 'amazon', 'google', 'none'], value: cfg.trusttunnel.camouflage },
        { label: 'Fragment Size', key: 'fragment_size', type: 'number', value: cfg.trusttunnel.fragment_size },
        { label: 'Fragment Interval (ms)', key: 'fragment_interval', type: 'number', value: cfg.trusttunnel.fragment_interval },
        { label: 'SNI', key: 'sni', value: cfg.trusttunnel.sni },
        { label: 'ALPN', key: 'alpn', value: cfg.trusttunnel.alpn },
        { label: 'Timeout (s)', key: 'timeout', type: 'number', value: cfg.trusttunnel.timeout },
      ], [{ label: 'Padding', key: 'padding', value: cfg.trusttunnel.padding }]);
      default: return null;
    }
  };

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 flex items-center gap-2"><Settings className="w-8 h-8 text-orange-500" /> Core Configs</h1>
        <p className="text-xs text-slate-500 dark:text-slate-400">Configure VPN protocol cores</p>
      </div>
      <div className="flex overflow-x-auto gap-1 pb-1 -mx-1 px-1">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`px-3 py-2 rounded-xl text-xs font-bold whitespace-nowrap transition-colors flex items-center gap-1.5 ${activeTab === t.id ? 'bg-orange-500 text-white shadow-md shadow-orange-300/30' : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-orange-50 dark:hover:bg-slate-700 border border-slate-200/50 dark:border-slate-700/50'}`}>
            {t.icon} {t.name}
          </button>
        ))}
      </div>
      <div className="animate-fade-in" key={activeTab}>{renderTab()}</div>
    </div>
  );
};

export default CoreConfigsPage;
