import React from 'react';
import { Zap, Shield, Lock, KeyRound, Radio, Globe, Wind, Castle, Circle, Pause } from 'lucide-react';

// ============================================================
// CandyConnect Server Panel - Mock Data (mirrors web-panel)
// ============================================================

export interface AdminCredentials { username: string; password: string; }
export interface PanelConfig { panelPort: number; panelPath: string; version: string; buildDate: string; }
export interface ServerInfo {
    hostname: string; ip: string; os: string; kernel: string; uptime: number;
    cpu: { model: string; cores: number; usage: number };
    ram: { total: number; used: number };
    disk: { total: number; used: number };
    network: { totalIn: number; totalOut: number; speedIn: number; speedOut: number };
}
export interface VPNCore {
    id: string; name: string; status: 'running' | 'stopped'; version: string;
    uptime: number; port: number; activeConnections: number;
    totalTraffic: { in: number; out: number }; icon: React.ReactNode;
}
export interface LogEntry { time: string; level: 'INFO' | 'WARN' | 'ERROR'; source: string; message: string; }
export interface ClientProtocols { v2ray: boolean; wireguard: boolean; openvpn: boolean; ikev2: boolean; l2tp: boolean; dnstt: boolean; slipstream: boolean; trusttunnel: boolean; }
export interface ConnectionHistoryEntry { ip: string; time: string; protocol: string; duration: string; }
export interface Client {
    id: string; username: string; password: string; comment: string; enabled: boolean;
    group?: string;
    trafficLimit: { value: number; unit: 'GB' | 'MB' };
    trafficUsed: number;
    timeLimit: { mode: 'days' | 'months'; value: number; onHold: boolean };
    timeUsed: number;
    createdAt: string; expiresAt: string;
    protocols: ClientProtocols;
    lastConnectedIP: string | null; lastConnectedTime: string | null;
    connectionHistory: ConnectionHistoryEntry[];
}
export interface CoreConfigs {
    candyconnect: { panel_domain: string; ssl_enabled: boolean; ssl_cert_path: string; ssl_key_path: string; max_clients: number; log_level: string; auto_backup: boolean; backup_interval: number; api_enabled: boolean; api_port: number; };
    wireguard: { listen_port: number; dns: string; address: string; private_key: string; public_key: string; mtu: number; post_up: string; post_down: string; };
    v2ray: { config_json: string };
    openvpn: { port: number; protocol: string; device: string; cipher: string; auth: string; dh: string; tls_crypt: boolean; dns1: string; dns2: string; subnet: string; max_clients: number; keepalive: string; comp_lzo: boolean; };
    ikev2: { port: number; nat_port: number; cipher: string; lifetime: string; margintime: string; dns: string; subnet: string; cert_validity: number; };
    l2tp: { port: number; ipsec_port: number; psk: string; local_ip: string; remote_range: string; dns: string; mtu: number; mru: number; };
    dnstt: { listen_port: number; domain: string; public_key: string; tunnel_mode: string; mtu: number; };
    slipstream: { port: number; method: string; obfs: string; obfs_host: string; fast_open: boolean; no_delay: boolean; udp_relay: boolean; timeout: number; };
    trusttunnel: { port: number; protocol: string; camouflage: string; fragment_size: number; fragment_interval: number; sni: string; alpn: string; padding: boolean; timeout: number; };
}

export const MockData = {
    admin: { username: 'admin', password: 'admin123' } as AdminCredentials,
    panelConfig: { panelPort: 8443, panelPath: '/candyconnect', version: '1.4.2', buildDate: '2026-01-28' } as PanelConfig,
    server: {
        hostname: 'CC-VAULT-42', ip: '185.220.101.47', os: 'Ubuntu 24.04 LTS', kernel: '6.5.0-44-generic', uptime: 864000,
        cpu: { model: 'AMD EPYC 7543 32-Core', cores: 4, usage: 23 },
        ram: { total: 8192, used: 3276 },
        disk: { total: 160, used: 42 },
        network: { totalIn: 1285.7, totalOut: 3842.1, speedIn: 12.4, speedOut: 38.7 },
    } as ServerInfo,
    vpnCores: [
        { id: 'v2ray', name: 'V2Ray (Xray)', status: 'running', version: '1.8.24', uptime: 864000, port: 443, activeConnections: 47, totalTraffic: { in: 524.3, out: 1672.8 }, icon: <Zap className="w-4 h-4" /> },
        { id: 'wireguard', name: 'WireGuard', status: 'running', version: '1.0.20210914', uptime: 860000, port: 51820, activeConnections: 23, totalTraffic: { in: 312.1, out: 887.4 }, icon: <Shield className="w-4 h-4" /> },
        { id: 'openvpn', name: 'OpenVPN', status: 'running', version: '2.6.8', uptime: 855000, port: 1194, activeConnections: 15, totalTraffic: { in: 198.6, out: 534.2 }, icon: <Lock className="w-4 h-4" /> },
        { id: 'ikev2', name: 'IKEv2/IPSec', status: 'running', version: '5.9.14', uptime: 850000, port: 500, activeConnections: 8, totalTraffic: { in: 87.3, out: 245.1 }, icon: <KeyRound className="w-4 h-4" /> },
        { id: 'l2tp', name: 'L2TP/IPSec', status: 'stopped', version: '1.5.4', uptime: 0, port: 1701, activeConnections: 0, totalTraffic: { in: 45.2, out: 112.8 }, icon: <Radio className="w-4 h-4" /> },
        { id: 'dnstt', name: 'DNSTT', status: 'running', version: '0.20231205', uptime: 720000, port: 53, activeConnections: 3, totalTraffic: { in: 12.4, out: 34.7 }, icon: <Globe className="w-4 h-4" /> },
        { id: 'slipstream', name: 'SlipStream', status: 'running', version: '2.1.0', uptime: 800000, port: 8388, activeConnections: 12, totalTraffic: { in: 67.8, out: 198.3 }, icon: <Wind className="w-4 h-4" /> },
        { id: 'trusttunnel', name: 'TrustTunnel', status: 'running', version: '3.0.2', uptime: 810000, port: 9443, activeConnections: 6, totalTraffic: { in: 38.0, out: 156.8 }, icon: <Castle className="w-4 h-4" /> },
    ] as VPNCore[],
    logs: [
        { time: '2026-02-10 11:45:02', level: 'INFO', source: 'V2Ray', message: 'Client vault_dweller connected via VLESS+WS' },
        { time: '2026-02-10 11:44:58', level: 'INFO', source: 'WireGuard', message: 'Handshake completed for peer nuka_cola' },
        { time: '2026-02-10 11:44:30', level: 'WARN', source: 'System', message: 'CPU usage spike detected: 78% (threshold: 75%)' },
        { time: '2026-02-10 11:43:15', level: 'INFO', source: 'OpenVPN', message: 'Client power_armor authenticated successfully' },
        { time: '2026-02-10 11:42:50', level: 'ERROR', source: 'L2TP', message: 'Service failed to start: port 1701 configuration error' },
        { time: '2026-02-10 11:41:22', level: 'INFO', source: 'DNSTT', message: 'DNS tunnel established for client rad_roach' },
        { time: '2026-02-10 11:40:10', level: 'INFO', source: 'SlipStream', message: 'New connection from 94.182.44.12' },
        { time: '2026-02-10 11:39:45', level: 'WARN', source: 'TrustTunnel', message: 'Certificate renewal due in 7 days' },
        { time: '2026-02-10 11:38:20', level: 'INFO', source: 'System', message: 'Automatic backup completed successfully' },
        { time: '2026-02-10 11:37:00', level: 'INFO', source: 'V2Ray', message: 'Inbound traffic routed via Trojan protocol' },
        { time: '2026-02-10 11:35:55', level: 'INFO', source: 'WireGuard', message: 'Interface wg0 peer count: 23' },
        { time: '2026-02-10 11:34:30', level: 'ERROR', source: 'OpenVPN', message: 'TLS handshake failed for IP 203.0.113.55' },
        { time: '2026-02-10 11:33:10', level: 'INFO', source: 'IKEv2', message: 'SA established with client deathclaw_hunter' },
        { time: '2026-02-10 11:32:00', level: 'INFO', source: 'System', message: 'Memory usage: 40% (3276/8192 MB)' },
        { time: '2026-02-10 11:30:45', level: 'WARN', source: 'V2Ray', message: 'Rate limit triggered for IP 198.51.100.22' },
    ] as LogEntry[],
    clients: [
        { id: 'c001', username: 'vault_dweller', password: 'Pip3000Boy!', comment: 'Primary admin user', enabled: true, group: 'Admins', trafficLimit: { value: 100, unit: 'GB' }, trafficUsed: 34.7, timeLimit: { mode: 'days', value: 30, onHold: false }, timeUsed: 12, createdAt: '2026-01-15 08:30:00', expiresAt: '2026-02-14 08:30:00', protocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: true, dnstt: true, slipstream: true, trusttunnel: true }, lastConnectedIP: '94.182.44.128', lastConnectedTime: '2026-02-10 11:45:02', connectionHistory: [{ ip: '94.182.44.128', time: '2026-02-10 11:45:02', protocol: 'V2Ray', duration: 'Active' }, { ip: '94.182.44.128', time: '2026-02-10 08:12:30', protocol: 'WireGuard', duration: '3h 22m' }, { ip: '91.108.56.200', time: '2026-02-09 22:10:15', protocol: 'OpenVPN', duration: '1h 45m' }] },
        { id: 'c002', username: 'nuka_cola', password: 'QuantumFizz#42', comment: 'Office network user', enabled: true, trafficLimit: { value: 50, unit: 'GB' }, trafficUsed: 22.1, timeLimit: { mode: 'months', value: 3, onHold: false }, timeUsed: 1, createdAt: '2026-01-20 14:00:00', expiresAt: '2026-04-20 14:00:00', protocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: false, dnstt: false, slipstream: true, trusttunnel: true }, lastConnectedIP: '78.39.152.44', lastConnectedTime: '2026-02-10 11:44:58', connectionHistory: [{ ip: '78.39.152.44', time: '2026-02-10 11:44:58', protocol: 'WireGuard', duration: 'Active' }, { ip: '78.39.152.44', time: '2026-02-09 18:30:00', protocol: 'V2Ray', duration: '5h 10m' }] },
        { id: 'c003', username: 'power_armor', password: 'T60-Fusion!', comment: 'Mobile user', enabled: true, trafficLimit: { value: 500, unit: 'MB' }, trafficUsed: 0.312, timeLimit: { mode: 'days', value: 7, onHold: true }, timeUsed: 0, createdAt: '2026-02-08 10:00:00', expiresAt: '2026-02-15 10:00:00', protocols: { v2ray: true, wireguard: false, openvpn: true, ikev2: true, l2tp: true, dnstt: false, slipstream: false, trusttunnel: false }, lastConnectedIP: '5.200.67.88', lastConnectedTime: '2026-02-10 11:43:15', connectionHistory: [{ ip: '5.200.67.88', time: '2026-02-10 11:43:15', protocol: 'OpenVPN', duration: 'Active' }] },
        { id: 'c004', username: 'rad_roach', password: 'Glow1ngBug$', comment: 'Test account - censorship bypass', enabled: true, trafficLimit: { value: 10, unit: 'GB' }, trafficUsed: 4.8, timeLimit: { mode: 'days', value: 14, onHold: false }, timeUsed: 6, createdAt: '2026-02-04 16:20:00', expiresAt: '2026-02-18 16:20:00', protocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: true, dnstt: true, slipstream: true, trusttunnel: true }, lastConnectedIP: '151.232.18.90', lastConnectedTime: '2026-02-10 11:41:22', connectionHistory: [{ ip: '151.232.18.90', time: '2026-02-10 11:41:22', protocol: 'DNSTT', duration: 'Active' }, { ip: '151.232.18.90', time: '2026-02-09 20:00:00', protocol: 'V2Ray', duration: '2h 15m' }, { ip: '151.232.19.11', time: '2026-02-08 14:30:00', protocol: 'SlipStream', duration: '4h 50m' }] },
        { id: 'c005', username: 'deathclaw_hunter', password: 'Cl4w$Fury!', comment: 'Premium user', enabled: true, trafficLimit: { value: 200, unit: 'GB' }, trafficUsed: 87.3, timeLimit: { mode: 'months', value: 6, onHold: false }, timeUsed: 2, createdAt: '2025-12-10 09:00:00', expiresAt: '2026-06-10 09:00:00', protocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: true, dnstt: true, slipstream: true, trusttunnel: true }, lastConnectedIP: '188.210.33.76', lastConnectedTime: '2026-02-10 11:33:10', connectionHistory: [{ ip: '188.210.33.76', time: '2026-02-10 11:33:10', protocol: 'IKEv2', duration: 'Active' }, { ip: '188.210.33.76', time: '2026-02-10 06:00:00', protocol: 'WireGuard', duration: '4h 30m' }, { ip: '188.210.34.12', time: '2026-02-09 12:00:00', protocol: 'V2Ray', duration: '8h 15m' }, { ip: '188.210.33.76', time: '2026-02-08 20:00:00', protocol: 'TrustTunnel', duration: '3h 00m' }] },
        { id: 'c006', username: 'super_mutant', password: 'SmAsH!2026', comment: 'Disabled - bandwidth abuse', enabled: false, trafficLimit: { value: 50, unit: 'GB' }, trafficUsed: 49.8, timeLimit: { mode: 'days', value: 30, onHold: false }, timeUsed: 28, createdAt: '2026-01-12 12:00:00', expiresAt: '2026-02-11 12:00:00', protocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: true, dnstt: true, slipstream: true, trusttunnel: true }, lastConnectedIP: '62.133.47.201', lastConnectedTime: '2026-02-09 23:59:00', connectionHistory: [{ ip: '62.133.47.201', time: '2026-02-09 23:59:00', protocol: 'V2Ray', duration: '23h 58m' }] },
        { id: 'c007', username: 'pip_boy', password: 'W4steland#', comment: 'Guest access', enabled: true, trafficLimit: { value: 5, unit: 'GB' }, trafficUsed: 1.2, timeLimit: { mode: 'days', value: 3, onHold: true }, timeUsed: 0, createdAt: '2026-02-09 10:00:00', expiresAt: '2026-02-12 10:00:00', protocols: { v2ray: true, wireguard: true, openvpn: false, ikev2: false, l2tp: false, dnstt: false, slipstream: false, trusttunnel: false }, lastConnectedIP: '109.122.200.15', lastConnectedTime: '2026-02-10 09:30:00', connectionHistory: [{ ip: '109.122.200.15', time: '2026-02-10 09:30:00', protocol: 'V2Ray', duration: '2h 22m' }] },
        { id: 'c008', username: 'brotherhood', password: 'St33lReign!', comment: 'Corporate VPN access', enabled: true, trafficLimit: { value: 500, unit: 'GB' }, trafficUsed: 156.9, timeLimit: { mode: 'months', value: 12, onHold: false }, timeUsed: 4, createdAt: '2025-10-10 08:00:00', expiresAt: '2026-10-10 08:00:00', protocols: { v2ray: true, wireguard: true, openvpn: true, ikev2: true, l2tp: true, dnstt: true, slipstream: true, trusttunnel: true }, lastConnectedIP: '31.56.78.234', lastConnectedTime: '2026-02-10 10:15:00', connectionHistory: [{ ip: '31.56.78.234', time: '2026-02-10 10:15:00', protocol: 'WireGuard', duration: '1h 37m' }, { ip: '31.56.78.234', time: '2026-02-09 08:00:00', protocol: 'V2Ray', duration: '12h 00m' }, { ip: '31.56.79.100', time: '2026-02-08 09:00:00', protocol: 'OpenVPN', duration: '10h 30m' }] },
    ] as Client[],
    coreConfigs: {
        candyconnect: { panel_domain: 'vpn.candyconnect.io', ssl_enabled: true, ssl_cert_path: '/etc/ssl/certs/candyconnect.pem', ssl_key_path: '/etc/ssl/private/candyconnect.key', max_clients: 500, log_level: 'info', auto_backup: true, backup_interval: 24, api_enabled: true, api_port: 8444 },
        wireguard: {
            listen_port: 51820, dns: '1.1.1.1, 8.8.8.8', address: '10.66.66.1/24',
            private_key: 'YHR0fH8kN3qFbGx1T2VzXzRfZG9udF9sb29rXw==', public_key: 'aGVsbG9fd2FzdGVsYW5kX3dhbmRlcmVyXzQy',
            mtu: 1420, post_up: 'iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE',
            post_down: 'iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE',
        },
        v2ray: { config_json: '{\n  "log": { "loglevel": "warning" },\n  "inbounds": [\n    { "tag": "vless-ws", "port": 443, "protocol": "vless" },\n    { "tag": "vmess-ws", "port": 8443, "protocol": "vmess" },\n    { "tag": "trojan-tcp", "port": 2083, "protocol": "trojan" },\n    { "tag": "shadowsocks", "port": 1080, "protocol": "shadowsocks" },\n    { "tag": "vless-grpc", "port": 2053, "protocol": "vless" }\n  ],\n  "outbounds": [\n    { "tag": "direct", "protocol": "freedom" },\n    { "tag": "blocked", "protocol": "blackhole" }\n  ]\n}' },
        openvpn: { port: 1194, protocol: 'udp', device: 'tun', cipher: 'AES-256-GCM', auth: 'SHA512', dh: 'none', tls_crypt: true, dns1: '1.1.1.1', dns2: '8.8.8.8', subnet: '10.8.0.0/24', max_clients: 100, keepalive: '10 120', comp_lzo: false },
        ikev2: { port: 500, nat_port: 4500, cipher: 'aes256-sha256-modp2048', lifetime: '24h', margintime: '3h', dns: '1.1.1.1', subnet: '10.10.0.0/24', cert_validity: 3650 },
        l2tp: { port: 1701, ipsec_port: 500, psk: 'CandyConnect_L2TP_PSK_2026', local_ip: '10.20.0.1', remote_range: '10.20.0.10-10.20.0.250', dns: '1.1.1.1', mtu: 1400, mru: 1400 },
        dnstt: { listen_port: 5300, domain: 'dns.candyconnect.io', public_key: '', tunnel_mode: 'ssh', mtu: 1232 },
        slipstream: { port: 8388, method: 'aes-256-cfb', obfs: 'tls', obfs_host: 'www.microsoft.com', fast_open: true, no_delay: true, udp_relay: true, timeout: 300 },
        trusttunnel: { port: 9443, protocol: 'https', camouflage: 'cloudflare', fragment_size: 100, fragment_interval: 50, sni: 'www.google.com', alpn: 'h2,http/1.1', padding: true, timeout: 60 },
    } as CoreConfigs,
    generateId: () => 'c' + Math.random().toString(36).substr(2, 9),
    generatePassword: () => {
        const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%';
        return Array.from({ length: 12 }, () => c[Math.floor(Math.random() * c.length)]).join('');
    },
};

// Utility functions
export const formatUptime = (s: number) => {
    if (s <= 0) return 'Offline';
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
};

export const formatTraffic = (gb: number) => gb >= 1024 ? (gb / 1024).toFixed(2) + ' TB' : gb >= 1 ? gb.toFixed(1) + ' GB' : (gb * 1024).toFixed(0) + ' MB';

export const formatClientTraffic = (usedGB: number, limit: { value: number; unit: string }) =>
    limit.unit === 'MB' ? `${(usedGB * 1024).toFixed(0)} / ${limit.value} MB` : `${usedGB.toFixed(1)} / ${limit.value} GB`;

export const getTrafficPercent = (usedGB: number, limit: { value: number; unit: string }) =>
    limit.unit === 'MB' ? ((usedGB * 1024) / limit.value) * 100 : (usedGB / limit.value) * 100;

export const formatTimeLimit = (client: Client) => {
    const r = client.timeLimit.value - client.timeUsed;
    return client.timeLimit.onHold ? (
        <span className="flex items-center gap-1.5 align-middle">
            <Pause size={12} className="inline-block" />
            <span>On Hold ({client.timeLimit.value} {client.timeLimit.mode})</span>
        </span>
    ) : (
        `${r} ${client.timeLimit.mode} left`
    );
};

export const protocolName = (id: string) => ({ v2ray: 'V2Ray', wireguard: 'WireGuard', openvpn: 'OpenVPN', ikev2: 'IKEv2', l2tp: 'L2TP', dnstt: 'DNSTT', slipstream: 'SlipStream', trusttunnel: 'TrustTunnel' }[id] || id);
export const protocolIcon = (id: string) => {
    const p = { size: 12, strokeWidth: 2.5 };
    switch (id) {
        case 'v2ray': return <Zap {...p} />;
        case 'wireguard': return <Shield {...p} />;
        case 'openvpn': return <Lock {...p} />;
        case 'ikev2': return <KeyRound {...p} />;
        case 'l2tp': return <Radio {...p} />;
        case 'dnstt': return <Globe {...p} />;
        case 'slipstream': return <Wind {...p} />;
        case 'trusttunnel': return <Castle {...p} />;
        default: return <Circle {...p} />;
    }
};

export const generateUUID = (str: string) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) hash = ((hash << 5) - hash) + str.charCodeAt(i);
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return `${hex.substr(0, 8)}-${hex.substr(0, 4)}-4${hex.substr(1, 3)}-a${hex.substr(4, 3)}-${hex.padEnd(12, '0').substr(0, 12)}`;
};
