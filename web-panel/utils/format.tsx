/**
 * CandyConnect - Formatting Utilities
 */
import React from 'react';
import { Zap, Shield, Lock, KeyRound, Radio, Globe, Wind, Castle, Circle, Pause } from 'lucide-react';

export const formatUptime = (s: number) => {
    if (!s || s <= 0) return 'Offline';
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
};

export const formatTraffic = (value: number) => {
    const gb = Number(value) || 0;
    return gb >= 1024 ? (gb / 1024).toFixed(2) + ' TB' : gb >= 1 ? gb.toFixed(1) + ' GB' : (gb * 1024).toFixed(0) + ' MB';
};

export const formatClientTraffic = (usedGB: number, limit: { value: number; unit: string }) => {
    const used = Number(usedGB) || 0;
    const lim = Number(limit?.value) || 0;
    return limit?.unit === 'MB' ? `${(used * 1024).toFixed(0)} / ${lim} MB` : `${used.toFixed(1)} / ${lim} GB`;
};

export const getTrafficPercent = (usedGB: number, limit: { value: number; unit: string }) => {
    const used = Number(usedGB) || 0;
    const lim = Number(limit?.value) || 0;
    if (lim <= 0) return 0;
    return limit.unit === 'MB' ? ((used * 1024) / lim) * 100 : (used / lim) * 100;
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


// Server emits both "WARN" and "WARNING"; normalize for display/filtering.
export const normLevel = (level?: string) => {
    const l = (level || 'INFO').toUpperCase();
    return l === 'WARNING' ? 'WARN' : l;
};

// "YYYY-MM-DD HH:MM:SS" -> "HH:MM:SS" (falls back to the raw value)
export const logTime = (time?: string) => (time || '').split(' ')[1] || time || '';
