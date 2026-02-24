/**
 * CandyConnect - Formatting Utilities
 */
import React from 'react';
import { Zap, Shield, Lock, KeyRound, Radio, Globe, Wind, Castle, Circle, Pause } from 'lucide-react';

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

export const protocolName = (id: string) => ({ v2ray: 'V2Ray', wireguard: 'WireGuard', openvpn: 'OpenVPN', ikev2: 'IKEv2', l2tp: 'L2TP', amnezia: 'Amnezia', slipstream: 'SlipStream', trusttunnel: 'TrustTunnel' }[id] || id);

export const protocolIcon = (id: string) => {
    const p = { size: 12, strokeWidth: 2.5 };
    switch (id) {
        case 'v2ray': return <Zap {...p} />;
        case 'wireguard': return <Shield {...p} />;
        case 'openvpn': return <Lock {...p} />;
        case 'ikev2': return <KeyRound {...p} />;
        case 'l2tp': return <Radio {...p} />;
        case 'amnezia': return <Globe {...p} />;
        case 'slipstream': return <Wind {...p} />;
        case 'trusttunnel': return <Castle {...p} />;
        default: return <Circle {...p} />;
    }
};

