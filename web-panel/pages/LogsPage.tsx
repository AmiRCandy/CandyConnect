import React, { useState, useEffect } from 'react';
import { useLanguage } from '../contexts/LanguageContext';
import { getLogs } from '../services/api';
import type { LogEntry } from '../services/api';
import {
    ArrowLeft,
    Search,
    RotateCw,
    Filter,
    FileText,
    AlertCircle,
    Clock,
    ExternalLink
} from 'lucide-react';
import { Card, BtnSecondary } from '../components/UI';

const LogsPage: React.FC<{ onBack: () => void }> = ({ onBack }) => {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [limit, setLimit] = useState(100);
    const [filter, setFilter] = useState('');
    const [levelFilter, setLevelFilter] = useState('ALL');

    const fetchLogs = async () => {
        setLoading(true);
        try {
            const data = await getLogs(limit);
            setLogs(data);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchLogs();
    }, [limit]);

    const filteredLogs = logs.filter(log => {
        const matchesSearch = log.message.toLowerCase().includes(filter.toLowerCase()) ||
            log.source.toLowerCase().includes(filter.toLowerCase());
        const matchesLevel = levelFilter === 'ALL' || log.level === levelFilter;
        return matchesSearch && matchesLevel;
    });

    const logLevelColor = (level: string) => {
        switch (level) {
            case 'ERROR': return 'text-red-500 bg-red-500/10 border-red-500/20';
            case 'WARN': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
            case 'INFO': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
            default: return 'text-slate-500 bg-slate-500/10 border-slate-500/20';
        }
    };

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <button
                        onClick={onBack}
                        className="p-2 rounded-xl bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                    >
                        <ArrowLeft className="w-5 h-5 text-slate-600 dark:text-slate-400" />
                    </button>
                    <div>
                        <h1 className="text-2xl font-black text-slate-800 dark:text-slate-200 tracking-tight">System Logs</h1>
                        <p className="text-sm text-slate-500 dark:text-slate-400 font-medium">Monitor system events and protocol status</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <BtnSecondary onClick={fetchLogs} disabled={loading} className="gap-2">
                        <RotateCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                        Refresh
                    </BtnSecondary>
                </div>
            </div>

            <Card className="p-0 overflow-hidden border-none shadow-xl shadow-slate-200/50 dark:shadow-slate-900/50">
                <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700 flex flex-wrap gap-4 items-center justify-between">
                    <div className="flex flex-1 min-w-[200px] relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input
                            type="text"
                            placeholder="Search logs..."
                            value={filter}
                            onChange={(e) => setFilter(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-sm outline-none focus:ring-2 focus:ring-orange-500/20 transition-all font-medium"
                        />
                    </div>

                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-3 py-1.5 shadow-sm">
                            <Filter className="w-4 h-4 text-slate-400" />
                            <select
                                value={levelFilter}
                                onChange={(e) => setLevelFilter(e.target.value)}
                                className="bg-transparent text-sm font-bold outline-none cursor-pointer pr-2"
                            >
                                <option value="ALL">All Levels</option>
                                <option value="INFO">Info</option>
                                <option value="WARN">Warn</option>
                                <option value="ERROR">Error</option>
                            </select>
                        </div>

                        <div className="flex items-center gap-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-3 py-1.5 shadow-sm">
                            <Clock className="w-4 h-4 text-slate-400" />
                            <select
                                value={limit}
                                onChange={(e) => setLimit(Number(e.target.value))}
                                className="bg-transparent text-sm font-bold outline-none cursor-pointer pr-2"
                            >
                                <option value={100}>100 Entries</option>
                                <option value={500}>500 Entries</option>
                                <option value={1000}>1000 Entries</option>
                                <option value={5000}>5000 Entries</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div className="max-h-[60vh] overflow-y-auto custom-scrollbar bg-white dark:bg-slate-900/50">
                    <table className="w-full text-left border-collapse">
                        <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800 text-[10px] font-black uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 z-10">
                            <tr>
                                <th className="px-5 py-3 w-40">Time</th>
                                <th className="px-5 py-3 w-24">Level</th>
                                <th className="px-5 py-3 w-32">Source</th>
                                <th className="px-5 py-3 text-center">Message</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                            {loading && logs.length === 0 ? (
                                <tr>
                                    <td colSpan={4} className="py-20 text-center">
                                        <RotateCw className="w-8 h-8 animate-spin text-orange-500 mx-auto opacity-50" />
                                    </td>
                                </tr>
                            ) : filteredLogs.length === 0 ? (
                                <tr>
                                    <td colSpan={4} className="py-20 text-center text-slate-500 font-medium">No logs matched your filters</td>
                                </tr>
                            ) : (
                                filteredLogs.map((log, i) => (
                                    <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors group">
                                        <td className="px-5 py-3 font-mono text-[10px] text-slate-400 dark:text-slate-500 whitespace-nowrap">
                                            {log.time}
                                        </td>
                                        <td className="px-5 py-3">
                                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-black border ${logLevelColor(log.level)}`}>
                                                {log.level}
                                            </span>
                                        </td>
                                        <td className="px-5 py-3">
                                            <span className="font-bold text-xs text-orange-500 dark:text-orange-400">{log.source}</span>
                                        </td>
                                        <td className="px-5 py-3 text-sm text-slate-600 dark:text-slate-300 font-medium break-all">
                                            {log.message}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>

                <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 flex justify-between items-center text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest">
                    <span>Showing {filteredLogs.length} of {logs.length} fetched entries</span>
                    <span className="flex items-center gap-2">
                        <AlertCircle className="w-3 h-3" />
                        Logs are stored in volatile Redis memory
                    </span>
                </div>
            </Card>
        </div>
    );
};

export default LogsPage;
