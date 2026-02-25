import React, { useState, useEffect } from 'react';
import { LayoutDashboard, Users, Settings, Wrench, LogOut, Activity, Network, ExternalLink } from 'lucide-react';
import { getPanel, type PanelData } from '../services/api';
import GreenCandy from '../assets/green-candy.svg';
import RedCandy from '../assets/red-candy.svg';

interface SidebarProps {
  currentPage: string;
  onNavigate: (page: string) => void;
  onLogout: () => void;
  open: boolean;
  onClose: () => void;
}

const pages = [
  { id: 'dashboard', title: 'Dashboard', icon: LayoutDashboard },
  { id: 'clients', title: 'Clients', icon: Users },
  { id: 'tunnels', title: 'Tunnels', icon: Network },
  { id: 'logs', title: 'System Logs', icon: Activity },
  { id: 'coreconfigs', title: 'Core Configs', icon: Settings },
  { id: 'panelconfigs', title: 'Panel Configs', icon: Wrench },
];

const Sidebar: React.FC<SidebarProps> = ({ currentPage, onNavigate, onLogout, open, onClose }) => {
  const [showGreen, setShowGreen] = useState(true);
  const [panelData, setPanelData] = useState<PanelData | null>(null);

  useEffect(() => {
    const interval = setInterval(() => setShowGreen(prev => !prev), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    getPanel().then(setPanelData).catch(() => { });
  }, []);

  const version = panelData?.config.version || '1.4.2';
  const hostname = panelData?.server.hostname || '';
  const adminUser = panelData?.admin_username || 'admin';

  const userPortalUrl = `${window.location.origin}${window.location.pathname.replace(/\/?$/, '/user')}`;

  return (
    <>
      {open && <div className="fixed inset-0 bg-black/40 z-40 lg:hidden" onClick={onClose} />}

      <nav className={`fixed top-0 left-0 h-full w-64 bg-white dark:bg-slate-800 border-r border-slate-200/50 dark:border-slate-700/50 z-50 flex flex-col transition-transform duration-300 ${open ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0 shadow-xl lg:shadow-none`}>
        {/* Header */}
        <div className="px-5 py-5 border-b border-slate-200/50 dark:border-slate-700/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br rounded-xl flex items-center justify-center shadow-md shadow-orange-300/30 dark:shadow-orange-900/30">
              <div className="relative w-7 h-7 flex items-center justify-center">
                <img src={GreenCandy} alt="Menu" className={`absolute w-full h-full object-contain transition-all duration-700 ease-in-out ${showGreen ? 'opacity-100 rotate-0 scale-100' : 'opacity-0 rotate-180 scale-50'}`} />
                <img src={RedCandy} alt="Menu" className={`absolute w-full h-full object-contain transition-all duration-700 ease-in-out ${!showGreen ? 'opacity-100 rotate-0 scale-100' : 'opacity-0 -rotate-180 scale-50'}`} />
              </div>
            </div>
            <div>
              <span className="text-lg font-black text-slate-800 dark:text-slate-200 tracking-tight block leading-tight">
                Candy<span className="text-orange-500">Connect</span>
              </span>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-widest font-semibold">
                Panel v{version}
              </span>
            </div>
          </div>
        </div>

        {/* Nav items */}
        <div className="flex-1 py-4 px-3 overflow-y-auto space-y-1">
          {pages.map(p => {
            const Icon = p.icon;
            const active = currentPage === p.id;
            return (
              <button
                key={p.id}
                onClick={() => { onNavigate(p.id); onClose(); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 ${active
                  ? 'bg-orange-500 text-white shadow-md shadow-orange-300/30 dark:shadow-orange-900/30'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700/50 hover:text-slate-800 dark:hover:text-slate-200'
                  }`}
              >
                <Icon className={`w-[18px] h-[18px] ${active ? 'text-white' : 'text-slate-400 dark:text-slate-500'}`} strokeWidth={active ? 2.2 : 1.8} />
                <span className="text-sm font-bold">{p.title}</span>
              </button>
            );
          })}

          {/* User Portal link */}
          <a
            href={userPortalUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700/50 hover:text-slate-800 dark:hover:text-slate-200"
          >
            <ExternalLink className="w-[18px] h-[18px] text-slate-400 dark:text-slate-500" strokeWidth={1.8} />
            <span className="text-sm font-bold">User Portal</span>
          </a>
        </div>

        {/* Footer */}
        <div className="px-4 py-4 border-t border-slate-200/50 dark:border-slate-700/50">
          <div className="flex items-center gap-3 mb-3 px-1">
            <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center">
              <span className="text-xs font-black text-slate-600 dark:text-slate-300">{adminUser.charAt(0).toUpperCase()}</span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-bold text-slate-700 dark:text-slate-300 truncate">{adminUser}</p>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 truncate">{hostname}</p>
            </div>
          </div>
          <button
            onClick={onLogout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-xs font-bold text-red-500 hover:text-red-600 bg-red-50 dark:bg-red-900/10 hover:bg-red-100 dark:hover:bg-red-900/20 border border-red-200/50 dark:border-red-800/30 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" strokeWidth={2.5} />
            Logout
          </button>
        </div>
      </nav>
    </>
  );
};

export default Sidebar;
