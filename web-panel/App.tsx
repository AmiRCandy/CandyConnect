import React, { useState, useEffect } from 'react';
import { Sun, Moon } from 'lucide-react';
import GreenCandy from './assets/green-candy.svg';
import RedCandy from './assets/red-candy.svg';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import ClientsPage from './pages/ClientsPage';
import LogsPage from './pages/LogsPage';
import CoreConfigsPage from './pages/CoreConfigsPage';
import PanelConfigsPage from './pages/PanelConfigsPage';
import Sidebar from './components/Sidebar';
import { NotificationProvider, useNotify } from './components/Notification';

const AppContent: React.FC = () => {
  const [isAuth, setIsAuth] = useState(() => sessionStorage.getItem('cc_auth') === 'true');
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [dark, setDark] = useState(() => localStorage.getItem('cc-theme') === 'dark');
  const [showGreen, setShowGreen] = useState(true);
  const { notify } = useNotify();

  useEffect(() => {
    (window as any).ccNavigate = (page: string) => setCurrentPage(page);
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('cc-theme', dark ? 'dark' : 'light');
  }, [dark]);

  useEffect(() => {
    const interval = setInterval(() => setShowGreen(p => !p), 2000);
    return () => clearInterval(interval);
  }, []);

  const handleLogin = () => { setIsAuth(true); notify('Welcome back, Overseer', 'success'); };
  const handleLogout = () => {
    sessionStorage.removeItem('cc_auth');
    sessionStorage.removeItem('cc_token');
    setIsAuth(false);
    setCurrentPage('dashboard');
    notify('Logged out', 'info');
  };

  if (!isAuth) return <LoginPage onLogin={handleLogin} />;

  const renderPage = () => {
    switch (currentPage) {
      case 'clients': return <ClientsPage />;
      case 'logs': return <LogsPage onBack={() => setCurrentPage('dashboard')} />;
      case 'coreconfigs': return <CoreConfigsPage />;
      case 'panelconfigs': return <PanelConfigsPage />;
      default: return <DashboardPage />;
    }
  };

  return (
    <div className="min-h-screen bg-[#FBEFE0] dark:bg-slate-900 transition-colors">
      <Sidebar
        currentPage={currentPage}
        onNavigate={setCurrentPage}
        onLogout={handleLogout}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main */}
      <div className="lg:ml-64 min-h-screen">
        {/* Top Bar */}
        <header className="sticky top-0 z-30 bg-[#FBEFE0]/80 dark:bg-slate-900/80 backdrop-blur-lg border-b border-slate-200/50 dark:border-slate-700/50 px-4 py-3 flex items-center justify-between">
          <button onClick={() => setSidebarOpen(true)} className="lg:hidden text-slate-600 dark:text-slate-400 p-1.5 rounded-lg hover:bg-white dark:hover:bg-slate-800 transition-colors">
            <div className="relative w-7 h-7 flex items-center justify-center">
              <img src={GreenCandy} alt="Menu" className={`absolute w-full h-full object-contain transition-all duration-700 ease-in-out ${showGreen ? 'opacity-100 rotate-0 scale-100' : 'opacity-0 rotate-180 scale-50'}`} />
              <img src={RedCandy} alt="Menu" className={`absolute w-full h-full object-contain transition-all duration-700 ease-in-out ${!showGreen ? 'opacity-100 rotate-0 scale-100' : 'opacity-0 -rotate-180 scale-50'}`} />
            </div>
          </button>
          <div className="flex items-center gap-3">
            <button onClick={() => setDark(!dark)} className="text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-2 rounded-lg hover:bg-white dark:hover:bg-slate-800 transition-colors">
              {dark ? <Sun className="w-5 h-5 text-orange-500" /> : <Moon className="w-5 h-5 text-slate-400" />}
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="p-4 sm:p-6 max-w-7xl mx-auto">
          {renderPage()}
        </main>
      </div>
    </div>
  );
};

const App: React.FC = () => (
  <NotificationProvider>
    <AppContent />
  </NotificationProvider>
);

export default App;
