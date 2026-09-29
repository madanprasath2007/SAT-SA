import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  ShieldAlert,
  Building2,
  Flame,
  FileSearch,
  BarChart3,
  Search,
  UploadCloud,
  Sliders,
  Sun,
  Moon,
  ShieldCheck,
  Radio,
  Terminal,
  Server,
  CheckSquare,
  RefreshCw,
  Lock,
  DownloadCloud,
  UserCheck,
} from 'lucide-react';

export const Layout: React.FC = () => {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [currentTime, setCurrentTime] = useState(new Date().toUTCString());
  const location = useLocation();

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    if (next === 'light') {
      document.documentElement.classList.add('light-theme');
    } else {
      document.documentElement.classList.remove('light-theme');
    }
  };

  const [currentRole, setCurrentRole] = useState<'Admin' | 'Supervisor' | 'Analyst'>(
    (localStorage.getItem('satsa_role') as any) || 'Supervisor'
  );

  const handleRoleSelect = async (role: 'Admin' | 'Supervisor' | 'Analyst') => {
    setCurrentRole(role);
    localStorage.setItem('satsa_role', role);
    try {
      const { switchRole } = await import('../api');
      const res = await switchRole(role);
      localStorage.setItem('satsa_token', res.data.access_token);
    } catch (e) {
      console.warn('Role switch fallback active');
    }
  };

  const navItems = [
    { to: '/', label: 'Overall Risk View', icon: ShieldAlert, badge: 'Rollup' },
    { to: '/cse-analysis', label: 'CSE-wise Analysis', icon: Building2 },
    { to: '/attack-path', label: 'Attack Path Graph', icon: Flame, badge: 'S1-S4' },
    { to: '/findings', label: 'Key Findings', icon: Search },
    { to: '/peer-comparison', label: 'Peer Benchmarks', icon: BarChart3 },
    { to: '/drilldown', label: 'Record Drill-down', icon: FileSearch },
    { to: '/reviews', label: 'Review Queue', icon: CheckSquare, badge: 'Adjudicate' },
    { to: '/feedback', label: 'Feedback Loop', icon: RefreshCw, badge: 'Tuning' },
    { to: '/export', label: 'Reports & Export', icon: DownloadCloud, badge: 'PDF' },
    { to: '/admin', label: 'Admin & Audit', icon: Lock, badge: 'Audit' },
    { to: '/upload', label: 'Upload Telemetry', icon: UploadCloud, group: 'Ingestion' },
    { to: '/normalization', label: 'Normalization Data', icon: Sliders, group: 'Ingestion' },
  ];

  return (
    <div className={`min-h-screen flex bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-white ${theme}`}>
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0 z-20">
        <div>
          {/* Brand Header */}
          <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-600/10">
              <ShieldCheck size={20} />
            </div>
            <div>
              <div className="font-extrabold text-sm tracking-wider text-slate-100 font-mono flex items-center gap-1.5">
                <span>SAT-SA</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-400 font-normal">
                  v3.0
                </span>
              </div>
              <div className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">
                Supervisory SOC Tool
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="p-3 space-y-1">
            <div className="px-3 pt-2 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
              Supervisory Analytics
            </div>

            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive =
                item.to === '/'
                  ? location.pathname === '/' || location.pathname === '/overall-risk'
                  : location.pathname.startsWith(item.to);

              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={`flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30 font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon size={16} className={isActive ? 'text-cyan-400' : 'text-slate-400'} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                      {item.badge}
                    </span>
                  )}
                </NavLink>
              );
            })}
          </div>
        </div>

        {/* Sidebar Footer / System Badge */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 text-xs space-y-2">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <Radio size={12} className="animate-pulse" />
              <span>Offline / Air-Gapped</span>
            </span>
            <span className="text-slate-500 text-[10px]">DuckDB Local</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono line-clamp-1">
            Compliant: NCIIPC & NTRO
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header Bar */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/90 backdrop-blur-md px-6 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span className="text-xs font-mono text-slate-300">
              National Critical Infrastructure Cyber Telemetry Console
            </span>
          </div>

          <div className="flex items-center gap-4">
            {/* RBAC Role Switcher */}
            <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-[11px] font-mono">
              <span className="px-2 text-slate-500 hidden sm:inline">Role:</span>
              <button
                onClick={() => handleRoleSelect('Admin')}
                className={`px-2 py-0.5 rounded transition-all font-semibold ${
                  currentRole === 'Admin'
                    ? 'bg-purple-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Admin
              </button>
              <button
                onClick={() => handleRoleSelect('Supervisor')}
                className={`px-2 py-0.5 rounded transition-all font-semibold ${
                  currentRole === 'Supervisor'
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Supervisor
              </button>
              <button
                onClick={() => handleRoleSelect('Analyst')}
                className={`px-2 py-0.5 rounded transition-all font-semibold ${
                  currentRole === 'Analyst'
                    ? 'bg-slate-700 text-slate-100 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Analyst
              </button>
            </div>

            {/* UTC Clock */}
            <div className="text-xs font-mono text-slate-400 hidden md:block">
              {currentTime}
            </div>

            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              title="Toggle Dark / Light Theme"
            >
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
          </div>
        </header>

        {/* Body Container */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
          <div className="max-w-7xl mx-auto">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};
