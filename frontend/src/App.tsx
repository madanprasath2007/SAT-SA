import React, { useEffect, useState, useCallback } from 'react';
import {
  LayoutDashboard, AlertTriangle, Shield, Database,
  Activity, Settings, ChevronRight, RefreshCw, Play,
  Zap, Eye, TrendingDown, BarChart3
} from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';
import {
  seedDatabase, runEngines, getKPIs, getMTTR, getHeatmap,
  getTimeline, getFeed, getFindings, getSummary, getStatus
} from './api';

// ── Types ──────────────────────────────────────────────────────────────────
interface KPIs {
  total_alerts: number; total_findings: number;
  critical_findings: number; high_findings: number;
  cse_count: number; avg_critical_mttr_minutes: number;
}
interface Finding {
  finding_id: string; cse_id: string; engine: string;
  finding_type: string; severity: string; description: string;
  score: number; created_at: string;
}
interface Toast { id: number; type: 'success' | 'error' | 'info'; msg: string; }

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e',
};
const ENGINE_COLORS: Record<string, string> = {
  ExecutionGapEngine: '#f97316', NegativeSpaceEngine: '#8b5cf6',
};

function SeverityBadge({ severity }: { severity: string }) {
  const cls = severity.toLowerCase();
  return <span className={`badge badge-${cls}`}>{severity}</span>;
}

function LoadingSpinner({ label = 'Loading...' }) {
  return (
    <div className="loading-spinner">
      <div className="spinner" />
      <span>{label}</span>
    </div>
  );
}

// ── Toast System ────────────────────────────────────────────────────────────
function ToastContainer({ toasts, onRemove }: { toasts: Toast[]; onRemove: (id: number) => void }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`} onClick={() => onRemove(t.id)}>
          {t.type === 'success' ? '✓' : t.type === 'error' ? '✗' : 'ℹ'} {t.msg}
        </div>
      ))}
    </div>
  );
}

// ── KPI Card ─────────────────────────────────────────────────────────────────
function KPICard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color: string }) {
  return (
    <div className={`kpi-card ${color}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

// ── Overview Page ─────────────────────────────────────────────────────────────
function OverviewPage({ kpis, timeline, feed, summary, loading }:
  { kpis: KPIs | null; timeline: any[]; feed: Finding[]; summary: any; loading: boolean }) {
  if (loading) return <LoadingSpinner label="Loading dashboard…" />;
  if (!kpis) return <div className="empty-state"><Shield size={40} /><p>No data. Seed the database first.</p></div>;

  // Prepare timeline data
  const timelineMap: Record<string, any> = {};
  timeline.forEach(row => {
    const d = String(row.day).slice(0, 10);
    if (!timelineMap[d]) timelineMap[d] = { day: d };
    timelineMap[d][row.severity] = (timelineMap[d][row.severity] || 0) + row.count;
  });
  const timelineData = Object.values(timelineMap).slice(-14);

  const pieData = summary?.by_engine?.map((e: any) => ({ name: e.engine.replace('Engine', ''), value: e.count })) || [];

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Supervisory Overview</div>
          <div className="page-subtitle">Real-time SOC audit posture across all CSEs</div>
        </div>
      </div>

      <div className="kpi-grid">
        <KPICard label="Total Alerts" value={kpis.total_alerts.toLocaleString()} sub="Last 30 days" color="blue" />
        <KPICard label="Critical Findings" value={kpis.critical_findings} sub="Require immediate attention" color="red" />
        <KPICard label="High Findings" value={kpis.high_findings} sub="Elevated risk" color="amber" />
        <KPICard label="Total Findings" value={kpis.total_findings} sub="All engines" color="purple" />
        <KPICard label="CSEs Monitored" value={kpis.cse_count} sub="Active entities" color="cyan" />
        <KPICard label="Avg MTTR (Critical)" value={`${kpis.avg_critical_mttr_minutes}m`} sub="Mean time to resolve" color="green" />
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Activity size={14} /> Alert Volume (14 days)</span>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={timelineData}>
                <defs>
                  {SEV_ORDER.map(s => (
                    <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor={SEV_COLORS[s]} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={SEV_COLORS[s]} stopOpacity={0.0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d47" />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#475569' }} />
                <YAxis tick={{ fontSize: 10, fill: '#475569' }} />
                <Tooltip contentStyle={{ background: '#131c30', border: '1px solid #1e2d47', borderRadius: '8px', fontSize: '12px' }} />
                {SEV_ORDER.map(s => (
                  <Area key={s} type="monotone" dataKey={s} stackId="1"
                    stroke={SEV_COLORS[s]} fill={`url(#grad-${s})`} strokeWidth={1.5} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title"><BarChart3 size={14} /> Findings by Engine</span>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                  dataKey="value" nameKey="name" paddingAngle={3}>
                  {pieData.map((entry: any, i: number) => (
                    <Cell key={i} fill={Object.values(ENGINE_COLORS)[i % 2] as string} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#131c30', border: '1px solid #1e2d47', borderRadius: '8px', fontSize: '12px' }} />
                <Legend wrapperStyle={{ fontSize: '12px', color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title"><Zap size={14} /> Live Findings Feed</span>
          <span style={{ fontSize: '11px', color: '#475569' }}>Latest {feed.length} findings</span>
        </div>
        <div className="card-body" style={{ padding: '0 18px' }}>
          {feed.length === 0
            ? <div className="empty-state"><p>No findings yet. Run the analytics engines.</p></div>
            : feed.map(f => (
              <div key={f.finding_id} className="finding-item">
                <div className={`finding-icon ${f.engine === 'ExecutionGapEngine' ? 'eg' : 'ns'}`}>
                  {f.engine === 'ExecutionGapEngine' ? '⚡' : '👁'}
                </div>
                <div className="finding-body">
                  <div className="finding-type">{f.finding_type}</div>
                  <div className="finding-desc">{f.description}</div>
                  <div className="finding-meta">
                    <span className="finding-cse">{f.cse_id}</span>
                    <SeverityBadge severity={f.severity} />
                    <span className="finding-time">{new Date(f.created_at).toLocaleString()}</span>
                  </div>
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <span style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace' }}>
                    {typeof f.score === 'number' ? f.score.toFixed(3) : '—'}
                  </span>
                </div>
              </div>
            ))}
        </div>
      </div>
    </>
  );
}

// ── Findings Page ─────────────────────────────────────────────────────────────
function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [sevFilter, setSevFilter] = useState('');
  const [engineFilter, setEngineFilter] = useState('');

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string> = {};
    if (sevFilter) params.severity = sevFilter;
    if (engineFilter) params.engine = engineFilter;
    getFindings(params)
      .then((r: any) => setFindings(r.data))
      .finally(() => setLoading(false));
  }, [sevFilter, engineFilter]);

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Findings Explorer</div>
          <div className="page-subtitle">All detected execution gaps & negative space anomalies</div>
        </div>
      </div>
      <div className="card">
        <div className="card-header">
          <span className="card-title"><AlertTriangle size={14} /> Findings ({findings.length})</span>
          <div className="filter-row">
            <select className="filter-select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
              <option value="">All Severities</option>
              {SEV_ORDER.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="filter-select" value={engineFilter} onChange={e => setEngineFilter(e.target.value)}>
              <option value="">All Engines</option>
              <option value="ExecutionGapEngine">Execution Gap</option>
              <option value="NegativeSpaceEngine">Negative Space</option>
            </select>
          </div>
        </div>
        {loading
          ? <LoadingSpinner />
          : findings.length === 0
            ? <div className="empty-state"><AlertTriangle size={32} /><p>No findings match filters.</p></div>
            : (
              <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Type</th><th>CSE</th><th>Engine</th>
                      <th>Severity</th><th>Score</th><th>Description</th><th>Detected</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map(f => (
                      <tr key={f.finding_id}>
                        <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          <span style={{ color: '#e2e8f0', fontWeight: 500, fontSize: '12px' }}>{f.finding_type}</span>
                        </td>
                        <td><span className="mono" style={{ color: '#3b82f6' }}>{f.cse_id}</span></td>
                        <td>
                          <span style={{ fontSize: '11px', color: ENGINE_COLORS[f.engine] || '#94a3b8' }}>
                            {f.engine.replace('Engine', '')}
                          </span>
                        </td>
                        <td><SeverityBadge severity={f.severity} /></td>
                        <td><span className="mono">{typeof f.score === 'number' ? f.score.toFixed(3) : '—'}</span></td>
                        <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {f.description}
                        </td>
                        <td><span className="mono" style={{ fontSize: '10px' }}>{new Date(f.created_at).toLocaleString()}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
      </div>
    </>
  );
}

// ── Analytics Page ─────────────────────────────────────────────────────────────
function AnalyticsPage({ mttr }: { mttr: any[] }) {
  const catMap: Record<string, any> = {};
  mttr.forEach(row => {
    if (!catMap[row.category]) catMap[row.category] = { category: row.category };
    catMap[row.category][row.severity + '_avg'] = row.avg_mttr_min;
  });
  const chartData = Object.values(catMap);

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">MTTR Analytics</div>
          <div className="page-subtitle">Mean time to resolve by category and severity</div>
        </div>
      </div>
      <div className="card">
        <div className="card-header">
          <span className="card-title"><TrendingDown size={14} /> MTTR by Alert Category (minutes)</span>
        </div>
        <div className="card-body">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={chartData} layout="vertical" margin={{ left: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d47" />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#475569' }} />
              <YAxis type="category" dataKey="category" tick={{ fontSize: 10, fill: '#94a3b8' }} width={130} />
              <Tooltip contentStyle={{ background: '#131c30', border: '1px solid #1e2d47', borderRadius: '8px', fontSize: '12px' }} />
              <Legend wrapperStyle={{ fontSize: '12px', color: '#94a3b8' }} />
              {SEV_ORDER.map(s => (
                <Bar key={s} dataKey={s + '_avg'} name={s} fill={SEV_COLORS[s]} radius={[0, 3, 3, 0]} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </>
  );
}

// ── CSE Heatmap Page ──────────────────────────────────────────────────────────
function HeatmapPage({ heatmap }: { heatmap: any[] }) {
  const cses = [...new Set(heatmap.map(h => h.cse_id))];
  const types = [...new Set(heatmap.map(h => h.finding_type))];
  const lookup: Record<string, number> = {};
  heatmap.forEach(h => { lookup[`${h.cse_id}||${h.finding_type}`] = h.count; });
  const maxCount = Math.max(...heatmap.map(h => h.count), 1);

  function cellColor(count: number) {
    const intensity = count / maxCount;
    if (intensity === 0) return '#1a2540';
    if (intensity < 0.3) return '#1e3a5f';
    if (intensity < 0.6) return '#1d4ed8';
    if (intensity < 0.85) return '#f97316';
    return '#ef4444';
  }

  if (heatmap.length === 0) return (
    <div className="empty-state"><Eye size={32} /><p>Run analytics to generate heatmap data.</p></div>
  );

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">CSE Risk Heatmap</div>
          <div className="page-subtitle">Finding density by CSE and finding type</div>
        </div>
      </div>
      <div className="card">
        <div className="card-header">
          <span className="card-title"><Eye size={14} /> Risk Density Matrix</span>
        </div>
        <div className="card-body" style={{ overflowX: 'auto' }}>
          <table style={{ borderCollapse: 'collapse', minWidth: '100%' }}>
            <thead>
              <tr>
                <th style={{ padding: '8px 12px', textAlign: 'left', fontSize: '11px', color: '#475569' }}>CSE</th>
                {types.map(t => (
                  <th key={t} style={{ padding: '8px 8px', fontSize: '10px', color: '#475569', maxWidth: 100, textAlign: 'center' }}>
                    {t.replace('Execution Gap: ', 'EG: ').replace('Negative Space: ', 'NS: ')}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cses.map(cse => (
                <tr key={cse}>
                  <td style={{ padding: '8px 12px', fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: '#3b82f6', fontWeight: 600 }}>{cse}</td>
                  {types.map(t => {
                    const count = lookup[`${cse}||${t}`] || 0;
                    return (
                      <td key={t} style={{ padding: '4px 8px', textAlign: 'center' }}>
                        <div className="heatmap-cell" style={{
                          background: cellColor(count), color: count > 0 ? '#fff' : '#1e2d47',
                          width: 42, height: 28, margin: '0 auto',
                        }} title={`${cse} — ${t}: ${count}`}>
                          {count || ''}
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage]     = useState('overview');
  const [kpis, setKpis]     = useState<KPIs | null>(null);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [feed, setFeed]     = useState<Finding[]>([]);
  const [mttr, setMttr]     = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = React.useRef(0);

  const toast = (type: Toast['type'], msg: string) => {
    const id = ++toastId.current;
    setToasts(t => [...t, { id, type, msg }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4000);
  };

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [k, tl, f, m, h, s, st] = await Promise.all([
        getKPIs(), getTimeline(), getFeed(), getMTTR(), getHeatmap(), getSummary(), getStatus(),
      ]);
      setKpis(k.data); setTimeline(tl.data); setFeed(f.data);
      setMttr(m.data); setHeatmap(h.data); setSummary(s.data); setStatus(st.data);
    } catch {
      toast('error', 'Failed to load dashboard data. Is the backend running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const handleSeed = async () => {
    setSeeding(true);
    try {
      const r = await seedDatabase();
      toast('success', `Seeded ${r.data.alerts_inserted} alerts into DuckDB`);
      await loadAll();
    } catch { toast('error', 'Seeding failed'); }
    finally { setSeeding(false); }
  };

  const handleRun = async () => {
    setRunning(true);
    try {
      const r = await runEngines();
      toast('success', `Analysis complete — ${r.data.total_findings} findings detected`);
      await loadAll();
    } catch { toast('error', 'Engine run failed'); }
    finally { setRunning(false); }
  };

  const navItems = [
    { id: 'overview',  label: 'Overview',       icon: <LayoutDashboard size={16} /> },
    { id: 'findings',  label: 'Findings',        icon: <AlertTriangle size={16} /> },
    { id: 'analytics', label: 'MTTR Analytics',  icon: <Activity size={16} /> },
    { id: 'heatmap',   label: 'CSE Heatmap',     icon: <Eye size={16} /> },
  ];

  return (
    <div className="app-shell">
      {/* Top Bar */}
      <header className="topbar">
        <div className="topbar-logo">
          <Shield size={20} />
          SAT-SA
          <span className="topbar-logo-badge">NCIIPC</span>
        </div>
        <span style={{ fontSize: '12px', color: '#475569', marginLeft: 4 }}>
          Supervisory Analytics Tool for SOC Assessment
        </span>
        <div className="topbar-spacer" />
        {status && (
          <span style={{ fontSize: '11px', color: '#475569', fontFamily: 'JetBrains Mono, monospace' }}>
            {status.alerts} alerts · {status.findings} findings
          </span>
        )}
        <div className="topbar-status">
          <div className="status-dot" />
          Air-Gapped Mode
        </div>
        <button className="btn btn-secondary" onClick={handleSeed} disabled={seeding}>
          <Database size={13} />{seeding ? 'Seeding…' : 'Seed Data'}
        </button>
        <button className="btn btn-primary" onClick={handleRun} disabled={running}>
          <Play size={13} />{running ? 'Running…' : 'Run Engines'}
        </button>
        <button className="btn btn-secondary" onClick={loadAll} disabled={loading}>
          <RefreshCw size={13} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
        </button>
      </header>

      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-section-label">Navigation</div>
        {navItems.map(n => (
          <div key={n.id} className={`nav-item ${page === n.id ? 'active' : ''}`} onClick={() => setPage(n.id)}>
            {n.icon}
            {n.label}
            {page === n.id && <ChevronRight size={12} style={{ marginLeft: 'auto' }} />}
          </div>
        ))}
        <div className="sidebar-section-label" style={{ marginTop: 'auto' }}>System</div>
        <div className="nav-item"><Settings size={16} />Settings</div>
      </nav>

      {/* Main */}
      <main className="main-content">
        {page === 'overview'  && <OverviewPage kpis={kpis} timeline={timeline} feed={feed} summary={summary} loading={loading} />}
        {page === 'findings'  && <FindingsPage />}
        {page === 'analytics' && <AnalyticsPage mttr={mttr} />}
        {page === 'heatmap'   && <HeatmapPage heatmap={heatmap} />}
      </main>

      <ToastContainer toasts={toasts} onRemove={id => setToasts(t => t.filter(x => x.id !== id))} />
    </div>
  );
}
