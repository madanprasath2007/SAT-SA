import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  Building2,
  TrendingUp,
  Activity,
  ArrowRight,
  Flame,
  Clock,
  Sparkles,
  RefreshCw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Legend,
} from 'recharts';
import { getRiskScores, getKPIs, runAnalytics, RiskScoreData } from '../api';
import { RiskBadge } from '../components/RiskBadge';
import { StatCard } from '../components/StatCard';

export const OverallRiskView: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [riskData, setRiskData] = useState<RiskScoreData[]>([]);
  const [kpis, setKpis] = useState<any>({
    total_alerts: 0,
    total_findings: 0,
    critical_findings: 0,
    high_findings: 0,
    cse_count: 4,
    avg_critical_mttr_minutes: 0,
  });

  const fetchData = async () => {
    try {
      const [riskRes, kpiRes] = await Promise.all([
        getRiskScores(),
        getKPIs(),
      ]);
      setRiskData(riskRes.data?.data || []);
      if (kpiRes.data?.data) {
        setKpis(kpiRes.data.data);
      }
    } catch (err) {
      console.error('Failed to load risk overview:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunAnalytics = async () => {
    setRefreshing(true);
    try {
      await runAnalytics();
      await fetchData();
    } catch (e) {
      console.error(e);
      setRefreshing(false);
    }
  };

  // Prepare chart comparison data
  const comparisonData = riskData.map((d) => ({
    name: d.cse_id,
    sector: d.sector,
    score: d.overall_score,
    critical: d.finding_counts?.critical || 0,
    high: d.finding_counts?.high || 0,
    level: d.risk_level,
  }));

  const getBarColor = (score: number) => {
    if (score >= 75) return '#ef4444';
    if (score >= 50) return '#f97316';
    if (score >= 25) return '#f59e0b';
    return '#3b82f6';
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <ShieldAlert className="text-cyan-400" size={24} />
            National Supervisory Risk Rollup
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Supervisory risk index across all designated Critical Security Entities (CSEs) · NCIIPC / NTRO Standard
          </p>
        </div>

        <button
          onClick={handleRunAnalytics}
          disabled={refreshing}
          className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-600/30 transition-all cursor-pointer"
        >
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
          <span>{refreshing ? 'Evaluating Engines...' : 'Run Supervisory Engines'}</span>
        </button>
      </div>

      {/* KPI Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          title="Monitored Entities"
          value={kpis.cse_count || 4}
          subtitle="Critical Infrastructure Sectors"
          icon={Building2}
          variant="cyan"
        />
        <StatCard
          title="Critical Findings"
          value={kpis.critical_findings || 0}
          subtitle="Requires immediate supervisory action"
          icon={Flame}
          variant="red"
          trend={{ value: 'Active S1-S4', isPositive: false }}
        />
        <StatCard
          title="Total Telemetry Alerts"
          value={kpis.total_alerts || 0}
          subtitle="Processed across ingestion stages"
          icon={Activity}
          variant="blue"
        />
        <StatCard
          title="Avg Critical MTTR"
          value={`${kpis.avg_critical_mttr_minutes || 0}m`}
          subtitle="Sector benchmark average"
          icon={Clock}
          variant="amber"
        />
      </div>

      {/* CSE Cards Grid */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Designated Entities Risk Assessment
          </h2>
          <span className="text-xs text-slate-500 font-mono">
            Click any CSE card to inspect breakdown & attack paths
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {riskData.map((cse) => {
            const isCritical = cse.overall_score >= 75;
            return (
              <div
                key={cse.cse_id}
                onClick={() => navigate(`/cse-analysis?cse_id=${cse.cse_id}`)}
                className={`p-5 rounded-xl border bg-slate-900/80 transition-all duration-200 cursor-pointer flex flex-col justify-between group hover:-translate-y-1 hover:shadow-xl ${
                  isCritical
                    ? 'border-rose-500/40 hover:border-rose-500 shadow-rose-500/5'
                    : 'border-slate-800 hover:border-cyan-500/50 shadow-slate-950/20'
                }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <span className="text-xs font-mono font-bold text-cyan-400">
                        {cse.cse_id}
                      </span>
                      <h3 className="font-bold text-slate-100 text-sm group-hover:text-cyan-300 transition-colors">
                        {cse.cse_name}
                      </h3>
                      <span className="text-[11px] text-slate-400 capitalize">
                        {cse.sector} Sector
                      </span>
                    </div>
                    <RiskBadge level={cse.risk_level} showDot={isCritical} />
                  </div>

                  {/* Score Gauge */}
                  <div className="my-4 p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-center justify-between">
                    <div>
                      <span className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider block">
                        Composite Risk Score
                      </span>
                      <div className="flex items-baseline gap-1 mt-0.5">
                        <span
                          className="text-3xl font-extrabold font-mono"
                          style={{ color: getBarColor(cse.overall_score) }}
                        >
                          {cse.overall_score.toFixed(1)}
                        </span>
                        <span className="text-xs text-slate-500 font-mono">/ 100</span>
                      </div>
                    </div>

                    {/* Mini Sparkline Bar */}
                    <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${Math.min(100, cse.overall_score)}%`,
                          backgroundColor: getBarColor(cse.overall_score),
                        }}
                      />
                    </div>
                  </div>

                  {/* Finding Breakdown by Severity */}
                  <div className="grid grid-cols-4 gap-1.5 text-center text-xs font-mono mb-3">
                    <div className="p-1.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400">
                      <div className="font-bold">{cse.finding_counts?.critical || 0}</div>
                      <div className="text-[9px] uppercase opacity-75">Crit</div>
                    </div>
                    <div className="p-1.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400">
                      <div className="font-bold">{cse.finding_counts?.high || 0}</div>
                      <div className="text-[9px] uppercase opacity-75">High</div>
                    </div>
                    <div className="p-1.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400">
                      <div className="font-bold">{cse.finding_counts?.medium || 0}</div>
                      <div className="text-[9px] uppercase opacity-75">Med</div>
                    </div>
                    <div className="p-1.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">
                      <div className="font-bold">{cse.finding_counts?.low || 0}</div>
                      <div className="text-[9px] uppercase opacity-75">Low</div>
                    </div>
                  </div>

                  {/* Highlight S1 / CTI indicator if CSE-A */}
                  {cse.cse_id === 'CSE-A' && (
                    <div className="mb-3 p-2 rounded bg-rose-950/40 border border-rose-500/30 text-[11px] text-rose-300 flex items-center gap-1.5 font-mono">
                      <Flame size={13} className="text-rose-400 shrink-0" />
                      <span>S1 Attack Traceback & CTI IOC 203.0.113.5 Matched</span>
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-cyan-400 font-medium group-hover:translate-x-0.5 transition-transform">
                  <span>Inspect CSE Findings</span>
                  <ArrowRight size={14} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Comparison Chart & Sector Benchmark Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Composite Score Bar Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/80 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-slate-100 text-sm">
                Cross-Entity Composite Risk Comparison
              </h3>
              <p className="text-xs text-slate-400">
                Normalized 0–100 risk score breakdown across national infrastructure targets
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/20">
              Threshold &gt;= 75 Critical
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={comparisonData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  }}
                  cursor={{ fill: 'rgba(255, 255, 255, 0.05)' }}
                />
                <Bar dataKey="score" name="Composite Score" radius={[6, 6, 0, 0]}>
                  {comparisonData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Supervisory Highlights Card */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2 mb-2">
              <Sparkles size={16} className="text-cyan-400" />
              Supervisory Action Triggers
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Automated high-priority supervisory alerts generated from telemetry deviations:
            </p>

            <div className="space-y-2.5 text-xs">
              <div
                onClick={() => navigate('/attack-path?cse_id=CSE-A')}
                className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30 hover:bg-rose-950/50 transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between font-mono font-bold text-rose-400 mb-1">
                  <span>CSE-A (Power)</span>
                  <span>99.0% Conf</span>
                </div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  5-stage APT attack reconstructed with lateral movement across 3 servers. Click to view attack graph.
                </p>
              </div>

              <div
                onClick={() => navigate('/cse-analysis?cse_id=CSE-B')}
                className="p-3 rounded-lg bg-orange-950/30 border border-orange-500/30 hover:bg-orange-950/50 transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between font-mono font-bold text-orange-400 mb-1">
                  <span>CSE-B (Banking)</span>
                  <span>Rapid Closure</span>
                </div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  15 critical alerts rapidly closed in &lt;120s with template notes. Metric gaming detected.
                </p>
              </div>

              <div
                onClick={() => navigate('/cse-analysis?cse_id=CSE-C')}
                className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 hover:bg-amber-950/50 transition-colors cursor-pointer"
              >
                <div className="flex items-center justify-between font-mono font-bold text-amber-400 mb-1">
                  <span>CSE-C (Telecom)</span>
                  <span>Negative Space</span>
                </div>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  High-criticality asset reporting 0 alerts over 30 days. Sensor health audit recommended.
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 mt-4 flex items-center justify-between text-xs text-slate-400">
            <span className="font-mono">Air-Gapped Certified</span>
            <button
              onClick={() => navigate('/peer-comparison')}
              className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1"
            >
              <span>View Benchmarks</span>
              <ArrowRight size={12} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
