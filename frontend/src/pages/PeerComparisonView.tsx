import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart3,
  TrendingDown,
  TrendingUp,
  AlertTriangle,
  Flame,
  ShieldAlert,
  ArrowRight,
  Info,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import { getPeerBenchmarks, PeerBenchmark } from '../api';
import { RiskBadge } from '../components/RiskBadge';

export const PeerComparisonView: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [benchmarks, setBenchmarks] = useState<PeerBenchmark[]>([]);
  const [medians, setMedians] = useState<any>({
    critical_mttr_min: 10,
    escalation_rate: 20,
    investigation_coverage: 50,
  });

  useEffect(() => {
    setLoading(true);
    getPeerBenchmarks()
      .then((res) => {
        const d = res.data?.data;
        if (d) {
          setBenchmarks(d.benchmarks || []);
          setMedians(d.medians || {});
        }
      })
      .catch((err) => {
        console.error('Failed to load peer benchmarks:', err);
      })
      .finally(() => setLoading(false));
  }, []);

  // Prepare chart datasets
  const mttrChartData = benchmarks.map((b) => ({
    name: b.cse_id,
    sector: b.sector,
    'Critical MTTR (min)': b.avg_critical_mttr_min,
    'Cohort Median': medians.critical_mttr_min,
  }));

  const escChartData = benchmarks.map((b) => ({
    name: b.cse_id,
    sector: b.sector,
    'Escalation Rate (%)': b.escalation_rate,
    'Cohort Median': medians.escalation_rate,
  }));

  const invChartData = benchmarks.map((b) => ({
    name: b.cse_id,
    sector: b.sector,
    'Coverage (%)': b.investigation_coverage,
    'Cohort Median': medians.investigation_coverage,
  }));

  // Flatten all outliers across all CSEs
  const allOutliers = benchmarks.flatMap((b) =>
    b.outliers.map((o) => ({ ...o, cse_id: b.cse_id, sector: b.sector }))
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
          <BarChart3 className="text-cyan-400" size={24} />
          Cross-Sector Peer Benchmarking & Outlier Detection
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Comparative baseline analysis identifying operational drift, gamed triage metrics, and systemic blind spots
        </p>
      </div>

      {/* Cohort Norms Summary Banner */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
        <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
          <span className="text-slate-500 uppercase text-[10px] block">Sector Median MTTR</span>
          <span className="text-lg font-bold text-cyan-400">{medians.critical_mttr_min} min</span>
        </div>
        <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
          <span className="text-slate-500 uppercase text-[10px] block">Median Escalation Rate</span>
          <span className="text-lg font-bold text-emerald-400">{medians.escalation_rate}%</span>
        </div>
        <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
          <span className="text-slate-500 uppercase text-[10px] block">Median Investigation Coverage</span>
          <span className="text-lg font-bold text-amber-400">{medians.investigation_coverage}%</span>
        </div>
        <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
          <span className="text-slate-500 uppercase text-[10px] block">Active Outliers Detected</span>
          <span className="text-lg font-bold text-rose-400">{allOutliers.length}</span>
        </div>
      </div>

      {/* Outlier Alert Cards */}
      {allOutliers.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle size={14} className="text-rose-400" />
            Detected Benchmark Deviations & Operational Outliers
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {allOutliers.map((out, idx) => (
              <div
                key={idx}
                className="p-4 rounded-xl bg-slate-900/80 border border-rose-500/30 shadow-lg shadow-rose-950/20 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-400">
                        {out.cse_id}
                      </span>
                      <span className="text-xs text-slate-400">({out.sector})</span>
                    </div>
                    <RiskBadge level={out.severity} size="sm" showDot />
                  </div>

                  <div className="text-xs font-bold text-slate-200 mb-1">
                    {out.metric} Deviation: {out.type}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {out.description}
                  </p>
                </div>

                <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                  <button
                    onClick={() => navigate(`/cse-analysis?cse_id=${out.cse_id}`)}
                    className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1 cursor-pointer"
                  >
                    <span>Inspect {out.cse_id}</span>
                    <ArrowRight size={12} />
                  </button>
                  {out.cse_id === 'CSE-A' && (
                    <button
                      onClick={() => navigate('/attack-path?cse_id=CSE-A')}
                      className="text-rose-400 hover:text-rose-300 font-medium inline-flex items-center gap-1 cursor-pointer"
                    >
                      <span>View S1 Attack</span>
                      <Flame size={12} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Comparison Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* MTTR Comparison */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-slate-100 text-sm">
                Critical Alert MTTR Comparison
              </h3>
              <p className="text-xs text-slate-400">
                Average MTTR (minutes) vs sector median — flagging ultra-rapid closure anomalies
              </p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mttrChartData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace' }} />
                <Bar dataKey="Critical MTTR (min)" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Cohort Median" fill="#64748b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Escalation Rate Comparison */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-slate-100 text-sm">
                Critical Escalation Rate Comparison
              </h3>
              <p className="text-xs text-slate-400">
                % of critical alerts escalated to formal cases or Tier-2/3 review
              </p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={escChartData}>
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
                />
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace' }} />
                <Bar dataKey="Escalation Rate (%)" fill="#10b981" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Cohort Median" fill="#64748b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
