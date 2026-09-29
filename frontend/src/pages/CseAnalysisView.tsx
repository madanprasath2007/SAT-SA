import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Building2,
  ShieldAlert,
  Flame,
  ArrowRight,
  ExternalLink,
  CheckCircle2,
  AlertCircle,
  FileText,
  Activity,
  Network,
  Cpu,
  RefreshCw,
} from 'lucide-react';
import {
  getRiskScoreBreakdown,
  getFindings,
  getRejects,
  RiskScoreData,
  Finding,
} from '../api';
import { RiskBadge } from '../components/RiskBadge';
import { EvidenceChip } from '../components/EvidenceChip';

export const CseAnalysisView: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const cseId = searchParams.get('cse_id') || 'CSE-A';
  const [loading, setLoading] = useState(true);
  const [breakdown, setBreakdown] = useState<RiskScoreData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rejects, setRejects] = useState<any[]>([]);

  const cses = [
    { id: 'CSE-A', name: 'National Power Grid Corp', sector: 'Power' },
    { id: 'CSE-B', name: 'Federal Reserve Banking', sector: 'Banking' },
    { id: 'CSE-C', name: 'Telecom Infrastructure Ltd', sector: 'Telecom' },
    { id: 'CSE-D', name: 'National Healthcare Network', sector: 'Health' },
  ];

  const fetchCseData = async (targetId: string) => {
    setLoading(true);
    try {
      const [bRes, fRes, rRes] = await Promise.all([
        getRiskScoreBreakdown(targetId),
        getFindings({ cse_id: targetId, limit: 50 }),
        getRejects({ cse_id: targetId }),
      ]);
      setBreakdown(bRes.data?.data || null);
      setFindings(fRes.data?.data || []);
      setRejects(rRes.data?.data || []);
    } catch (err) {
      console.error('Error fetching CSE analysis data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCseData(cseId);
  }, [cseId]);

  const handleCseChange = (id: string) => {
    setSearchParams({ cse_id: id });
  };

  const currentCse = cses.find((c) => c.id === cseId) || cses[0];

  return (
    <div className="space-y-6">
      {/* Header & CSE Pill Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <Building2 className="text-cyan-400" size={24} />
            Entity Supervisory Analysis — {cseId}
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            In-depth engine findings, composite risk score explainability, and regulatory action items
          </p>
        </div>

        {/* CSE Switcher Tabs */}
        <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800">
          {cses.map((c) => (
            <button
              key={c.id}
              onClick={() => handleCseChange(c.id)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg font-mono transition-all cursor-pointer ${
                c.id === cseId
                  ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {c.id}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center h-64 space-y-3">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-400 font-mono">Analyzing entity findings and telemetry...</span>
        </div>
      ) : (
        <>
          {/* Top Overview Strip */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Entity Card */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Entity Details
                </span>
                <h3 className="font-bold text-slate-100 text-base mt-1">{currentCse.name}</h3>
                <span className="inline-block mt-1 text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
                  Sector: {currentCse.sector}
                </span>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
                <span className="text-slate-400 font-mono">Total Findings:</span>
                <span className="font-bold text-cyan-400 font-mono">{findings.length}</span>
              </div>
            </div>

            {/* Overall Score Card */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Composite Risk
                </span>
                <RiskBadge level={breakdown?.risk_level || 'LOW'} showDot />
              </div>
              <div className="my-2">
                <div className="text-3xl font-extrabold font-mono text-slate-100">
                  {(breakdown?.overall_score || 0).toFixed(1)}
                  <span className="text-xs font-normal text-slate-500 ml-1">/ 100</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full mt-2 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${Math.min(100, breakdown?.overall_score || 0)}%`,
                      backgroundColor:
                        (breakdown?.overall_score || 0) >= 75
                          ? '#ef4444'
                          : (breakdown?.overall_score || 0) >= 50
                          ? '#f97316'
                          : '#3b82f6',
                    }}
                  />
                </div>
              </div>
              <div className="text-[11px] text-slate-400">
                Tier: <strong className="text-slate-200">{breakdown?.risk_level} Risk</strong>
              </div>
            </div>

            {/* Attack Path Quick Action */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-cyan-500/30 shadow-lg shadow-cyan-500/5 flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Flame size={12} className="text-cyan-400" />
                  Attack Path Corroboration
                </span>
                <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                  Interactive multi-stage attack reconstruction graph and verified kill-chain evidence.
                </p>
              </div>
              <button
                onClick={() => navigate(`/attack-path?cse_id=${cseId}`)}
                className="mt-3 w-full py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer shadow-md shadow-cyan-600/20"
              >
                <span>Launch Attack Graph</span>
                <ArrowRight size={13} />
              </button>
            </div>

            {/* Data Quality & Rejects */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                  Data Quality & Hygiene
                </span>
                <div className="mt-2 text-2xl font-bold font-mono text-slate-200">
                  {rejects.length} Rejects
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  Schema failures & malformed rows quarantined during ingestion.
                </p>
              </div>
              <button
                onClick={() => navigate(`/normalization?cse_id=${cseId}`)}
                className="mt-3 text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
              >
                <span>View Ingestion Rejects</span>
                <ArrowRight size={12} />
              </button>
            </div>
          </div>

          {/* 6 Dimensions Explainable Breakdown */}
          {breakdown?.components && (
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
              <h3 className="font-semibold text-slate-100 text-sm mb-1">
                6-Dimension Explainable Risk Decomposition
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Bounded component scores according to SAT-SA supervisory scoring methodology v2:
              </p>

              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                {Object.entries(breakdown.components).map(([key, comp]: [string, any]) => {
                  const labels: Record<string, { title: string; max: number }> = {
                    rule_violations:     { title: 'Rule Violations', max: 25 },
                    anomalies:           { title: 'Temporal Anomalies', max: 20 },
                    peer_benchmarks:     { title: 'Peer Benchmarks', max: 15 },
                    silent_assets:       { title: 'Negative Space', max: 15 },
                    threat_intelligence: { title: 'Threat Intel / CTI', max: 25 },
                    attack_traceback:    { title: 'Attack Traceback', max: 30 },
                  };
                  const cfg = labels[key] || { title: key, max: 20 };
                  const score = Number(comp.score || 0);

                  return (
                    <div
                      key={key}
                      className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex flex-col justify-between"
                    >
                      <span className="text-[11px] font-semibold text-slate-400 line-clamp-1">
                        {cfg.title}
                      </span>
                      <div className="my-2">
                        <span className="text-xl font-bold font-mono text-cyan-400">
                          {score.toFixed(1)}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono ml-1">/ {cfg.max}</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyan-500 rounded-full"
                          style={{ width: `${Math.min(100, (score / cfg.max) * 100)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Top Findings & Supervisory Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Top Findings List (2 cols) */}
            <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/80 border border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="font-semibold text-slate-100 text-sm">
                    Entity Supervisory Findings
                  </h3>
                  <p className="text-xs text-slate-400">
                    Flagged violations, anomalies, and operational gaps
                  </p>
                </div>
                <button
                  onClick={() => navigate(`/findings?cse_id=${cseId}`)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1"
                >
                  <span>View All in Explorer</span>
                  <ArrowRight size={13} />
                </button>
              </div>

              {findings.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 font-mono">
                  No supervisory findings recorded for {cseId}.
                </div>
              ) : (
                <div className="space-y-3">
                  {findings.slice(0, 6).map((f) => (
                    <div
                      key={f.finding_id}
                      className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors flex items-start justify-between gap-4"
                    >
                      <div className="flex-1 space-y-1.5">
                        <div className="flex items-center gap-2">
                          <RiskBadge level={f.severity} size="sm" />
                          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                            {f.engine}
                          </span>
                          <span className="text-xs font-bold text-slate-200">
                            {f.finding_type}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          {f.description}
                        </p>
                        <div className="flex items-center gap-2 pt-1 text-[11px] font-mono text-slate-400">
                          <span>Score: <strong className="text-cyan-400">{f.score}</strong></span>
                          <span>·</span>
                          <EvidenceChip id={f.finding_id} type="alert" label="ID" />
                        </div>
                      </div>

                      <div className="flex flex-col gap-1.5 shrink-0">
                        <button
                          onClick={() => navigate(`/attack-path?finding_id=${f.finding_id}&cse_id=${cseId}`)}
                          className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors cursor-pointer"
                        >
                          Attack Graph
                        </button>
                        <button
                          onClick={() => navigate(`/drilldown?finding_id=${f.finding_id}`)}
                          className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors cursor-pointer"
                        >
                          Drill Down
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recommendations Panel (1 col) */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
              <div>
                <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                  <CheckCircle2 size={16} className="text-cyan-400" />
                  Prescriptive Supervisory Directives
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Required remediation measures per national audit criteria:
                </p>
              </div>

              {breakdown?.recommendations && breakdown.recommendations.length > 0 ? (
                <div className="space-y-2.5">
                  {breakdown.recommendations.map((rec, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs text-slate-200 leading-relaxed flex items-start gap-2.5"
                    >
                      <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-400 font-mono text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5 border border-cyan-500/30">
                        {i + 1}
                      </span>
                      <span>{rec}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-slate-950/60 text-xs text-slate-500 font-mono">
                  All monitored metrics are within normative tolerance levels.
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
};
