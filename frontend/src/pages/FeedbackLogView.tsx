import React, { useState, useEffect } from 'react';
import {
  RefreshCw,
  GitPullRequest,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Sliders,
  Cpu,
  ShieldCheck,
  Sparkles,
  Terminal,
} from 'lucide-react';
import {
  getFeedbackStats,
  getFeedbackSuggestions,
  actionFeedbackSuggestion,
  getTracebackFeedbackContext,
  FeedbackSuggestion,
  EngineFPRate,
} from '../api';

export const FeedbackLogView: React.FC = () => {
  const [engineStats, setEngineStats] = useState<EngineFPRate[]>([]);
  const [overallFP, setOverallFP] = useState({ total_reviews: 0, total_false_positives: 0, overall_fp_rate: 0 });
  const [suggestions, setSuggestions] = useState<FeedbackSuggestion[]>([]);
  const [tracebackContext, setTracebackContext] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [statsRes, suggRes, tbRes] = await Promise.all([
        getFeedbackStats().catch(() => ({ data: { data: { by_engine: [], overall: {} } } })),
        getFeedbackSuggestions().catch(() => ({ data: { data: [] } })),
        getTracebackFeedbackContext().catch(() => ({ data: { active_samples: [] } })),
      ]);

      if (statsRes.data?.data) {
        setEngineStats(statsRes.data.data.by_engine || []);
        if (statsRes.data.data.overall) {
          setOverallFP(statsRes.data.data.overall);
        }
      }

      setSuggestions(suggRes.data?.data || []);
      setTracebackContext(tbRes.data?.active_samples || []);
    } catch (err: any) {
      setMsg({ type: 'error', text: 'Failed to load feedback loop telemetry.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleAction = async (logId: string, action: 'APPROVE' | 'REJECT') => {
    setActionLoading(logId);
    setMsg(null);
    try {
      await actionFeedbackSuggestion(logId, action, `Supervisor manual ${action.toLowerCase()} via console`);
      setMsg({
        type: 'success',
        text: `Proposal ${logId} successfully ${action === 'APPROVE' ? 'approved & applied' : 'rejected'}.`,
      });
      fetchData();
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to update rule proposal.' });
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <RefreshCw className="text-cyan-400" size={24} />
            Supervisory Feedback Loop & Adaptive Rule Tuning
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Engine false-positive mitigation, human-approved threshold recommendations, and AI prompt context injection
          </p>
        </div>

        <button
          onClick={fetchData}
          className="px-3 py-1.5 rounded-xl text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors"
        >
          Refresh Feedback Telemetry
        </button>
      </div>

      {msg && (
        <div
          className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
            msg.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          {msg.type === 'success' ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
          <span>{msg.text}</span>
        </div>
      )}

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-slate-400 text-xs font-mono">Overall False Positive Rate</span>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-2">
            {overallFP.overall_fp_rate}%
          </div>
          <span className="text-[10px] text-slate-500 mt-1 block">
            {overallFP.total_false_positives} FP out of {overallFP.total_reviews} reviewed
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-slate-400 text-xs font-mono">Pending Rule Proposals</span>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
            {suggestions.filter((s) => s.status === 'PENDING').length}
          </div>
          <span className="text-[10px] text-slate-500 mt-1 block">Requires supervisor authorization</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-slate-400 text-xs font-mono">Approved Adaptations</span>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
            {suggestions.filter((s) => s.status === 'APPROVED').length}
          </div>
          <span className="text-[10px] text-slate-500 mt-1 block">Enforced in analytics pipeline</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-slate-400 text-xs font-mono">Traceback Context Samples</span>
          <div className="text-2xl font-bold font-mono text-slate-200 mt-2">
            {tracebackContext.length}
          </div>
          <span className="text-[10px] text-slate-500 mt-1 block">Few-shot LLM guidance active</span>
        </div>
      </div>

      {/* Engine False Positive Distribution */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-3">
          <Cpu className="text-cyan-400" size={16} />
          Engine False Positive Rate & Noise Benchmarks
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Supervisory determinations feed continuous quality metrics for each algorithmic engine.
        </p>

        {engineStats.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No supervisor reviews recorded across engines yet.</p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {engineStats.map((eng) => {
              const isHigh = eng.false_positive_rate > 30;
              return (
                <div
                  key={eng.engine}
                  className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200">{eng.engine}</span>
                    <span
                      className={`text-xs font-mono font-bold ${
                        isHigh ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {eng.false_positive_rate}% FP
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-full transition-all duration-500 ${
                        isHigh ? 'bg-rose-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(eng.false_positive_rate, 100)}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                    <span>Valid: {eng.valid}</span>
                    <span>FP: {eng.false_positive}</span>
                    <span>Total: {eng.total_reviews}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Suggested Threshold/Rule Changes (Never auto-apply) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Sliders className="text-cyan-400" size={16} />
            Rule & Threshold Tuning Ledger (Human-in-the-Loop Approval)
          </h2>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
            Never Auto-Applied: Supervisor Authorization Required
          </span>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          When high false-positive frequencies or operational noise are detected, the system recommends tuning proposals.
        </p>

        {suggestions.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No tuning proposals currently pending.</p>
        ) : (
          <div className="space-y-3">
            {suggestions.map((s) => {
              const isPending = s.status === 'PENDING';
              return (
                <div
                  key={s.log_id}
                  className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2 font-mono">
                      <span className="text-xs font-bold text-cyan-400">{s.engine}</span>
                      {s.rule_id && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          {s.rule_id}
                        </span>
                      )}
                      <span
                        className={`text-[9px] px-2 py-0.5 rounded font-bold uppercase ${
                          s.status === 'APPROVED'
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : s.status === 'REJECTED'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}
                      >
                        {s.status}
                      </span>
                    </div>

                    <div className="text-xs font-medium text-slate-200">{s.suggested_change}</div>
                    <div className="text-[11px] text-slate-400 italic">Justification: {s.justification}</div>

                    <div className="text-[10px] text-slate-500 font-mono">
                      Log ID: {s.log_id} | Created: {s.created_at}
                      {s.reviewed_by && (
                        <span>
                          {' '}
                          | Reviewed by: <b className="text-slate-400">{s.reviewed_by}</b>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Actions for pending proposals */}
                  {isPending && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleAction(s.log_id, 'APPROVE')}
                        disabled={actionLoading === s.log_id}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors disabled:opacity-50 flex items-center gap-1.5"
                      >
                        <CheckCircle2 size={13} />
                        <span>Approve Change</span>
                      </button>
                      <button
                        onClick={() => handleAction(s.log_id, 'REJECT')}
                        disabled={actionLoading === s.log_id}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-rose-900/40 text-slate-300 hover:text-rose-300 transition-colors disabled:opacity-50 flex items-center gap-1.5 border border-slate-700"
                      >
                        <XCircle size={13} />
                        <span>Reject</span>
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Traceback Prompt Context Feed */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-2">
          <Sparkles className="text-cyan-400" size={16} />
          Traceback Few-Shot Context Injection (AI Alignment)
        </h2>
        <p className="text-xs text-slate-400 mb-3">
          Validated findings and rejected false positives are dynamically injected into offline LLM prompt context to
          prevent hallucinatory conclusions during attack path reconstruction.
        </p>

        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-48">
          <div className="text-slate-500 mb-2">
            // Prompt Context Header: SUPERVISOR FEEDBACK & PRIOR REVIEWS CONTEXT
          </div>
          {tracebackContext.length === 0 ? (
            <div className="text-slate-600 italic">No human reviews available for prompt injection yet.</div>
          ) : (
            tracebackContext.map((c, i) => (
              <div key={i} className="mb-1 text-slate-300">
                - Finding <span className="text-cyan-400 font-bold">{c.finding_type || c.finding_id}</span> ({c.cse_id}):
                Marked as <span className="text-amber-400 font-bold">{c.decision}</span> by {c.reviewer}. Note: "
                {c.notes || 'Confirmed under formal review'}"
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
