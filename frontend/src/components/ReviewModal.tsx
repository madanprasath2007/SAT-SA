import React, { useState, useEffect } from 'react';
import {
  X,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  FileText,
  Clock,
  User,
  ShieldCheck,
  Send,
  Download,
} from 'lucide-react';
import { submitReview, getFindingReviewHistory, getFindingPdfReportUrl, ReviewRecord } from '../api';

interface ReviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  findingId: string;
  cseId: string;
  findingTitle?: string;
  initialDecision?: string | null;
  onReviewSubmitted?: (newDecision: string) => void;
}

export const ReviewModal: React.FC<ReviewModalProps> = ({
  isOpen,
  onClose,
  findingId,
  cseId,
  findingTitle,
  initialDecision,
  onReviewSubmitted,
}) => {
  const [decision, setDecision] = useState<'VALID' | 'FALSE_POSITIVE' | 'NEEDS_MORE_DATA'>(
    (initialDecision as any) || 'VALID'
  );
  const [notes, setNotes] = useState('');
  const [investigateDeeper, setInvestigateDeeper] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [history, setHistory] = useState<ReviewRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && findingId) {
      setError(null);
      setSuccessMsg(null);
      setNotes('');
      setInvestigateDeeper(false);
      setDecision((initialDecision as any) || 'VALID');

      // Load review history
      setLoadingHistory(true);
      getFindingReviewHistory(findingId)
        .then((res) => {
          setHistory(res.data.data || []);
        })
        .catch(() => setHistory([]))
        .finally(() => setLoadingHistory(false));
    }
  }, [isOpen, findingId, initialDecision]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setSuccessMsg(null);

    try {
      await submitReview({
        finding_id: findingId,
        cse_id: cseId,
        decision,
        notes,
        investigation_requested: investigateDeeper,
      });

      setSuccessMsg(`Determination saved as ${decision}. Audit record created.`);
      if (onReviewSubmitted) {
        onReviewSubmitted(decision);
      }
      setTimeout(() => {
        onClose();
      }, 1200);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to submit supervisory review.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center border border-cyan-500/30">
              <ShieldCheck size={18} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                Supervisory Review & Adjudication
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  {cseId}
                </span>
              </h2>
              <p className="text-[11px] font-mono text-slate-400">{findingId}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {findingTitle && (
            <div className="p-3 bg-slate-950/50 rounded-xl border border-slate-800 text-xs text-slate-300">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
                Finding Narrative:
              </span>
              {findingTitle}
            </div>
          )}

          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle size={15} />
              <span>{successMsg}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Decision Radio Cards */}
            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-2 font-semibold">
                Supervisory Determination (Adjudication):
              </label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                {/* VALID */}
                <button
                  type="button"
                  onClick={() => setDecision('VALID')}
                  className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all ${
                    decision === 'VALID'
                      ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-200 ring-1 ring-emerald-500/40'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-xs">Valid Finding</span>
                    <CheckCircle size={14} className={decision === 'VALID' ? 'text-emerald-400' : 'text-slate-600'} />
                  </div>
                  <span className="text-[10px] text-slate-400">Confirmed risk requiring CSE mitigation.</span>
                </button>

                {/* FALSE_POSITIVE */}
                <button
                  type="button"
                  onClick={() => setDecision('FALSE_POSITIVE')}
                  className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all ${
                    decision === 'FALSE_POSITIVE'
                      ? 'bg-rose-500/15 border-rose-500/50 text-rose-200 ring-1 ring-rose-500/40'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-xs">False Positive</span>
                    <AlertTriangle size={14} className={decision === 'FALSE_POSITIVE' ? 'text-rose-400' : 'text-slate-600'} />
                  </div>
                  <span className="text-[10px] text-slate-400">Benign activity; generates rule tuning.</span>
                </button>

                {/* NEEDS_MORE_DATA */}
                <button
                  type="button"
                  onClick={() => setDecision('NEEDS_MORE_DATA')}
                  className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all ${
                    decision === 'NEEDS_MORE_DATA'
                      ? 'bg-amber-500/15 border-amber-500/50 text-amber-200 ring-1 ring-amber-500/40'
                      : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-xs">Needs More Data</span>
                    <HelpCircle size={14} className={decision === 'NEEDS_MORE_DATA' ? 'text-amber-400' : 'text-slate-600'} />
                  </div>
                  <span className="text-[10px] text-slate-400">Request supplemental telemetry from CSE.</span>
                </button>
              </div>
            </div>

            {/* Deeper Investigation Checkbox */}
            <div className="flex items-center gap-2.5 p-3 rounded-xl bg-slate-950/40 border border-slate-800">
              <input
                type="checkbox"
                id="investigateDeeper"
                checked={investigateDeeper}
                onChange={(e) => setInvestigateDeeper(e.target.checked)}
                className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0 cursor-pointer"
              />
              <label htmlFor="investigateDeeper" className="text-xs text-slate-300 cursor-pointer">
                <span className="font-semibold text-slate-200">Escalate for Deeper Investigation:</span> Flag this finding
                for immediate active forensic scrutiny and SOC escalation.
              </label>
            </div>

            {/* Notes Input */}
            <div>
              <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1 font-semibold">
                Supervisor Adjudication Notes & Assessment:
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Enter justification, mitigation instructions, or rationale for this determination..."
                rows={3}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>

            {/* Action Bar */}
            <div className="flex items-center justify-between pt-2">
              <a
                href={getFindingPdfReportUrl(findingId)}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono font-medium text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
              >
                <Download size={14} />
                <span>Export Dossier (PDF)</span>
              </a>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex items-center gap-1.5 px-5 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-colors disabled:opacity-50 shadow-lg shadow-cyan-600/20"
                >
                  <Send size={13} />
                  <span>{submitting ? 'Recording...' : 'Save Decision'}</span>
                </button>
              </div>
            </div>
          </form>

          {/* Historical Review Audit Trail */}
          <div className="border-t border-slate-800 pt-4">
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-2 mb-3">
              <Clock size={13} />
              <span>Prior Adjudication History ({history.length})</span>
            </h3>

            {loadingHistory ? (
              <p className="text-xs text-slate-500 italic">Loading review ledger...</p>
            ) : history.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No prior reviews recorded. Pending initial adjudication.</p>
            ) : (
              <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                {history.map((rev) => (
                  <div
                    key={rev.review_id}
                    className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-[11px] space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                        <User size={12} className="text-slate-500" />
                        {rev.reviewer} ({rev.reviewer_role})
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono font-bold text-[9px] ${
                          rev.decision === 'VALID'
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : rev.decision === 'FALSE_POSITIVE'
                            ? 'bg-rose-500/20 text-rose-400'
                            : 'bg-amber-500/20 text-amber-400'
                        }`}
                      >
                        {rev.decision}
                      </span>
                    </div>
                    {rev.notes && <p className="text-slate-400">{rev.notes}</p>}
                    <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                      <span>{rev.created_at}</span>
                      {rev.investigation_requested && (
                        <span className="text-cyan-400 font-bold">Investigation Requested</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
