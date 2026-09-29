import React, { useEffect, useState } from 'react';
import { X, ExternalLink, ShieldAlert, Server, Network, User, Clock, FileText, CheckCircle2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { getDrilldown, RawAlert } from '../api';
import { RiskBadge } from './RiskBadge';
import { EvidenceChip } from './EvidenceChip';

interface EvidenceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  evidenceId: string | null;
  stageName?: string;
  mitreTactic?: string;
}

export const EvidenceDrawer: React.FC<EvidenceDrawerProps> = ({
  isOpen,
  onClose,
  evidenceId,
  stageName,
  mitreTactic,
}) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [alertData, setAlertData] = useState<RawAlert | null>(null);
  const [linkedCase, setLinkedCase] = useState<any | null>(null);

  useEffect(() => {
    if (!evidenceId || !isOpen) return;

    setLoading(true);
    getDrilldown({ alert_id: evidenceId })
      .then((res) => {
        const d = res.data?.data;
        if (d) {
          setAlertData(d.primary_alert || null);
          setLinkedCase(d.linked_case || null);
        }
      })
      .catch((err) => {
        console.error('Failed to load evidence details:', err);
      })
      .finally(() => setLoading(false));
  }, [evidenceId, isOpen]);

  if (!isOpen) return null;

  const handleOpenDrilldown = () => {
    onClose();
    if (evidenceId) {
      navigate(`/drilldown?alert_id=${evidenceId}`);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      {/* Drawer Panel */}
      <div className="relative w-full max-w-lg bg-slate-900 border-l border-slate-800 shadow-2xl h-full flex flex-col z-10 animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-cyan-400" />
            <div>
              <h3 className="font-semibold text-slate-100 text-sm">Evidence Inspection</h3>
              <p className="text-[11px] text-slate-400 font-mono">
                {stageName ? `${stageName} · ` : ''}{evidenceId}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-48 space-y-3">
              <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-xs text-slate-400 font-mono">Retrieving evidence record from DuckDB...</span>
            </div>
          ) : alertData ? (
            <>
              {/* Primary Identity & Severity */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Alert Record</span>
                  <RiskBadge level={alertData.severity} showDot />
                </div>
                <div className="text-base font-bold text-slate-100">{alertData.category}</div>
                <div className="flex flex-wrap gap-2 pt-1">
                  <EvidenceChip id={alertData.alert_id} type="alert" />
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {alertData.cse_id}
                  </span>
                  {alertData.status && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60 uppercase">
                      Status: {alertData.status}
                    </span>
                  )}
                </div>
              </div>

              {/* Network & Infrastructure Context */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Network & Infrastructure</span>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80">
                    <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                      <Network size={13} className="text-rose-400" />
                      <span>Source / Attacker IP</span>
                    </div>
                    <div className="font-mono font-semibold text-slate-200">
                      {alertData.source_ip ? (
                        <EvidenceChip id={alertData.source_ip} type="ip" />
                      ) : (
                        'N/A (Internal)'
                      )}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80">
                    <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                      <Server size={13} className="text-purple-400" />
                      <span>Impacted Target Asset</span>
                    </div>
                    <div className="font-mono font-semibold text-slate-200">
                      {alertData.asset_id ? (
                        <EvidenceChip id={alertData.asset_id} type="asset" />
                      ) : (
                        'N/A'
                      )}
                    </div>
                  </div>
                </div>

                {alertData.dest_ip && (
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 text-xs">
                    <span className="text-slate-400 block mb-1">Target Destination IP</span>
                    <EvidenceChip id={alertData.dest_ip} type="ip" label="DST" />
                  </div>
                )}
              </div>

              {/* Triage & Operational Performance */}
              <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">SOC Triage Context</span>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80">
                    <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                      <User size={13} className="text-blue-400" />
                      <span>Analyst ID</span>
                    </div>
                    <div className="font-mono text-slate-200">
                      {alertData.analyst_id || 'Unassigned'}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80">
                    <div className="flex items-center gap-1.5 text-slate-400 mb-1">
                      <Clock size={13} className="text-amber-400" />
                      <span>MTTR</span>
                    </div>
                    <div className="font-mono font-semibold text-slate-200">
                      {alertData.mttr_seconds ? `${alertData.mttr_seconds}s (${Math.round(alertData.mttr_seconds/60)}m)` : 'N/A'}
                    </div>
                  </div>
                </div>

                <div className="text-xs text-slate-400 space-y-1 font-mono">
                  <div>Created: <span className="text-slate-300">{alertData.created_at}</span></div>
                  {alertData.closed_at && (
                    <div>Closed: <span className="text-slate-300">{alertData.closed_at}</span></div>
                  )}
                </div>

                {/* Closure Notes */}
                {alertData.closure_notes && (
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 text-xs space-y-1.5">
                    <div className="flex items-center gap-1.5 text-slate-400 font-medium">
                      <FileText size={13} className="text-cyan-400" />
                      <span>Triage / Closure Notes</span>
                    </div>
                    <p className="text-slate-200 italic font-mono text-[11px] leading-relaxed bg-slate-950/80 p-2 rounded border border-slate-800/60">
                      "{alertData.closure_notes}"
                    </p>
                  </div>
                )}
              </div>

              {/* Linked Case if any */}
              {linkedCase && (
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Linked SOC Case</span>
                    <span className="text-xs font-mono text-cyan-400 font-semibold">{linkedCase.case_id}</span>
                  </div>
                  <div className="text-xs text-slate-200 font-medium">{linkedCase.title}</div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    Status: <span className="uppercase text-slate-300">{linkedCase.status}</span> · Severity: {linkedCase.severity}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="p-6 text-center text-xs text-slate-400 font-mono">
              Evidence record details not found for {evidenceId}.
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            Close
          </button>
          <button
            onClick={handleOpenDrilldown}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white transition-colors shadow-lg shadow-cyan-600/20"
          >
            <span>View in Raw Record Drill-down</span>
            <ExternalLink size={13} />
          </button>
        </div>
      </div>
    </div>
  );
};
