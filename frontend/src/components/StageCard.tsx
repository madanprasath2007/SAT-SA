import React from 'react';
import { ShieldAlert, Clock, ArrowRight, CheckCircle2 } from 'lucide-react';
import { AttackStage } from '../api';
import { EvidenceChip } from './EvidenceChip';

interface StageCardProps {
  stage: AttackStage;
  isActive?: boolean;
  onSelect?: (stage: AttackStage) => void;
  onSelectEvidence?: (evidenceId: string) => void;
}

export const StageCard: React.FC<StageCardProps> = ({
  stage,
  isActive = false,
  onSelect,
  onSelectEvidence,
}) => {
  const confPct = Math.round((stage.confidence > 1 ? stage.confidence : stage.confidence * 100));

  return (
    <div
      onClick={() => onSelect && onSelect(stage)}
      className={`p-4 rounded-xl border transition-all duration-200 cursor-pointer relative ${
        isActive
          ? 'bg-slate-900/90 border-cyan-500 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-500'
          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
      }`}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-6 h-6 rounded-md bg-cyan-500/20 text-cyan-400 font-mono text-xs font-bold border border-cyan-500/30">
            {stage.stage_number}
          </span>
          <h4 className="font-semibold text-slate-100 text-sm">{stage.stage_name}</h4>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {stage.tactic} · {stage.technique}
          </span>
          <span
            className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
              confPct >= 85
                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
            }`}
          >
            {confPct}% conf
          </span>
        </div>
      </div>

      <p className="text-xs text-slate-300 mb-3 leading-relaxed">
        {stage.claim}
      </p>

      {stage.attacker_intent && (
        <div className="mb-3 p-2 rounded-lg bg-slate-950/60 border border-slate-800/80 text-[11px] text-slate-400 flex items-start gap-1.5">
          <ShieldAlert size={13} className="text-amber-400 shrink-0 mt-0.5" />
          <span><strong className="text-slate-300">Adversary Intent:</strong> {stage.attacker_intent}</span>
        </div>
      )}

      <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400">
          <Clock size={12} className="text-slate-500" />
          <span>{stage.start_time?.slice(11, 19) || '00:00:00'}</span>
          <ArrowRight size={10} className="text-slate-600" />
          <span>{stage.end_time?.slice(11, 19) || '00:00:00'}</span>
        </div>
        <div className="flex items-center gap-1">
          <CheckCircle2 size={12} className="text-emerald-400" />
          <span className="text-emerald-400 font-medium">Verified Evidence ({stage.evidence_ids?.length || 0})</span>
        </div>
      </div>

      {stage.evidence_ids && stage.evidence_ids.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5 pt-2 border-t border-slate-800/40">
          {stage.evidence_ids.map((eid) => (
            <EvidenceChip
              key={eid}
              id={eid}
              type="alert"
              onClick={() => onSelectEvidence && onSelectEvidence(eid)}
            />
          ))}
        </div>
      )}
    </div>
  );
};
