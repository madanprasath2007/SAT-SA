import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  FileSearch,
  Search,
  Server,
  Network,
  User,
  Clock,
  Briefcase,
  Flame,
  FileText,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';
import { getDrilldown, DrilldownData, RawAlert, RawCase } from '../api';
import { RiskBadge } from '../components/RiskBadge';
import { EvidenceChip } from '../components/EvidenceChip';

export const DrilldownView: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const findingId = searchParams.get('finding_id') || '';
  const alertId = searchParams.get('alert_id') || '';
  const caseId = searchParams.get('case_id') || '';
  const cseId = searchParams.get('cse_id') || '';

  const [inputVal, setInputVal] = useState(alertId || findingId || caseId || 'S1-ALT-0001');
  const [loading, setLoading] = useState(false);
  const [drillData, setDrillData] = useState<DrilldownData | null>(null);

  const fetchDrilldown = (fid?: string, aid?: string, cid?: string, entityId?: string) => {
    setLoading(true);
    getDrilldown({
      finding_id: fid || undefined,
      alert_id: aid || undefined,
      case_id: cid || undefined,
      cse_id: entityId || undefined,
    })
      .then((res) => {
        setDrillData(res.data?.data || null);
      })
      .catch((err) => {
        console.error('Failed to load drill-down records:', err);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    // If no params, default to S1-ALT-0001 for immediate demonstration
    const aid = alertId || (!findingId && !caseId && !cseId ? 'S1-ALT-0001' : undefined);
    fetchDrilldown(findingId, aid, caseId, cseId);
  }, [findingId, alertId, caseId, cseId]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const val = inputVal.trim();
    if (!val) return;

    if (val.startsWith('ALT') || val.startsWith('S1-ALT')) {
      setSearchParams({ alert_id: val });
    } else if (val.startsWith('CASE') || val.startsWith('S1-CASE')) {
      setSearchParams({ case_id: val });
    } else if (val.startsWith('CSE')) {
      setSearchParams({ cse_id: val });
    } else {
      setSearchParams({ finding_id: val });
    }
  };

  const alert = drillData?.primary_alert;
  const linkedCase = drillData?.linked_case;
  const investigations = drillData?.investigations || [];
  const relatedAlerts = drillData?.related_alerts || [];
  const finding = drillData?.finding;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
          <FileSearch className="text-cyan-400" size={24} />
          Raw Record & Telemetry Drill-Down
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Inspect raw immutable DuckDB records, linked SOC cases, analyst notes, and correlated timelines
        </p>
      </div>

      {/* Record Search Bar */}
      <form onSubmit={handleSearchSubmit} className="flex gap-2 max-w-xl">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            placeholder="Search by Alert ID (e.g. S1-ALT-0001), Case ID, Finding ID..."
            className="w-full pl-10 pr-3 py-2 text-xs bg-slate-900 border border-slate-800 rounded-xl text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
        <button
          type="submit"
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-xl transition-colors cursor-pointer shadow-lg shadow-cyan-600/20"
        >
          Inspect Record
        </button>
      </form>

      {loading ? (
        <div className="flex flex-col items-center justify-center h-64 space-y-3">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-400 font-mono">
            Querying raw record tables from DuckDB...
          </span>
        </div>
      ) : alert ? (
        <div className="space-y-6">
          {/* Finding Banner if linked to finding */}
          {finding && (
            <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/40 shadow-lg shadow-cyan-500/5 flex flex-wrap items-center justify-between gap-3">
              <div>
                <span className="text-[10px] uppercase font-mono font-bold text-cyan-400 block">
                  Associated Supervisory Finding · {finding.engine}
                </span>
                <div className="text-xs font-bold text-slate-100 mt-0.5">{finding.finding_type}</div>
                <p className="text-xs text-slate-300 mt-1">{finding.description}</p>
              </div>

              <div className="flex items-center gap-2">
                <RiskBadge level={finding.severity} showDot />
                <button
                  onClick={() => navigate(`/attack-path?finding_id=${finding.finding_id}&cse_id=${finding.cse_id}`)}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <span>Attack Graph</span>
                  <ExternalLink size={12} />
                </button>
              </div>
            </div>
          )}

          {/* Primary Alert Record Full View */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <span className="text-xs font-mono font-bold text-cyan-400 px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/20">
                  {alert.alert_id}
                </span>
                <h2 className="text-base font-bold text-slate-100">{alert.category}</h2>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {alert.cse_id}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <RiskBadge level={alert.severity} showDot />
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 uppercase font-semibold">
                  {alert.status || 'CLOSED'}
                </span>
              </div>
            </div>

            {/* Alert Fields Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
                <span className="text-slate-500 uppercase text-[10px] font-semibold block mb-1">
                  Source / Attacker IP
                </span>
                <div className="font-mono font-bold text-rose-400 flex items-center gap-1.5">
                  <Network size={13} />
                  <span>{alert.source_ip || 'N/A (Internal)'}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
                <span className="text-slate-500 uppercase text-[10px] font-semibold block mb-1">
                  Target Destination IP
                </span>
                <div className="font-mono font-semibold text-slate-200">
                  {alert.dest_ip || 'N/A'}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
                <span className="text-slate-500 uppercase text-[10px] font-semibold block mb-1">
                  Impacted Asset
                </span>
                <div className="font-mono font-bold text-purple-400 flex items-center gap-1.5">
                  <Server size={13} />
                  <span>{alert.asset_id || 'N/A'}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
                <span className="text-slate-500 uppercase text-[10px] font-semibold block mb-1">
                  Triage MTTR (Seconds)
                </span>
                <div className="font-mono font-bold text-amber-400 flex items-center gap-1.5">
                  <Clock size={13} />
                  <span>{alert.mttr_seconds ? `${alert.mttr_seconds}s (${Math.round(alert.mttr_seconds/60)}m)` : 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Timestamps & Analyst Details */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-slate-300">
                <span className="text-slate-500 uppercase text-[10px] block mb-0.5">Created Timestamp</span>
                <span>{alert.created_at}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-slate-300">
                <span className="text-slate-500 uppercase text-[10px] block mb-0.5">Closed Timestamp</span>
                <span>{alert.closed_at || 'Still Open'}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-slate-300">
                <span className="text-slate-500 uppercase text-[10px] block mb-0.5">Assigned Analyst</span>
                <div className="flex items-center gap-1.5 text-slate-200">
                  <User size={13} className="text-blue-400" />
                  <span>{alert.analyst_id || 'Unassigned'}</span>
                </div>
              </div>
            </div>

            {/* Closure Notes */}
            {alert.closure_notes && (
              <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-1.5">
                <div className="flex items-center gap-1.5 text-slate-400 text-xs font-semibold">
                  <FileText size={14} className="text-cyan-400" />
                  <span>Analyst Triage & Closure Notes</span>
                </div>
                <p className="text-xs text-slate-200 font-mono leading-relaxed bg-slate-900/80 p-2.5 rounded border border-slate-800">
                  "{alert.closure_notes}"
                </p>
              </div>
            )}
          </div>

          {/* Linked SOC Case & Investigations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Linked Case */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                  <Briefcase size={16} className="text-cyan-400" />
                  Linked SOC Case
                </h3>
                {linkedCase && (
                  <span className="text-xs font-mono font-bold text-cyan-400">
                    {linkedCase.case_id}
                  </span>
                )}
              </div>

              {linkedCase ? (
                <div className="space-y-3 text-xs">
                  <div>
                    <div className="font-bold text-slate-100 text-sm">{linkedCase.title}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <RiskBadge level={linkedCase.severity} size="sm" />
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                        {linkedCase.status}
                      </span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 font-mono space-y-1 text-slate-400">
                    <div>Opened: <span className="text-slate-300">{linkedCase.opened_at}</span></div>
                    {linkedCase.closed_at && (
                      <div>Closed: <span className="text-slate-300">{linkedCase.closed_at}</span></div>
                    )}
                    <div>Analyst: <span className="text-slate-300">{linkedCase.analyst_id}</span></div>
                  </div>

                  {linkedCase.linked_alert_ids && (
                    <div>
                      <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
                        Linked Alerts in Case:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {linkedCase.linked_alert_ids.split(',').map((aid: string) => (
                          <EvidenceChip
                            key={aid.trim()}
                            id={aid.trim()}
                            type="alert"
                            onClick={() => setSearchParams({ alert_id: aid.trim() })}
                          />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-6 text-center text-xs text-slate-500 font-mono">
                  No escalated SOC case linked to this alert record.
                </div>
              )}
            </div>

            {/* Investigations Log */}
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                  <ShieldCheck size={16} className="text-cyan-400" />
                  Investigation Log & Tier Notes
                </h3>
                <span className="text-xs font-mono text-slate-500">
                  {investigations.length} Entry(s)
                </span>
              </div>

              {investigations.length > 0 ? (
                <div className="space-y-3">
                  {investigations.map((inv) => (
                    <div
                      key={inv.investigation_id}
                      className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-cyan-400 font-bold">{inv.investigation_id}</span>
                        <span className="text-slate-400">{inv.started_at?.slice(0, 19)}</span>
                      </div>
                      <p className="text-slate-300 leading-relaxed font-sans">
                        {inv.notes}
                      </p>
                      <div className="text-[11px] text-slate-500 font-mono">
                        Analyst: {inv.analyst_id} · Status: <span className="uppercase text-slate-400">{inv.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-xs text-slate-500 font-mono">
                  No investigation notes recorded for this entity case.
                </div>
              )}
            </div>
          </div>

          {/* Related Alerts Timeline on Same Asset / Source IP */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-semibold text-slate-100 text-sm">
                  Correlated Entity Telemetry Timeline
                </h3>
                <p className="text-xs text-slate-400">
                  Adjacent alerts on asset <strong>{alert.asset_id}</strong> or source IP <strong>{alert.source_ip}</strong>
                </p>
              </div>
              <span className="text-xs font-mono text-slate-500">
                {relatedAlerts.length} Correlated Records
              </span>
            </div>

            <div className="divide-y divide-slate-800/60 max-h-72 overflow-y-auto">
              {relatedAlerts.map((ra) => (
                <div
                  key={ra.alert_id}
                  onClick={() => setSearchParams({ alert_id: ra.alert_id })}
                  className="py-2.5 px-3 rounded-lg hover:bg-slate-800/40 transition-colors flex items-center justify-between gap-4 cursor-pointer"
                >
                  <div className="flex items-center gap-2.5 text-xs">
                    <RiskBadge level={ra.severity} size="sm" />
                    <span className="font-mono text-cyan-400 font-bold">{ra.alert_id}</span>
                    <span className="text-slate-200 font-medium">{ra.category}</span>
                    <span className="text-slate-500 font-mono">·</span>
                    <span className="text-purple-400 font-mono">{ra.asset_id}</span>
                  </div>

                  <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                    <span>{ra.created_at?.slice(0, 19).replace('T', ' ')}</span>
                    <ChevronRight size={14} className="text-slate-600" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-xs text-slate-500 font-mono">
          Record not found. Enter an alert ID like <strong>S1-ALT-0001</strong> above to drill down.
        </div>
      )}
    </div>
  );
};
