import React, { useEffect, useState, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Flame,
  Search,
  ArrowUpDown,
  FileSearch,
  CheckSquare,
} from 'lucide-react';
import { getFindings, Finding } from '../api';
import { RiskBadge } from '../components/RiskBadge';
import { EvidenceChip } from '../components/EvidenceChip';
import { FilterBar } from '../components/FilterBar';
import { ReviewModal } from '../components/ReviewModal';

export const KeyFindingsView: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [findings, setFindings] = useState<Finding[]>([]);

  // Filter states
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCse, setSelectedCse] = useState(searchParams.get('cse_id') || 'ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedEngine, setSelectedEngine] = useState('ALL');

  // Expanded rows state
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  // Sorting
  const [sortField, setSortField] = useState<'severity' | 'score' | 'created_at'>('severity');
  const [sortAsc, setSortAsc] = useState(false);

  // Review Modal state
  const [reviewModalFinding, setReviewModalFinding] = useState<Finding | null>(null);
  const [isReviewOpen, setIsReviewOpen] = useState(false);

  useEffect(() => {
    setLoading(true);
    getFindings({ limit: 300 })
      .then((res) => {
        setFindings(res.data?.data || []);
      })
      .catch((err) => {
        console.error('Failed to load findings:', err);
      })
      .finally(() => setLoading(false));
  }, []);

  const toggleRow = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleResetFilters = () => {
    setSearchQuery('');
    setSelectedCse('ALL');
    setSelectedSeverity('ALL');
    setSelectedEngine('ALL');
  };

  // Filter & sort findings
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        if (selectedCse !== 'ALL' && f.cse_id !== selectedCse) return false;
        if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
        if (selectedEngine !== 'ALL' && f.engine !== selectedEngine) return false;
        if (searchQuery.trim() !== '') {
          const q = searchQuery.toLowerCase();
          const matchDesc = f.description.toLowerCase().includes(q);
          const matchType = f.finding_type.toLowerCase().includes(q);
          const matchId = f.finding_id.toLowerCase().includes(q);
          const matchAlert = f.alert_id?.toLowerCase().includes(q);
          if (!matchDesc && !matchType && !matchId && !matchAlert) return false;
        }
        return true;
      })
      .sort((a, b) => {
        let cmp = 0;
        if (sortField === 'score') {
          cmp = a.score - b.score;
        } else if (sortField === 'created_at') {
          cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
        } else if (sortField === 'severity') {
          const weights: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
          cmp = (weights[a.severity] || 0) - (weights[b.severity] || 0);
        }
        return sortAsc ? cmp : -cmp;
      });
  }, [findings, selectedCse, selectedSeverity, selectedEngine, searchQuery, sortField, sortAsc]);

  const handleSort = (field: 'severity' | 'score' | 'created_at') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
          <ShieldAlert className="text-cyan-400" size={24} />
          Supervisory Key Findings Repository
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Explore and filter all rule breaches, temporal anomalies, execution gaps, and negative space detections
        </p>
      </div>

      {/* Filter Bar */}
      <FilterBar
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        selectedCse={selectedCse}
        onCseChange={setSelectedCse}
        selectedSeverity={selectedSeverity}
        onSeverityChange={setSelectedSeverity}
        selectedEngine={selectedEngine}
        onEngineChange={setSelectedEngine}
        totalResults={filteredFindings.length}
        onReset={handleResetFilters}
      />

      {/* Findings Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 font-mono text-slate-400 uppercase text-[11px] tracking-wider">
                <th className="py-3 px-4 w-10"></th>
                <th className="py-3 px-4">Entity</th>
                <th className="py-3 px-4">Engine</th>
                <th className="py-3 px-4">Finding Type</th>
                <th
                  onClick={() => handleSort('severity')}
                  className="py-3 px-4 cursor-pointer hover:text-cyan-400 transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Severity</span>
                    <ArrowUpDown size={11} />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('score')}
                  className="py-3 px-4 cursor-pointer hover:text-cyan-400 transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Risk Score</span>
                    <ArrowUpDown size={11} />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('created_at')}
                  className="py-3 px-4 cursor-pointer hover:text-cyan-400 transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <span>Detected Time</span>
                    <ArrowUpDown size={11} />
                  </div>
                </th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-800/60 font-sans">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-mono">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                      <span>Loading supervisory findings from DuckDB...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-mono">
                    No findings match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f) => {
                  const isExpanded = expandedIds.has(f.finding_id);
                  const isS1Related =
                    f.cse_id === 'CSE-A' &&
                    (f.description.includes('203.0.113.5') ||
                      f.finding_type.includes('Rapid Closure') ||
                      f.finding_id.includes('s1') ||
                      f.severity === 'CRITICAL');

                  return (
                    <React.Fragment key={f.finding_id}>
                      <tr
                        onClick={() => toggleRow(f.finding_id)}
                        className={`transition-colors cursor-pointer ${
                          isExpanded
                            ? 'bg-slate-800/40'
                            : 'hover:bg-slate-800/20'
                        } ${isS1Related ? 'border-l-2 border-l-rose-500' : ''}`}
                      >
                        <td className="py-3 px-4 text-slate-500">
                          {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>

                        <td className="py-3 px-4 font-mono font-bold text-cyan-400">
                          {f.cse_id}
                        </td>

                        <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700/80">
                            {f.engine.replace('Engine', '')}
                          </span>
                        </td>

                        <td className="py-3 px-4 font-semibold text-slate-200">
                          {f.finding_type}
                        </td>

                        <td className="py-3 px-4">
                          <RiskBadge level={f.severity} size="sm" showDot />
                        </td>

                        <td className="py-3 px-4 font-mono font-bold text-slate-100">
                          {f.score}
                        </td>

                        <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                          {f.created_at ? f.created_at.slice(0, 19).replace('T', ' ') : 'N/A'}
                        </td>

                        <td className="py-3 px-4 text-right space-x-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => {
                              setReviewModalFinding(f);
                              setIsReviewOpen(true);
                            }}
                            className="px-2 py-1 text-[11px] font-mono font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors"
                            title="Supervisory Adjudication"
                          >
                            <CheckSquare size={11} className="inline mr-1" />
                            Review
                          </button>
                          <button
                            onClick={() => navigate(`/attack-path?finding_id=${f.finding_id}&cse_id=${f.cse_id}`)}
                            className="px-2 py-1 text-[11px] font-mono font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors"
                          >
                            Attack Graph
                          </button>
                          <button
                            onClick={() => navigate(`/drilldown?finding_id=${f.finding_id}`)}
                            className="px-2 py-1 text-[11px] font-mono font-semibold rounded bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
                          >
                            Drill Down
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Details Row */}
                      {isExpanded && (
                        <tr className="bg-slate-950/80 border-b border-slate-800/80">
                          <td colSpan={8} className="p-5">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                              {/* Description & WHY */}
                              <div className="md:col-span-2 space-y-2">
                                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 block">
                                  Finding Narrative & Supervisory Context
                                </span>
                                <p className="text-slate-200 leading-relaxed font-sans bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                                  {f.description}
                                </p>

                                <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px] text-slate-400">
                                  <span>Finding ID:</span>
                                  <EvidenceChip id={f.finding_id} type="alert" label="FID" />
                                  {f.alert_id && (
                                    <>
                                      <span>Trigger Alert:</span>
                                      <EvidenceChip
                                        id={f.alert_id}
                                        type="alert"
                                        onClick={() => navigate(`/drilldown?alert_id=${f.alert_id}`)}
                                      />
                                    </>
                                  )}
                                </div>
                              </div>

                              {/* Evidence Payload */}
                              <div className="space-y-2">
                                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 block">
                                  Structured Evidence Payload
                                </span>
                                <pre className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-36">
                                  {JSON.stringify(f.evidence, null, 2)}
                                </pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Review Modal */}
      {reviewModalFinding && (
        <ReviewModal
          isOpen={isReviewOpen}
          onClose={() => {
            setIsReviewOpen(false);
            setReviewModalFinding(null);
          }}
          findingId={reviewModalFinding.finding_id}
          cseId={reviewModalFinding.cse_id}
          findingTitle={reviewModalFinding.description}
          onReviewSubmitted={() => {
            // refresh
            getFindings({ limit: 300 }).then((res) => {
              setFindings(res.data?.data || []);
            });
          }}
        />
      )}
    </div>
  );
};
