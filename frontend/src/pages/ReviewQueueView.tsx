import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  CheckSquare,
  Filter,
  Search,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  Clock,
  ShieldAlert,
  ArrowRight,
  Download,
  Flame,
} from 'lucide-react';
import { getReviewQueue, ReviewQueueItem, getFindingPdfReportUrl } from '../api';
import { RiskBadge } from '../components/RiskBadge';
import { ReviewModal } from '../components/ReviewModal';

export const ReviewQueueView: React.FC = () => {
  const navigate = useNavigate();
  const [items, setItems] = useState<ReviewQueueItem[]>([]);
  const [summary, setSummary] = useState({
    total: 0,
    valid: 0,
    false_positive: 0,
    needs_more_data: 0,
    pending: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedCse, setSelectedCse] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modal State
  const [selectedFinding, setSelectedFinding] = useState<ReviewQueueItem | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchQueue = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getReviewQueue({
        cse_id: selectedCse !== 'ALL' ? selectedCse : undefined,
        status: selectedStatus !== 'ALL' ? selectedStatus : undefined,
        limit: 100,
      });
      setItems(res.data.data || []);
      if (res.data.summary) {
        setSummary(res.data.summary);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch review queue.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchQueue();
  }, [selectedCse, selectedStatus]);

  const filteredItems = items.filter((item) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.finding_id.toLowerCase().includes(q) ||
      item.cse_id.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.engine.toLowerCase().includes(q) ||
      item.finding_type.toLowerCase().includes(q)
    );
  });

  const handleOpenReview = (item: ReviewQueueItem) => {
    setSelectedFinding(item);
    setIsModalOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <CheckSquare className="text-cyan-400" size={24} />
            Supervisory Adjudication & Review Queue
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Human-in-the-loop validation ledger for automated findings under NCIIPC/NTRO governance
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchQueue()}
            className="px-3 py-1.5 rounded-xl text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors"
          >
            Refresh Queue
          </button>
        </div>
      </div>

      {/* Stats Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Pending Triage</span>
            <Clock size={15} className="text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">{summary.pending}</div>
          <span className="text-[10px] text-slate-500 mt-1">Awaiting determination</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Validated Risks</span>
            <CheckCircle size={15} className="text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">{summary.valid}</div>
          <span className="text-[10px] text-slate-500 mt-1">Confirmed actionable</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>False Positives</span>
            <AlertTriangle size={15} className="text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-2">{summary.false_positive}</div>
          <span className="text-[10px] text-slate-500 mt-1">Sent to tuning loop</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Needs Data</span>
            <HelpCircle size={15} className="text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-2">{summary.needs_more_data}</div>
          <span className="text-[10px] text-slate-500 mt-1">Telemetry requested</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Total Findings</span>
            <ShieldAlert size={15} className="text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-300 mt-2">{summary.total}</div>
          <span className="text-[10px] text-slate-500 mt-1">Across all engines</span>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {/* CSE Filter */}
          <div className="flex items-center gap-1.5 font-mono">
            <span className="text-slate-500 text-[11px] uppercase">Entity:</span>
            <select
              value={selectedCse}
              onChange={(e) => setSelectedCse(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Entities (CSEs)</option>
              <option value="CSE-A">CSE-A (Alpha Power)</option>
              <option value="CSE-B">CSE-B (Beta Banking)</option>
              <option value="CSE-C">CSE-C (Charlie Telecom)</option>
              <option value="CSE-D">CSE-D (Delta Healthcare)</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 font-mono">
            <span className="text-slate-500 text-[11px] uppercase">Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="PENDING">Pending Review</option>
              <option value="VALID">Valid (Confirmed)</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="NEEDS_MORE_DATA">Needs More Data</option>
            </select>
          </div>
        </div>

        {/* Search Input */}
        <div className="relative min-w-[240px]">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search findings, rules, notes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Main Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs">
            Loading supervisory review queue...
          </div>
        ) : error ? (
          <div className="p-8 text-center text-rose-400 font-mono text-xs">
            Error: {error}
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs">
            No findings match the selected review criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 font-mono text-slate-400 uppercase text-[11px] tracking-wider">
                  <th className="py-3 px-4">Entity</th>
                  <th className="py-3 px-4">Finding ID / Rule</th>
                  <th className="py-3 px-4">Engine</th>
                  <th className="py-3 px-4">Severity / Score</th>
                  <th className="py-3 px-4">Narrative</th>
                  <th className="py-3 px-4">Review Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredItems.map((item) => {
                  return (
                    <tr
                      key={item.finding_id}
                      className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                      onClick={() => handleOpenReview(item)}
                    >
                      {/* Entity */}
                      <td className="py-3 px-4 font-mono font-semibold text-cyan-400 whitespace-nowrap">
                        {item.cse_id}
                      </td>

                      {/* Finding ID */}
                      <td className="py-3 px-4 font-mono whitespace-nowrap">
                        <span className="font-semibold text-slate-200 block">{item.finding_id}</span>
                        <span className="text-[10px] text-slate-500">{item.finding_type}</span>
                      </td>

                      {/* Engine */}
                      <td className="py-3 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                        {item.engine}
                      </td>

                      {/* Severity / Score */}
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <RiskBadge level={item.severity} />
                          <span className="font-mono text-slate-300 font-semibold">{item.score}</span>
                        </div>
                      </td>

                      {/* Description */}
                      <td className="py-3 px-4 text-slate-300 max-w-md truncate" title={item.description}>
                        {item.description}
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4 whitespace-nowrap font-mono">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold inline-flex items-center gap-1 ${
                            item.review_status === 'VALID'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : item.review_status === 'FALSE_POSITIVE'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : item.review_status === 'NEEDS_MORE_DATA'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          {item.review_status === 'VALID' && <CheckCircle size={10} />}
                          {item.review_status === 'FALSE_POSITIVE' && <AlertTriangle size={10} />}
                          {item.review_status === 'NEEDS_MORE_DATA' && <HelpCircle size={10} />}
                          {item.review_status === 'PENDING' && <Clock size={10} />}
                          <span>{item.review_status}</span>
                        </span>
                        {item.investigation_requested && (
                          <span className="text-[9px] text-cyan-400 block mt-0.5 font-bold">
                            Investigation Active
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td
                        className="py-3 px-4 text-right space-x-2 whitespace-nowrap"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          onClick={() => handleOpenReview(item)}
                          className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors"
                        >
                          Adjudicate
                        </button>
                        <button
                          onClick={() =>
                            navigate(`/attack-path?finding_id=${item.finding_id}&cse_id=${item.cse_id}`)
                          }
                          className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
                          title="Attack Graph"
                        >
                          <Flame size={12} className="inline mr-1 text-orange-400" />
                          Graph
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Review Modal */}
      {selectedFinding && (
        <ReviewModal
          isOpen={isModalOpen}
          onClose={() => {
            setIsModalOpen(false);
            setSelectedFinding(null);
          }}
          findingId={selectedFinding.finding_id}
          cseId={selectedFinding.cse_id}
          findingTitle={selectedFinding.description}
          initialDecision={selectedFinding.decision}
          onReviewSubmitted={() => {
            fetchQueue();
          }}
        />
      )}
    </div>
  );
};
