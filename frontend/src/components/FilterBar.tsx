import React from 'react';
import { Search, Filter, X } from 'lucide-react';

interface FilterBarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  selectedCse: string;
  onCseChange: (cse: string) => void;
  selectedSeverity: string;
  onSeverityChange: (sev: string) => void;
  selectedEngine?: string;
  onEngineChange?: (engine: string) => void;
  cses?: string[];
  engines?: string[];
  totalResults?: number;
  onReset?: () => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  searchQuery,
  onSearchChange,
  selectedCse,
  onCseChange,
  selectedSeverity,
  onSeverityChange,
  selectedEngine = 'ALL',
  onEngineChange,
  cses = ['CSE-A', 'CSE-B', 'CSE-C', 'CSE-D'],
  engines = [
    'RuleEngine',
    'AnomalyDetectionEngine',
    'PeerBenchmarkingEngine',
    'ExecutionGapEngine',
    'NegativeSpaceEngine',
  ],
  totalResults,
  onReset,
}) => {
  const hasActiveFilters =
    searchQuery.trim() !== '' ||
    selectedCse !== 'ALL' ||
    selectedSeverity !== 'ALL' ||
    selectedEngine !== 'ALL';

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/80 border border-slate-800 shadow-sm">
      <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search findings, alert IDs, assets..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition-colors"
          />
        </div>

        {/* CSE Dropdown */}
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">CSE:</span>
          <select
            value={selectedCse}
            onChange={(e) => onCseChange(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono cursor-pointer transition-colors"
          >
            <option value="ALL">All Entities</option>
            {cses.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>

        {/* Severity Dropdown */}
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Severity:</span>
          <select
            value={selectedSeverity}
            onChange={(e) => onSeverityChange(e.target.value)}
            className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono cursor-pointer transition-colors"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Engine Dropdown */}
        {onEngineChange && (
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Engine:</span>
            <select
              value={selectedEngine}
              onChange={(e) => onEngineChange(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono cursor-pointer transition-colors"
            >
              <option value="ALL">All Engines</option>
              {engines.map((eng) => (
                <option key={eng} value={eng}>{eng.replace('Engine', '')}</option>
              ))}
            </select>
          </div>
        )}

        {/* Reset Filter Button */}
        {hasActiveFilters && onReset && (
          <button
            onClick={onReset}
            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded-lg border border-rose-500/20 transition-colors"
            title="Reset filters"
          >
            <X size={12} />
            <span>Reset</span>
          </button>
        )}
      </div>

      {totalResults !== undefined && (
        <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
          <Filter size={12} className="text-cyan-400" />
          <span>Showing <strong className="text-cyan-400">{totalResults}</strong> records</span>
        </div>
      )}
    </div>
  );
};
