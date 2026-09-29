import React, { useState } from 'react';
import {
  DownloadCloud,
  FileText,
  FileSpreadsheet,
  Building2,
  ShieldAlert,
  ArrowRight,
  Download,
  ExternalLink,
  CheckCircle,
  FileCheck,
} from 'lucide-react';
import {
  getCsePdfReportUrl,
  getFindingPdfReportUrl,
  getFindingsCsvUrl,
} from '../api';

export const ExportReportsView: React.FC = () => {
  // CSE PDF selection
  const [selectedCse, setSelectedCse] = useState<string>('CSE-A');

  // Finding PDF selection
  const [findingIdInput, setFindingIdInput] = useState<string>('FND-S1-CORR-01');

  // CSV export filters
  const [csvCse, setCsvCse] = useState<string>('ALL');
  const [csvSeverity, setCsvSeverity] = useState<string>('ALL');
  const [csvEngine, setCsvEngine] = useState<string>('ALL');

  const cseDossiers = [
    {
      id: 'CSE-A',
      name: 'Alpha Power Grid',
      sector: 'Power / Critical Energy Infrastructure',
      risk: 'High (S1 Attack Chain)',
      findings: '18 Flagged Findings',
      desc: 'Comprehensive multi-engine audit capturing initial credential access, unmonitored lateral jumps, and telemetry dark zones.',
    },
    {
      id: 'CSE-B',
      name: 'Beta Banking Corp',
      sector: 'Banking & Financial Services',
      risk: 'Moderate',
      findings: '11 Flagged Findings',
      desc: 'Audit report capturing MTTR escalation outliers, privilege escalations, and SLA investigation breaches.',
    },
    {
      id: 'CSE-C',
      name: 'Charlie Telecom',
      sector: 'Telecommunications',
      risk: 'Moderate',
      findings: '9 Flagged Findings',
      desc: 'Telemetry silence analysis on central switching nodes and rule violation correlations.',
    },
    {
      id: 'CSE-D',
      name: 'Delta Healthcare',
      sector: 'Healthcare & Life Sciences',
      risk: 'Low to Moderate',
      findings: '6 Flagged Findings',
      desc: 'Peer comparative benchmarking against national critical care baseline.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
          <DownloadCloud className="text-cyan-400" size={24} />
          Regulatory Reports & Assessment Dossiers
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          NCIIPC & NTRO compliant offline PDF executive dossiers and forensic CSV data exports
        </p>
      </div>

      {/* Section 1: Official Executive Assessment Reports (PDF) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="text-cyan-400" size={18} />
            <h2 className="text-sm font-bold text-slate-100">
              Official Supervisory Assessment Reports (Per-CSE PDF)
            </h2>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            ReportLab Air-Gapped Generation
          </span>
        </div>
        <p className="text-xs text-slate-400">
          Executive dossiers formatted for national cyber regulatory oversight. Includes composite risk rollup,
          reconstructed kill-chain stages, full findings table, and supervisor adjudication sign-offs.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
          {cseDossiers.map((cse) => (
            <div
              key={cse.id}
              className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between space-y-3 hover:border-cyan-500/40 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-xs text-cyan-400">{cse.id}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {cse.findings}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-slate-200 mt-1">{cse.name}</h3>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">{cse.sector}</p>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">{cse.desc}</p>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80">
                <a
                  href={getCsePdfReportUrl(cse.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-colors shadow-lg shadow-cyan-600/20"
                >
                  <Download size={13} />
                  <span>Download Assessment PDF</span>
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Section 2: Targeted Incident Dossier (PDF) & CSV Data Export */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Finding PDF Dossier */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileCheck className="text-cyan-400" size={18} />
              <h2 className="text-sm font-bold text-slate-100">Finding Incident Dossier (PDF)</h2>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Export an individual technical finding dossier containing attack stage mapping, raw telemetry records,
              and complete supervisor review history.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Target Finding Reference ID:
                </label>
                <input
                  type="text"
                  value={findingIdInput}
                  onChange={(e) => setFindingIdInput(e.target.value)}
                  placeholder="e.g. FND-S1-CORR-01 or FND-EG-01"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <span className="font-semibold text-slate-300 block">Recommended demo findings:</span>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {['FND-S1-CORR-01', 'FND-S1-NS-01', 'FND-S1-ANOM-01'].map((fid) => (
                    <button
                      key={fid}
                      type="button"
                      onClick={() => setFindingIdInput(fid)}
                      className="px-2 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-cyan-400 hover:bg-slate-700"
                    >
                      {fid}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <a
            href={getFindingPdfReportUrl(findingIdInput.trim() || 'FND-S1-CORR-01')}
            target="_blank"
            rel="noreferrer"
            className="flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-slate-600 transition-colors"
          >
            <Download size={14} />
            <span>Export Finding Dossier (PDF)</span>
          </a>
        </div>

        {/* Forensic CSV Export */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileSpreadsheet className="text-emerald-400" size={18} />
              <h2 className="text-sm font-bold text-slate-100">Forensic CSV Data Export</h2>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Export all supervisory findings into a standard comma-separated format for offline spreadsheet analysis
              and long-term archival storage.
            </p>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Entity:
                </label>
                <select
                  value={csvCse}
                  onChange={(e) => setCsvCse(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Entities</option>
                  <option value="CSE-A">CSE-A (Alpha Power)</option>
                  <option value="CSE-B">CSE-B (Beta Banking)</option>
                  <option value="CSE-C">CSE-C (Charlie Telecom)</option>
                  <option value="CSE-D">CSE-D (Delta Health)</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Severity:
                </label>
                <select
                  value={csvSeverity}
                  onChange={(e) => setCsvSeverity(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>
          </div>

          <a
            href={getFindingsCsvUrl(
              csvCse !== 'ALL' ? csvCse : undefined,
              csvSeverity !== 'ALL' ? csvSeverity : undefined,
              csvEngine !== 'ALL' ? csvEngine : undefined
            )}
            download="sat_sa_findings_export.csv"
            className="flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors shadow-lg shadow-emerald-600/20"
          >
            <Download size={14} />
            <span>Download Filtered CSV Dataset</span>
          </a>
        </div>
      </div>
    </div>
  );
};
