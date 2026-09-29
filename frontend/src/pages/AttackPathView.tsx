import React, { useEffect, useState, useMemo } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  Position,
} from 'reactflow';
import 'reactflow/dist/style.css';

import {
  ShieldAlert,
  Flame,
  Clock,
  ExternalLink,
  Layers,
  Calendar,
  Sparkles,
  CheckCircle2,
  RefreshCw,
  Info,
  CheckSquare,
  Download,
} from 'lucide-react';
import { getTracebackReport, triggerTraceback, TracebackReport, AttackStage, getFindingPdfReportUrl } from '../api';
import { StageCard } from '../components/StageCard';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { EvidenceChip } from '../components/EvidenceChip';
import { ReviewModal } from '../components/ReviewModal';

export const AttackPathView: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const cseId = searchParams.get('cse_id') || 'CSE-A';
  const findingId = searchParams.get('finding_id');

  const [loading, setLoading] = useState(true);
  const [runningTraceback, setRunningTraceback] = useState(false);
  const [report, setReport] = useState<TracebackReport | null>(null);
  const [viewMode, setViewMode] = useState<'graph' | 'timeline'>('graph');

  // Evidence Drawer state
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [selectedStageName, setSelectedStageName] = useState<string | undefined>(undefined);

  // Review Modal state
  const [isReviewOpen, setIsReviewOpen] = useState(false);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const targetParam = findingId || cseId;
      const res = await getTracebackReport(targetParam);
      setReport(res.data?.data || null);
    } catch (err) {
      console.error('Failed to load traceback report:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [cseId, findingId]);

  const handleRunTraceback = async () => {
    setRunningTraceback(true);
    try {
      await triggerTraceback(cseId, findingId || undefined);
      await fetchReport();
    } catch (e) {
      console.error(e);
    } finally {
      setRunningTraceback(false);
    }
  };

  // Convert stages into React Flow nodes and edges
  const { nodes, edges } = useMemo(() => {
    if (!report || !report.stages || report.stages.length === 0) {
      return { nodes: [], edges: [] };
    }

    const stageNodes: Node[] = [];
    const stageEdges: Edge[] = [];

    const numStages = report.stages.length;
    const spacingX = 260;

    report.stages.forEach((stage, idx) => {
      const confPct = Math.round(stage.confidence > 1 ? stage.confidence : stage.confidence * 100);
      const isHighConf = confPct >= 85;

      stageNodes.push({
        id: `stage-${stage.stage_number}`,
        position: { x: idx * spacingX + 40, y: 120 },
        data: {
          label: (
            <div className="p-3 bg-slate-900 border border-slate-700 hover:border-cyan-400 rounded-xl shadow-xl font-sans text-left min-w-[200px] cursor-pointer transition-all hover:-translate-y-1">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="w-5 h-5 rounded bg-cyan-500/20 text-cyan-400 text-xs font-bold font-mono flex items-center justify-center border border-cyan-500/40">
                  {stage.stage_number}
                </span>
                <span
                  className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                    isHighConf
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                  }`}
                >
                  {confPct}% conf
                </span>
              </div>

              <div className="font-bold text-xs text-slate-100 mb-1">{stage.stage_name}</div>
              <div className="text-[10px] font-mono text-cyan-400 mb-2">
                {stage.tactic} · {stage.technique}
              </div>

              <div className="text-[11px] text-slate-300 line-clamp-2 mb-2 leading-tight">
                {stage.claim}
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono text-slate-400">
                <span>{stage.evidence_ids?.length || 0} Evidences</span>
                <span className="text-cyan-400 hover:underline">Inspect &rarr;</span>
              </div>
            </div>
          ),
          stage,
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });

      // Chain edges
      if (idx < numStages - 1) {
        stageEdges.push({
          id: `edge-${idx}-${idx + 1}`,
          source: `stage-${stage.stage_number}`,
          target: `stage-${report.stages[idx + 1].stage_number}`,
          animated: true,
          style: { stroke: '#06b6d4', strokeWidth: 2 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#06b6d4',
          },
        });
      }
    });

    return { nodes: stageNodes, edges: stageEdges };
  }, [report]);

  const handleNodeClick = (_: React.MouseEvent, node: Node) => {
    const stage: AttackStage = node.data?.stage;
    if (stage && stage.evidence_ids && stage.evidence_ids.length > 0) {
      setSelectedEvidenceId(stage.evidence_ids[0]);
      setSelectedStageName(stage.stage_name);
      setDrawerOpen(true);
    }
  };

  const handleEvidenceClick = (evidenceId: string, stageName?: string) => {
    setSelectedEvidenceId(evidenceId);
    setSelectedStageName(stageName);
    setDrawerOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <Flame className="text-rose-500" size={24} />
            AI Attack Path Reconstruction
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Chronological multi-stage adversary kill-chain and verified evidence linkage · {cseId}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Timeline / Graph Mode Toggle */}
          <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800">
            <button
              onClick={() => setViewMode('graph')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                viewMode === 'graph'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers size={13} />
              <span>React Flow Graph</span>
            </button>
            <button
              onClick={() => setViewMode('timeline')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                viewMode === 'timeline'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-600/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Calendar size={13} />
              <span>Timeline Sequence</span>
            </button>
          </div>

            <button
              onClick={handleRunTraceback}
              disabled={runningTraceback}
              className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors cursor-pointer"
            >
              <RefreshCw size={13} className={runningTraceback ? 'animate-spin' : ''} />
              <span>{runningTraceback ? 'Reconstructing...' : 'Re-Run Traceback'}</span>
            </button>

            {/* Supervisor Adjudication Button */}
            <button
              onClick={() => setIsReviewOpen(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition-colors cursor-pointer shadow-lg shadow-emerald-600/20"
            >
              <CheckSquare size={13} />
              <span>Adjudicate Finding</span>
            </button>

            {/* Export PDF Dossier */}
            <a
              href={getFindingPdfReportUrl(findingId || report?.finding_id || 'FND-S1-CORR-01')}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors cursor-pointer"
            >
              <Download size={13} />
              <span>Export PDF</span>
            </a>
          </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center h-80 space-y-3">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-400 font-mono">
            Reconstructing MITRE attack sequence and graph nodes...
          </span>
        </div>
      ) : report ? (
        <div className="space-y-5">
          {/* Matched CTI Banner if any */}
          {report.matched_iocs && report.matched_iocs.length > 0 && (
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 shadow-lg shadow-rose-950/30 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <ShieldAlert className="text-rose-400 shrink-0" size={20} />
                <div>
                  <div className="text-xs font-bold text-rose-200 uppercase tracking-wide flex items-center gap-2">
                    <span>Confirmed CTI Threat Intelligence Indicator Matched</span>
                    <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono text-[10px]">
                      High Confidence
                    </span>
                  </div>
                  <p className="text-xs text-rose-300/80 mt-0.5">
                    Adversary campaign telemetry actively correlated with verified national threat intelligence feeds.
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {report.matched_iocs.map((ioc) => (
                  <EvidenceChip
                    key={ioc.ioc_value}
                    id={ioc.ioc_value}
                    type="ip"
                    label="CTI IOC"
                  />
                ))}
              </div>
            </div>
          )}

          {/* Narrative & Confidence Summary Card */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider font-mono">
                  Incident: {report.incident_id}
                </span>
                <h2 className="text-base font-bold text-slate-100 mt-0.5">{report.title}</h2>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase font-mono block">Overall Confidence</span>
                  <span className="text-xl font-bold font-mono text-emerald-400">
                    {report.confidence_score.toFixed(1)}%
                  </span>
                </div>
                <div className="h-8 w-px bg-slate-800" />
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase font-mono block">Attack Stages</span>
                  <span className="text-xl font-bold font-mono text-cyan-400">
                    {report.stages?.length || 0}
                  </span>
                </div>
              </div>
            </div>

            {report.why_flagged && (
              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs text-slate-300 leading-relaxed font-mono">
                <strong className="text-cyan-400">WHY Flagged:</strong> {report.why_flagged}
              </div>
            )}
          </div>

          {/* View Mode: React Flow Graph vs Chronological Timeline */}
          {viewMode === 'graph' ? (
            <div className="h-[480px] w-full rounded-xl bg-slate-950 border border-slate-800 overflow-hidden relative shadow-2xl">
              <div className="absolute top-3 left-3 z-10 p-2 rounded-lg bg-slate-900/90 border border-slate-800 text-[11px] text-slate-400 font-mono flex items-center gap-2">
                <Info size={14} className="text-cyan-400" />
                <span>Click any stage card to inspect underlying DuckDB evidence records</span>
              </div>

              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodeClick={handleNodeClick}
                fitView
                fitViewOptions={{ padding: 0.3 }}
              >
                <Background color="#334155" gap={20} size={1} />
                <Controls className="bg-slate-900 border border-slate-800 text-slate-200 fill-slate-200" />
                <MiniMap
                  nodeColor="#06b6d4"
                  maskColor="rgba(15, 23, 42, 0.7)"
                  className="bg-slate-900 border border-slate-800 rounded-lg"
                />
              </ReactFlow>
            </div>
          ) : (
            /* Timeline Sequence View */
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Chronological Stage Progression
                </h3>
                <span className="text-xs font-mono text-slate-500">
                  {report.stages?.length || 0} Stages Ordered Chronologically
                </span>
              </div>

              <div className="space-y-3">
                {report.stages.map((stage) => (
                  <StageCard
                    key={stage.stage_number}
                    stage={stage}
                    onSelectEvidence={(eid) => handleEvidenceClick(eid, stage.stage_name)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Adversary Narrative Breakdown */}
          {report.how_attack_happened && (
            <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                <Sparkles size={16} className="text-cyan-400" />
                Offline AI Incident Reconstruction Narrative
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed font-sans bg-slate-950/60 p-4 rounded-lg border border-slate-800/80">
                {report.how_attack_happened}
              </p>
            </div>
          )}
        </div>
      ) : (
        <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-xs text-slate-500 font-mono">
          No traceback report found for {cseId}. Click "Re-Run Traceback" above to generate.
        </div>
      )}

      {/* Slide-over Evidence Inspection Drawer */}
      <EvidenceDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        evidenceId={selectedEvidenceId}
        stageName={selectedStageName}
      />

      {/* Review Modal */}
      <ReviewModal
        isOpen={isReviewOpen}
        onClose={() => setIsReviewOpen(false)}
        findingId={findingId || report?.finding_id || 'FND-S1-CORR-01'}
        cseId={cseId}
        findingTitle={report?.title || 'Multi-stage adversary attack path'}
        onReviewSubmitted={() => {
          fetchReport();
        }}
      />
    </div>
  );
};
