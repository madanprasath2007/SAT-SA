import axios from 'axios';

const API_BASE_HOST = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api').replace(/\/api\/?$/, '');
const API = axios.create({ baseURL: `${API_BASE_HOST}/api` });


// ── Types & Interfaces ────────────────────────────────────────────────────────
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';

export interface CSEInfo {
  cse_id: string;
  cse_name: string;
  sector: string;
}

export interface RiskScoreComponent {
  score: number;
  max: number;
  [key: string]: any;
}

export interface RiskScoreData {
  cse_id: string;
  cse_name: string;
  sector: string;
  overall_score: number;
  risk_level: RiskLevel;
  components: {
    rule_violations: RiskScoreComponent;
    anomalies: RiskScoreComponent;
    peer_benchmarks: RiskScoreComponent;
    silent_assets: RiskScoreComponent;
    threat_intelligence: RiskScoreComponent;
    attack_traceback: RiskScoreComponent;
  };
  finding_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  recommendations: string[];
  top_contributors: Array<{
    finding_id: string;
    engine: string;
    finding_type: string;
    severity: SeverityLevel;
    score: number;
    description: string;
  }>;
}

export interface Finding {
  finding_id: string;
  alert_id?: string;
  cse_id: string;
  engine: string;
  finding_type: string;
  severity: SeverityLevel;
  description: string;
  score: number;
  evidence: any;
  created_at: string;
}

export interface AttackStage {
  stage_number: number;
  stage_name: string;
  tactic: string;
  technique: string;
  claim: string;
  evidence_ids: string[];
  confidence: number;
  start_time: string;
  end_time: string;
  attacker_intent: string;
  verified?: boolean;
}

export interface IOCMatch {
  ioc_value: string;
  ioc_type: string;
  threat_actor?: string;
  malware_family?: string;
  confidence: number;
  description?: string;
}

export interface TracebackReport {
  incident_id: string;
  cse_id: string;
  finding_id?: string;
  title: string;
  confidence_score: number;
  why_flagged: string;
  how_attack_happened: string;
  stages: AttackStage[];
  matched_iocs: IOCMatch[];
  evidence_ids: string[];
  graph?: {
    nodes: any[];
    edges: any[];
  };
  created_at: string;
}

export interface PeerBenchmark {
  cse_id: string;
  cse_name: string;
  sector: string;
  total_alerts: number;
  critical_alerts: number;
  avg_critical_mttr: number;
  avg_critical_mttr_min: number;
  monitored_assets: number;
  alerts_per_asset: number;
  cases_count: number;
  escalation_rate: number;
  investigation_coverage: number;
  ioc_count: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  total_findings: number;
  outliers: Array<{
    metric: string;
    type: string;
    description: string;
    severity: SeverityLevel;
  }>;
}

export interface PeerBenchmarksResponse {
  benchmarks: PeerBenchmark[];
  medians: {
    critical_mttr_seconds: number;
    critical_mttr_min: number;
    escalation_rate: number;
    investigation_coverage: number;
  };
}

export interface RawAlert {
  alert_id: string;
  cse_id: string;
  batch_id?: string;
  category: string;
  severity: SeverityLevel;
  severity_raw?: string;
  created_at: string;
  closed_at?: string;
  mttr_seconds?: number;
  closure_notes?: string;
  analyst_id?: string;
  asset_id?: string;
  source_ip?: string;
  dest_ip?: string;
  status?: string;
}

export interface RawCase {
  case_id: string;
  cse_id: string;
  batch_id?: string;
  title: string;
  severity: SeverityLevel;
  status: string;
  opened_at: string;
  closed_at?: string;
  analyst_id?: string;
  linked_alert_ids?: string;
}

export interface RawInvestigation {
  investigation_id: string;
  cse_id: string;
  case_id: string;
  analyst_id: string;
  started_at: string;
  completed_at?: string;
  status: string;
  notes: string;
}

export interface DrilldownData {
  finding?: Finding;
  primary_alert?: RawAlert;
  linked_case?: RawCase;
  investigations: RawInvestigation[];
  related_alerts: RawAlert[];
  timeline: any[];
  rejects: any[];
  traceback?: any;
}

// ── Phase 5 Interfaces ────────────────────────────────────────────────────────
export interface UserProfile {
  user_id: string;
  username: string;
  email: string;
  role: 'Admin' | 'Supervisor' | 'Analyst';
  full_name: string;
}

export interface ReviewRecord {
  review_id: string;
  finding_id: string;
  cse_id: string;
  reviewer: string;
  reviewer_role: string;
  decision: 'VALID' | 'FALSE_POSITIVE' | 'NEEDS_MORE_DATA';
  notes: string;
  investigation_requested: boolean;
  created_at: string;
}

export interface ReviewQueueItem {
  finding_id: string;
  cse_id: string;
  engine: string;
  finding_type: string;
  severity: SeverityLevel;
  description: string;
  score: number;
  created_at: string;
  decision: string | null;
  reviewer: string | null;
  notes: string | null;
  investigation_requested: boolean;
  is_reviewed: boolean;
  review_status: 'PENDING' | 'VALID' | 'FALSE_POSITIVE' | 'NEEDS_MORE_DATA';
}

export interface ReviewQueueResponse {
  data: ReviewQueueItem[];
  total: number;
  summary: {
    total: number;
    valid: number;
    false_positive: number;
    needs_more_data: number;
    pending: number;
  };
}

export interface EngineFPRate {
  engine: string;
  total_reviews: number;
  valid: number;
  false_positive: number;
  needs_more_data: number;
  false_positive_rate: number;
}

export interface FeedbackSuggestion {
  log_id: string;
  engine: string;
  rule_id: string;
  suggested_change: string;
  justification: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  reviewed_by?: string;
  action_taken_at?: string;
  created_at: string;
}

export interface AuditLogItem {
  log_id: string;
  action: string;
  user_id: string;
  username: string;
  role: string;
  target_entity?: string;
  details?: any;
  ip_address: string;
  timestamp: string;
}

// ── Auth Token Interceptor ───────────────────────────────────────────────────
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('satsa_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── API Methods ───────────────────────────────────────────────────────────────
export const getKPIs = () => API.get('/dashboard/kpis');
export const getMTTR = () => API.get('/dashboard/mttr-distribution');
export const getHeatmap = () => API.get('/dashboard/cse-heatmap');
export const getTimeline = () => API.get('/dashboard/alert-timeline');
export const getFindingsFeed = (limit = 20) => API.get('/dashboard/findings-feed', { params: { limit } });
export const getPeerBenchmarks = () => API.get('/dashboard/peer-benchmarks');
export const getDrilldown = (params: { finding_id?: string; alert_id?: string; case_id?: string; cse_id?: string }) =>
  API.get('/dashboard/drilldown', { params });

// Analytics & Findings
export const getRiskScores = () => API.get('/analytics/risk-scores');
export const getRiskScoreBreakdown = (cseId: string) => API.get(`/analytics/risk-scores/${cseId}/breakdown`);
export const getFindings = (params?: { cse_id?: string; engine?: string; severity?: string; date?: string; limit?: number; offset?: number }) =>
  API.get('/analytics/findings', { params });
export const getFindingById = (id: string) => API.get(`/analytics/findings/${id}`);
export const runAnalytics = (cseId?: string) => API.post('/analytics/run', null, { params: cseId ? { cse_id: cseId } : {} });

// Attack Traceback
export const getTracebackReport = (findingOrCseId: string) => API.get(`/traceback/${findingOrCseId}`);
export const getTracebackGraph = (findingOrCseId: string) => API.get(`/traceback/${findingOrCseId}/graph`);
export const triggerTraceback = (cseId: string, findingId?: string, llmBackend = 'mock') =>
  API.post('/traceback/run', { cse_id: cseId, finding_id: findingId, llm_backend: llmBackend });

// Ingest & Normalization (Phases 1 & 2)
export const ingestFile = (cseId: string, dataType: string, file: File) => {
  const form = new FormData();
  form.append('file', file);
  return API.post(`/ingest/${cseId}/${dataType}`, form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};
export const getRejects = (params?: Record<string, string>) => API.get('/ingest/rejects', { params });
export const getNormalizationPreview = (cseId: string, dataType = 'alerts', limit = 20) =>
  API.get('/ingest/normalization/preview', { params: { cse_id: cseId, data_type: dataType, limit } });
export const getCseStats = (cseId: string) => API.get(`/ingest/cses/${cseId}/stats`);
export const getIngestStatus = () => API.get('/ingest/status');

// ── Phase 5 Methods ──────────────────────────────────────────────────────────

// Auth & RBAC
export const login = (username: string, password: string) => API.post('/auth/login', { username, password });
export const getMe = () => API.get('/auth/me');
export const getDemoUsers = () => API.get('/auth/users');
export const switchRole = (role: 'Admin' | 'Supervisor' | 'Analyst') => API.post('/auth/switch-role', { role });

// Human Review Workflow
export const submitReview = (payload: {
  finding_id: string;
  cse_id: string;
  decision: 'VALID' | 'FALSE_POSITIVE' | 'NEEDS_MORE_DATA';
  notes?: string;
  investigation_requested?: boolean;
}) => API.post('/reviews/', payload);

export const getReviewQueue = (params?: { cse_id?: string; status?: string; limit?: number }) =>
  API.get<ReviewQueueResponse>('/reviews/queue', { params });

export const getFindingReviewHistory = (findingId: string) => API.get(`/reviews/history/${findingId}`);

// Feedback Loop
export const getFeedbackStats = () => API.get('/reviews/feedback/stats');
export const getFeedbackSuggestions = (status?: string) => API.get('/reviews/feedback/suggestions', { params: { status } });
export const actionFeedbackSuggestion = (logId: string, action: 'APPROVE' | 'REJECT', justification?: string) =>
  API.post(`/reviews/feedback/suggestions/${logId}/action`, { action, justification });
export const getTracebackFeedbackContext = () => API.get('/feedback/traceback-context');

// Admin & Audit
export const getAuditLogs = (params?: { action?: string; role?: string; limit?: number; offset?: number }) =>
  API.get('/admin/audit-logs', { params });
export const getSystemStatus = () => API.get('/admin/system-status');

// Export & Reports
export const getCsePdfReportUrl = (cseId: string) => `${API_BASE_HOST}/api/export/pdf/cse/${cseId}`;
export const getFindingPdfReportUrl = (findingId: string) => `${API_BASE_HOST}/api/export/pdf/finding/${findingId}`;
export const getFindingsCsvUrl = (cseId?: string, severity?: string, engine?: string) => {
  const params = new URLSearchParams();
  if (cseId) params.append('cse_id', cseId);
  if (severity) params.append('severity', severity);
  if (engine) params.append('engine', engine);
  return `${API_BASE_HOST}/api/export/findings/csv?${params.toString()}`;
};

