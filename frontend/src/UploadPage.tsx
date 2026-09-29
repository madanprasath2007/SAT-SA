/**
 * UploadPage — Phase 1
 * Allows uploading CSV/JSON files per CSE and data type.
 * Shows accepted/rejected counts after ingestion.
 */
import React, { useState, useRef } from 'react';
import { Upload, CheckCircle, XCircle, AlertTriangle, FileText, Loader } from 'lucide-react';
import { ingestFile } from './api';

const CSE_IDS    = ['CSE-A', 'CSE-B', 'CSE-C', 'CSE-D'];
const DATA_TYPES = ['alerts', 'cases', 'investigations', 'escalations', 'assets', 'others'];

const CSE_META: Record<string, { label: string; sector: string; color: string }> = {
  'CSE-A': { label: 'Alpha Power Grid',   sector: 'Power',    color: '#f97316' },
  'CSE-B': { label: 'Beta Banking Corp',  sector: 'Banking',  color: '#3b82f6' },
  'CSE-C': { label: 'Charlie Telecom',    sector: 'Telecom',  color: '#8b5cf6' },
  'CSE-D': { label: 'Delta Healthcare',   sector: 'Health',   color: '#22c55e' },
};

interface UploadResult {
  batch_id: string;
  cse_id: string;
  data_type: string;
  file_name: string;
  rows_received: number;
  rows_accepted: number;
  rows_rejected: number;
  error?: string;
}

export function UploadPage() {
  const [cseId, setCseId]       = useState('CSE-A');
  const [dataType, setDataType] = useState('alerts');
  const [file, setFile]         = useState<File | null>(null);
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<UploadResult | null>(null);
  const [history, setHistory]   = useState<UploadResult[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = (f: File) => setFile(f);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) handleFile(f);
  };

  const handleSubmit = async () => {
    if (!file) return;
    setLoading(true);
    setResult(null);
    try {
      const resp = await ingestFile(cseId, dataType, file);
      const r: UploadResult = resp.data;
      setResult(r);
      setHistory(prev => [r, ...prev].slice(0, 10));
    } catch (err: any) {
      const r: UploadResult = {
        batch_id: '',
        cse_id: cseId,
        data_type: dataType,
        file_name: file.name,
        rows_received: 0,
        rows_accepted: 0,
        rows_rejected: 0,
        error: err?.response?.data?.detail || err?.message || 'Upload failed',
      };
      setResult(r);
    } finally {
      setLoading(false);
    }
  };

  const meta = CSE_META[cseId];
  const acceptRate = result
    ? result.rows_received > 0
      ? Math.round((result.rows_accepted / result.rows_received) * 100)
      : 0
    : null;

  return (
    <div className="upload-page">
      <div className="page-header">
        <div>
          <div className="page-title">Data Ingestion Upload</div>
          <div className="page-subtitle">Upload CSE alert data for pipeline processing</div>
        </div>
      </div>

      <div className="upload-grid">
        {/* Form card */}
        <div className="card upload-form-card">
          <div className="card-header">
            <span className="card-title"><Upload size={14} /> Upload File</span>
          </div>
          <div className="card-body upload-form-body">
            {/* CSE selector */}
            <div className="form-group">
              <label className="form-label">CSE (Security Entity)</label>
              <div className="cse-selector">
                {CSE_IDS.map(id => (
                  <button
                    key={id}
                    className={`cse-btn ${cseId === id ? 'selected' : ''}`}
                    style={{ '--cse-color': CSE_META[id].color } as any}
                    onClick={() => setCseId(id)}
                  >
                    <span className="cse-btn-id">{id}</span>
                    <span className="cse-btn-label">{CSE_META[id].sector}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Data type selector */}
            <div className="form-group">
              <label className="form-label">Data Type</label>
              <select
                className="form-select"
                value={dataType}
                onChange={e => setDataType(e.target.value)}
              >
                {DATA_TYPES.map(dt => (
                  <option key={dt} value={dt}>{dt.charAt(0).toUpperCase() + dt.slice(1)}</option>
                ))}
              </select>
            </div>

            {/* Drop zone */}
            <div className="form-group">
              <label className="form-label">File (CSV or JSON)</label>
              <div
                className={`drop-zone ${dragOver ? 'drag-over' : ''} ${file ? 'has-file' : ''}`}
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileRef.current?.click()}
              >
                {file ? (
                  <>
                    <FileText size={28} className="drop-icon-file" />
                    <div className="drop-filename">{file.name}</div>
                    <div className="drop-filesize">{(file.size / 1024).toFixed(1)} KB</div>
                  </>
                ) : (
                  <>
                    <Upload size={28} className="drop-icon" />
                    <div className="drop-text">Drag & drop or click to select</div>
                    <div className="drop-hint">.csv or .json files accepted</div>
                  </>
                )}
                <input
                  ref={fileRef}
                  type="file"
                  accept=".csv,.json"
                  style={{ display: 'none' }}
                  onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
                />
              </div>
            </div>

            {/* CSE preview */}
            <div className="cse-preview" style={{ borderColor: meta.color }}>
              <div className="cse-preview-dot" style={{ background: meta.color }} />
              <div>
                <div className="cse-preview-name">{meta.label}</div>
                <div className="cse-preview-sub">{cseId} · {meta.sector} · Uploading: {dataType}</div>
              </div>
            </div>

            <button
              className="btn btn-primary upload-btn"
              onClick={handleSubmit}
              disabled={!file || loading}
            >
              {loading
                ? <><Loader size={14} className="spin" /> Processing…</>
                : <><Upload size={14} /> Ingest File</>
              }
            </button>
          </div>
        </div>

        {/* Result + history */}
        <div className="upload-results-col">
          {/* Result card */}
          {result && (
            <div className={`card result-card ${result.error ? 'result-error' : 'result-success'}`}>
              <div className="card-header">
                <span className="card-title">
                  {result.error
                    ? <><XCircle size={14} /> Ingestion Failed</>
                    : <><CheckCircle size={14} /> Ingestion Complete</>
                  }
                </span>
                <span className="result-batch-id">{result.batch_id?.slice(0, 8)}</span>
              </div>
              <div className="card-body">
                {result.error ? (
                  <div className="result-error-msg">{result.error}</div>
                ) : (
                  <>
                    <div className="result-stats">
                      <div className="result-stat">
                        <div className="result-stat-value">{result.rows_received}</div>
                        <div className="result-stat-label">Received</div>
                      </div>
                      <div className="result-stat accepted">
                        <div className="result-stat-value">{result.rows_accepted}</div>
                        <div className="result-stat-label">Accepted</div>
                      </div>
                      <div className="result-stat rejected">
                        <div className="result-stat-value">{result.rows_rejected}</div>
                        <div className="result-stat-label">Rejected</div>
                      </div>
                      <div className="result-stat rate">
                        <div className="result-stat-value">{acceptRate}%</div>
                        <div className="result-stat-label">Accept Rate</div>
                      </div>
                    </div>
                    <div className="result-progress">
                      <div
                        className="result-progress-bar"
                        style={{ width: `${acceptRate}%` }}
                      />
                    </div>
                    {result.rows_rejected > 0 && (
                      <div className="result-reject-note">
                        <AlertTriangle size={12} />
                        {result.rows_rejected} rows rejected — see Rejects page for details
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          )}

          {/* Upload history */}
          {history.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">Recent Uploads</span>
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>CSE</th><th>Type</th><th>File</th>
                      <th>Rcvd</th><th>✓</th><th>✗</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((r, i) => (
                      <tr key={i}>
                        <td><span className="mono" style={{ color: CSE_META[r.cse_id]?.color }}>{r.cse_id}</span></td>
                        <td><span style={{ fontSize: 11, color: '#94a3b8' }}>{r.data_type}</span></td>
                        <td style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11 }}>{r.file_name}</td>
                        <td><span className="mono">{r.rows_received}</span></td>
                        <td><span className="mono" style={{ color: '#22c55e' }}>{r.rows_accepted}</span></td>
                        <td><span className="mono" style={{ color: r.rows_rejected > 0 ? '#ef4444' : '#475569' }}>{r.rows_rejected}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
