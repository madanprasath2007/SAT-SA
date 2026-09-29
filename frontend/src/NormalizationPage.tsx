/**
 * NormalizationPage — Phase 1
 * Shows before/after normalization pairs for a selected CSE.
 */
import React, { useState, useEffect } from 'react';
import { ArrowRight, RefreshCw, Zap } from 'lucide-react';
import { getNormalizationPreview } from './api';

const CSE_IDS = ['CSE-A', 'CSE-B', 'CSE-C', 'CSE-D'];
const DATA_TYPES = ['alerts', 'assets'];

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e',
};

function SevBadge({ value }: { value: string }) {
  const color = SEV_COLORS[value?.toUpperCase()] || '#475569';
  return (
    <span style={{
      background: color + '22', color, border: `1px solid ${color}55`,
      borderRadius: 4, padding: '2px 6px', fontSize: 11, fontWeight: 600, fontFamily: 'monospace',
    }}>
      {value || '—'}
    </span>
  );
}

function Cell({ label, value, highlight }: { label: string; value: React.ReactNode; highlight?: boolean }) {
  return (
    <div style={{
      background: highlight ? '#1e2d4799' : 'transparent',
      border: '1px solid #1e2d47',
      borderRadius: 6,
      padding: '8px 12px',
      flex: 1,
      minWidth: 0,
    }}>
      <div style={{ fontSize: 10, color: '#475569', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 12, color: '#e2e8f0', wordBreak: 'break-all' }}>{value}</div>
    </div>
  );
}

interface AlertPair {
  alert_id: string;
  cse_id: string;
  severity_before: string;
  severity_after: string;
  created_at_iso: string;
  source_ip: string;
  mttr_seconds: number;
  category: string;
}

interface AssetPair {
  asset_id: string;
  cse_id: string;
  asset_name: string;
  criticality_normalised: string;
  ip_address: string;
  last_seen_iso: string;
}

export function NormalizationPage() {
  const [cseId, setCseId]         = useState('CSE-A');
  const [dataType, setDataType]   = useState('alerts');
  const [data, setData]           = useState<any[]>([]);
  const [loading, setLoading]     = useState(false);
  const [count, setCount]         = useState(0);
  const [error, setError]         = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const resp = await getNormalizationPreview(cseId, dataType, 25);
      setData(resp.data.data || []);
      setCount(resp.data.count || 0);
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to load preview');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [cseId, dataType]);

  return (
    <div className="normalization-page">
      <div className="page-header">
        <div>
          <div className="page-title">Before ↔ After Normalization</div>
          <div className="page-subtitle">Raw ingested values vs. pipeline-normalised output</div>
        </div>
        <button className="btn btn-secondary" onClick={load} disabled={loading}>
          <RefreshCw size={13} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
          Refresh
        </button>
      </div>

      {/* Controls */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-body" style={{ padding: '12px 20px', display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: '#475569' }}>CSE:</span>
            {CSE_IDS.map(id => (
              <button
                key={id}
                onClick={() => setCseId(id)}
                style={{
                  padding: '4px 12px', borderRadius: 6, fontSize: 12,
                  background: cseId === id ? '#3b82f6' : '#1e2d47',
                  color: cseId === id ? '#fff' : '#94a3b8',
                  border: 'none', cursor: 'pointer', transition: 'all .15s',
                }}
              >{id}</button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 12, color: '#475569' }}>Type:</span>
            {DATA_TYPES.map(dt => (
              <button
                key={dt}
                onClick={() => setDataType(dt)}
                style={{
                  padding: '4px 12px', borderRadius: 6, fontSize: 12,
                  background: dataType === dt ? '#8b5cf6' : '#1e2d47',
                  color: dataType === dt ? '#fff' : '#94a3b8',
                  border: 'none', cursor: 'pointer', transition: 'all .15s',
                }}
              >{dt}</button>
            ))}
          </div>
          {count > 0 && (
            <span style={{ fontSize: 11, color: '#475569', marginLeft: 'auto' }}>
              {count} normalised rows
            </span>
          )}
        </div>
      </div>

      {/* Before/After pairs */}
      {loading ? (
        <div className="loading-spinner"><div className="spinner" /><span>Loading…</span></div>
      ) : error ? (
        <div className="empty-state" style={{ color: '#ef4444' }}>{error}</div>
      ) : data.length === 0 ? (
        <div className="empty-state">
          <Zap size={32} />
          <p>No data for {cseId} / {dataType}. Upload a file first.</p>
        </div>
      ) : dataType === 'alerts' ? (
        <AlertPairs rows={data as AlertPair[]} />
      ) : (
        <AssetPairs rows={data as AssetPair[]} />
      )}
    </div>
  );
}

function AlertPairs({ rows }: { rows: AlertPair[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Header */}
      <div style={{
        display: 'grid', gridTemplateColumns: '200px 1fr 32px 1fr',
        gap: 8, padding: '6px 12px',
        fontSize: 10, color: '#475569', fontWeight: 600, letterSpacing: '0.08em',
      }}>
        <div>ALERT ID</div>
        <div>BEFORE (RAW)</div>
        <div />
        <div>AFTER (NORMALISED)</div>
      </div>

      {rows.map(row => (
        <div key={row.alert_id} className="norm-pair-row">
          <div className="norm-pair-id">
            <span className="mono" style={{ fontSize: 10, color: '#3b82f6' }}>{row.alert_id?.slice(0, 18)}</span>
            <span style={{ fontSize: 10, color: '#475569' }}>{row.category}</span>
          </div>

          {/* BEFORE */}
          <div className="norm-pair-side">
            <Cell label="Severity (raw)" value={<span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{row.severity_before || '—'}</span>} />
            <Cell label="Source IP (raw)" value={<span style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 11 }}>{row.source_ip || '—'}</span>} />
          </div>

          {/* Arrow */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ArrowRight size={16} color="#3b82f6" />
          </div>

          {/* AFTER */}
          <div className="norm-pair-side">
            <Cell label="Severity (normalised)" value={<SevBadge value={row.severity_after} />} highlight />
            <Cell label="Timestamp (UTC ISO-8601)" value={<span style={{ color: '#22c55e', fontFamily: 'monospace', fontSize: 11 }}>{row.created_at_iso || '—'}</span>} highlight />
          </div>
        </div>
      ))}
    </div>
  );
}

function AssetPairs({ rows }: { rows: AssetPair[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{
        display: 'grid', gridTemplateColumns: '200px 1fr 32px 1fr',
        gap: 8, padding: '6px 12px',
        fontSize: 10, color: '#475569', fontWeight: 600, letterSpacing: '0.08em',
      }}>
        <div>ASSET ID</div>
        <div>RAW</div>
        <div />
        <div>NORMALISED</div>
      </div>

      {rows.map(row => (
        <div key={row.asset_id} className="norm-pair-row">
          <div className="norm-pair-id">
            <span className="mono" style={{ fontSize: 10, color: '#8b5cf6' }}>{row.asset_id}</span>
            <span style={{ fontSize: 10, color: '#475569' }}>{row.asset_name}</span>
          </div>
          <div className="norm-pair-side">
            <Cell label="IP Address" value={row.ip_address || '—'} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ArrowRight size={16} color="#8b5cf6" />
          </div>
          <div className="norm-pair-side">
            <Cell label="Criticality (normalised)" value={<SevBadge value={row.criticality_normalised} />} highlight />
            <Cell label="Last Seen (UTC ISO)" value={<span style={{ color: '#22c55e', fontFamily: 'monospace', fontSize: 11 }}>{row.last_seen_iso || '—'}</span>} highlight />
          </div>
        </div>
      ))}
    </div>
  );
}
