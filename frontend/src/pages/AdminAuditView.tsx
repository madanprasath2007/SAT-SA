import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Users,
  FileCheck,
  Server,
  Lock,
  Search,
  Filter,
  Eye,
  Key,
  Database,
  Activity,
  UserCheck,
} from 'lucide-react';
import {
  getAuditLogs,
  getSystemStatus,
  getDemoUsers,
  switchRole,
  AuditLogItem,
  UserProfile,
} from '../api';

export const AdminAuditView: React.FC = () => {
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [totalLogs, setTotalLogs] = useState(0);
  const [systemStatus, setSystemStatus] = useState<any>(null);
  const [demoUsers, setDemoUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState('ALL');
  const [roleFilter, setRoleFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState<AuditLogItem | null>(null);

  const [activeRoleMsg, setActiveRoleMsg] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [logsRes, statusRes, usersRes] = await Promise.all([
        getAuditLogs({
          action: actionFilter !== 'ALL' ? actionFilter : undefined,
          role: roleFilter !== 'ALL' ? roleFilter : undefined,
          limit: 100,
        }).catch(() => ({ data: { data: [], total: 0 } })),
        getSystemStatus().catch(() => ({ data: null })),
        getDemoUsers().catch(() => ({ data: { users: [] } })),
      ]);

      setAuditLogs(logsRes.data?.data || []);
      setTotalLogs(logsRes.data?.total || 0);
      setSystemStatus(statusRes.data || null);
      setDemoUsers(usersRes.data?.users || []);
    } catch (err: any) {
      setError('Failed to fetch administrative ledger.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [actionFilter, roleFilter]);

  const handleRoleSwitch = async (role: 'Admin' | 'Supervisor' | 'Analyst') => {
    try {
      const res = await switchRole(role);
      localStorage.setItem('satsa_token', res.data.access_token);
      localStorage.setItem('satsa_role', role);
      setActiveRoleMsg(`Active user session changed to: ${role} (${res.data.user?.full_name || role})`);
      setTimeout(() => setActiveRoleMsg(null), 3000);
      fetchData();
    } catch (err) {
      alert('Failed to switch role session.');
    }
  };

  const filteredLogs = auditLogs.filter((log) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      log.action.toLowerCase().includes(q) ||
      (log.username && log.username.toLowerCase().includes(q)) ||
      (log.target_entity && log.target_entity.toLowerCase().includes(q)) ||
      (log.log_id && log.log_id.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2.5">
            <Lock className="text-cyan-400" size={24} />
            System Administration & Audit Ledger
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Role-based access enforcement, operator authentication, and immutable audit logs under NCIIPC/NTRO compliance
          </p>
        </div>

        <button
          onClick={fetchData}
          className="px-3 py-1.5 rounded-xl text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors"
        >
          Refresh Audit Trail
        </button>
      </div>

      {activeRoleMsg && (
        <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center gap-2">
          <UserCheck size={16} />
          <span>{activeRoleMsg}</span>
        </div>
      )}

      {/* System Telemetry & Storage Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Environment</span>
          <div className="text-sm font-bold text-emerald-400 mt-1 flex items-center gap-1.5">
            <Server size={14} />
            <span>Air-Gapped</span>
          </div>
          <span className="text-[9px] text-slate-500">Zero Internet Leakage</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Classification</span>
          <div className="text-sm font-bold text-amber-400 mt-1">RESTRICTED</div>
          <span className="text-[9px] text-slate-500">NCIIPC-NTRO Tier 1</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Database Engine</span>
          <div className="text-sm font-bold text-slate-200 mt-1 flex items-center gap-1.5">
            <Database size={14} className="text-cyan-400" />
            <span>DuckDB Local</span>
          </div>
          <span className="text-[9px] text-slate-500">In-Memory Analytical</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Total Audit Records</span>
          <div className="text-sm font-bold font-mono text-cyan-400 mt-1">
            {systemStatus?.counts?.audit_logs || totalLogs}
          </div>
          <span className="text-[9px] text-slate-500">Immutable Ledger</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Supervisory Findings</span>
          <div className="text-sm font-bold font-mono text-slate-200 mt-1">
            {systemStatus?.counts?.findings || 0}
          </div>
          <span className="text-[9px] text-slate-500">Across 6 Engines</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-[10px] font-mono text-slate-500 uppercase">Active Operators</span>
          <div className="text-sm font-bold font-mono text-slate-200 mt-1">
            {demoUsers.length || 3} Roles
          </div>
          <span className="text-[9px] text-slate-500">RBAC Seeded</span>
        </div>
      </div>

      {/* RBAC Operators & Demo Switcher */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-xl">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-2">
          <Users className="text-cyan-400" size={16} />
          Role-Based Access Control (RBAC) Accounts & Instant Simulator
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Switch active operational roles dynamically to verify permission boundaries between Read-Only Analysts,
          Adjudicating Supervisors, and SOC Administrators.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {/* Admin Card */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-purple-500/30 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-purple-300 font-mono">Role: Admin</span>
                <span className="text-[9px] px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono">
                  Full Authority
                </span>
              </div>
              <p className="text-xs text-slate-200 font-semibold mt-1">National SOC Administrator</p>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">admin@satsa.gov.in</p>
              <ul className="text-[10px] text-slate-400 space-y-1 mt-2.5">
                <li>• Ingest raw CSE datasets & normalize</li>
                <li>• Run supervisory analytics engines</li>
                <li>• Import Threat Intel STIX bundles</li>
                <li>• Manage operators, rules, & view audit ledger</li>
              </ul>
            </div>
            <button
              onClick={() => handleRoleSwitch('Admin')}
              className="w-full py-1.5 rounded-lg text-xs font-semibold bg-purple-600/30 border border-purple-500/40 text-purple-300 hover:bg-purple-600/50 transition-colors"
            >
              Simulate Admin Session
            </button>
          </div>

          {/* Supervisor Card */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-cyan-500/30 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyan-300 font-mono">Role: Supervisor</span>
                <span className="text-[9px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
                  Adjudication
                </span>
              </div>
              <p className="text-xs text-slate-200 font-semibold mt-1">Senior Supervisory Officer</p>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">supervisor@satsa.gov.in</p>
              <ul className="text-[10px] text-slate-400 space-y-1 mt-2.5">
                <li>• Triage findings in Review Queue</li>
                <li>• Mark Valid / False Positive / Needs Data</li>
                <li>• Authorize rule & threshold tuning changes</li>
                <li>• Export regulatory PDF audit dossiers</li>
              </ul>
            </div>
            <button
              onClick={() => handleRoleSwitch('Supervisor')}
              className="w-full py-1.5 rounded-lg text-xs font-semibold bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-600/50 transition-colors"
            >
              Simulate Supervisor Session
            </button>
          </div>

          {/* Analyst Card */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-700 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 font-mono">Role: Analyst</span>
                <span className="text-[9px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">Read-Only</span>
              </div>
              <p className="text-xs text-slate-200 font-semibold mt-1">Cyber Triage Analyst</p>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">analyst@satsa.gov.in</p>
              <ul className="text-[10px] text-slate-400 space-y-1 mt-2.5">
                <li>• Explore Attack Path visual graphs</li>
                <li>• Inspect telemetry evidence & drill-down</li>
                <li>• Read-only access; cannot submit reviews</li>
                <li>• Export CSV findings datasets</li>
              </ul>
            </div>
            <button
              onClick={() => handleRoleSwitch('Analyst')}
              className="w-full py-1.5 rounded-lg text-xs font-semibold bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Simulate Analyst Session
            </button>
          </div>
        </div>
      </div>

      {/* Audit Log Filter Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {/* Action Filter */}
          <div className="flex items-center gap-1.5 font-mono">
            <span className="text-slate-500 text-[11px] uppercase">Action:</span>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Actions</option>
              <option value="REVIEW_SUBMITTED">REVIEW_SUBMITTED</option>
              <option value="APPROVE_RULE_TUNING">APPROVE_RULE_TUNING</option>
              <option value="USER_LOGIN">USER_LOGIN</option>
              <option value="ROLE_SWITCH">ROLE_SWITCH</option>
              <option value="EXPORT_REPORT">EXPORT_REPORT</option>
              <option value="RUN_ANALYTICS">RUN_ANALYTICS</option>
              <option value="INGEST_BATCH">INGEST_BATCH</option>
            </select>
          </div>

          {/* Role Filter */}
          <div className="flex items-center gap-1.5 font-mono">
            <span className="text-slate-500 text-[11px] uppercase">Role:</span>
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Roles</option>
              <option value="Admin">Admin</option>
              <option value="Supervisor">Supervisor</option>
              <option value="Analyst">Analyst</option>
              <option value="System">System</option>
            </select>
          </div>
        </div>

        {/* Search Input */}
        <div className="relative min-w-[240px]">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search action, user, target ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Main Audit Log Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs">
            Loading immutable audit logs...
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs">
            No audit records match the current query criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/80 font-mono text-slate-400 uppercase text-[11px] tracking-wider">
                  <th className="py-3 px-4">Log ID</th>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Operator / Role</th>
                  <th className="py-3 px-4">Target Entity</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredLogs.map((log) => (
                  <tr
                    key={log.log_id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedLog(selectedLog?.log_id === log.log_id ? null : log)}
                  >
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {log.log_id}
                    </td>

                    <td className="py-3 px-4 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                      {log.timestamp}
                    </td>

                    <td className="py-3 px-4 font-mono whitespace-nowrap">
                      <span className="font-bold text-cyan-400">{log.action}</span>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px]">
                      <span className="text-slate-200 font-semibold">{log.username || 'system'}</span>
                      <span className="text-slate-500 ml-1.5">({log.role || 'System'})</span>
                    </td>

                    <td className="py-3 px-4 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                      {log.target_entity || '-'}
                    </td>

                    <td className="py-3 px-4 font-mono text-[11px] text-slate-500 whitespace-nowrap">
                      {log.ip_address}
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedLog(selectedLog?.log_id === log.log_id ? null : log);
                        }}
                        className="px-2.5 py-1 text-[11px] font-mono rounded bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
                      >
                        {selectedLog?.log_id === log.log_id ? 'Hide' : 'Inspect'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Expanded Details Drawer / Modal */}
      {selectedLog && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-700 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs font-bold text-cyan-400">
              Audit Payload Inspection: {selectedLog.log_id} ({selectedLog.action})
            </span>
            <button
              onClick={() => setSelectedLog(null)}
              className="text-slate-400 hover:text-white text-xs font-mono"
            >
              Close
            </button>
          </div>
          <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto max-h-48">
            {JSON.stringify(selectedLog.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
