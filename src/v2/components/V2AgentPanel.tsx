import React, { useState, useEffect, useCallback } from 'react';
import {
  Server,
  Plus,
  Download,
  Copy,
  Check,
  ShieldOff,
  RefreshCw,
  AlertTriangle,
  ShieldCheck
} from 'lucide-react';
import { V2AgentRecord, V2ScanResult } from '../types/v2';

interface V2AgentPanelProps {
  userId?: string;
  onSelectReport: (report: V2ScanResult) => void;
  onSyncAgentToFirestore?: (agent: V2AgentRecord) => Promise<void>;
  onSyncReportToFirestore?: (report: V2ScanResult) => Promise<void>;
  onAgentsChanged?: (agents: V2AgentRecord[]) => void;
}

export const V2AgentPanel: React.FC<V2AgentPanelProps> = ({
  userId,
  onSelectReport,
  onSyncAgentToFirestore,
  onSyncReportToFirestore,
  onAgentsChanged
}) => {
  const [agents, setAgents] = useState<V2AgentRecord[]>([]);
  const [reports, setReports] = useState<V2ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [registering, setRegistering] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAgentData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const q = userId ? `?userId=${encodeURIComponent(userId)}` : '';
      const [agentsRes, reportsRes] = await Promise.all([
        fetch(`/api/v2/agent/list${q}`),
        fetch(`/api/v2/agent/reports${q}`)
      ]);
      if (agentsRes.ok) {
        const data = await agentsRes.json();
        const loadedAgents: V2AgentRecord[] = data.agents || [];
        setAgents(loadedAgents);
        onAgentsChanged?.(loadedAgents);
      }
      if (reportsRes.ok) {
        const rData = await reportsRes.json();
        const loadedReports: V2ScanResult[] = rData.reports || [];
        setReports(loadedReports);
        if (onSyncReportToFirestore && loadedReports.length > 0) {
          for (const rep of loadedReports.slice(0, 5)) {
            onSyncReportToFirestore(rep).catch(() => {});
          }
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load agents.');
    } finally {
      setLoading(false);
    }
  }, [userId, onSyncReportToFirestore, onAgentsChanged]);

  useEffect(() => {
    fetchAgentData();
  }, [fetchAgentData]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || registering) return;
    setRegistering(true);
    setError(null);
    setNewToken(null);

    try {
      const res = await fetch('/api/v2/agent/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          environment,
          userId: userId || 'anonymous'
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Agent registration failed.');

      setNewToken(data.plainTextToken);
      setName('');
      const updated = [data.agent as V2AgentRecord, ...agents];
      setAgents(updated);
      onAgentsChanged?.(updated);
      if (onSyncAgentToFirestore) {
        onSyncAgentToFirestore(data.agent).catch(() => {});
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Agent registration failed.');
    } finally {
      setRegistering(false);
    }
  };

  const handleRevoke = async (agentId: string) => {
    setError(null);
    try {
      const res = await fetch('/api/v2/agent/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId, userId: userId || 'anonymous' })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Revocation failed.');
      const updated = agents.map((a) => (a.id === agentId ? (data.agent as V2AgentRecord) : a));
      setAgents(updated);
      onAgentsChanged?.(updated);
      if (onSyncAgentToFirestore) {
        onSyncAgentToFirestore(data.agent).catch(() => {});
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke agent.');
    }
  };

  const handleCopyToken = () => {
    if (!newToken) return;
    navigator.clipboard.writeText(newToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';
  const activeCount = agents.filter((a) => a.status === 'active' || a.status === 'registered').length;
  const staleCount = agents.filter((a) => a.status === 'stale').length;
  const revokedCount = agents.filter((a) => a.status === 'revoked').length;

  return (
    <div className="space-y-6">
      {/* Header & Script Download */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold text-white">Authorized Read-Only Server Agents</h2>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            Run this lightweight script locally on servers you own to check file permissions and environment flags. It sends only read-only security findings back and never grants remote shell or SSH access.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={fetchAgentData}
            className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <a
            href="/api/v2/agent/script"
            download="site-sentinel-agent.mjs"
            className="min-h-[40px] inline-flex items-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            Download Agent Script
          </a>
        </div>
      </div>

      {/* 3-Step Setup Guide & Real Counters */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-white">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            How Server Agent Onboarding Works
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-200">1. Generate a Token</div>
              <p className="text-slate-400">Create a revocable credential scoped only to your account. We store only a one-way SHA-256 hash.</p>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-200">2. Download & Inspect</div>
              <p className="text-slate-400">Download the Node.js script and run it on your server directory—no root permissions or SSH needed.</p>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
              <div className="font-semibold text-slate-200">3. Review or Revoke</div>
              <p className="text-slate-400">Reports appear below automatically. You can revoke any agent token immediately with one click.</p>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="text-xs font-semibold text-white">Agent Fleet Status</div>
          <div className="grid grid-cols-3 gap-2 pt-3 text-center">
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-base font-bold font-mono tabular-nums text-emerald-400">{activeCount}</div>
              <div className="text-[10px] text-slate-400">Active</div>
            </div>
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-base font-bold font-mono tabular-nums text-amber-400">{staleCount}</div>
              <div className="text-[10px] text-slate-400">Stale</div>
            </div>
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-base font-bold font-mono tabular-nums text-rose-400">{revokedCount}</div>
              <div className="text-[10px] text-slate-400">Revoked</div>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Register New Agent */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <h3 className="text-sm font-semibold text-white">Register New Agent Credential</h3>
        <form onSubmit={handleRegister} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Server label (e.g. prod-web-01)"
            required
            className="px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
          <select
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            className="px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
          >
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
          </select>
          <button
            type="submit"
            disabled={registering || !name.trim()}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap"
          >
            <Plus className="w-3.5 h-3.5" />
            {registering ? 'Generating...' : 'Generate Revocable Token'}
          </button>
        </form>

        {newToken && (
          <div className="p-4 bg-slate-950 border border-emerald-500/40 rounded-xl space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="font-semibold text-emerald-400 break-words">
                One-Time Agent Token Generated (save now — never shown again)
              </span>
              <button
                type="button"
                onClick={handleCopyToken}
                className="min-h-[36px] inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium shrink-0"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy Token'}
              </button>
            </div>
            <pre className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto break-all whitespace-pre-wrap">
              {newToken}
            </pre>
            <pre className="p-2.5 bg-slate-900/70 border border-slate-800 rounded-lg text-[11px] text-slate-300 font-mono overflow-x-auto">
              {`SENTINEL_SERVER=${origin} SENTINEL_TOKEN=${newToken} node site-sentinel-agent.mjs --target-dir /path/to/app`}
            </pre>
          </div>
        )}
      </div>

      {/* Registered Agents */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <span className="text-sm font-semibold text-white">Registered Agents ({agents.length})</span>
        </div>
        {loading ? (
          <div className="p-6 text-xs text-slate-400">Loading registered agents...</div>
        ) : agents.length === 0 ? (
          <div className="p-8 text-center space-y-2">
            <Server className="w-7 h-7 text-slate-600 mx-auto" />
            <p className="text-xs text-slate-400">No agents registered under this account yet. Generate a token above to connect a host.</p>
          </div>
        ) : (
          <>
            {/* Mobile Stacked Agent Cards (< md) */}
            <div className="md:hidden divide-y divide-slate-800">
              {agents.map((a) => (
                <div key={a.id} className="p-4 space-y-2.5 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="font-semibold text-white break-words">{a.name}</div>
                      {a.hostname && <div className="text-[11px] font-mono text-slate-400 break-all">{a.hostname}</div>}
                    </div>
                    <span
                      className={`font-medium capitalize shrink-0 ${
                        a.status === 'active'
                          ? 'text-emerald-400'
                          : a.status === 'revoked'
                            ? 'text-rose-400'
                            : a.status === 'stale'
                              ? 'text-amber-400'
                              : 'text-sky-400'
                      }`}
                    >
                      {a.status}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400 font-mono">
                    <span className="capitalize text-slate-300">{a.environment}</span>
                    <span>·</span>
                    <span>Prefix: {a.tokenPrefix}</span>
                  </div>
                  <div className="flex items-center justify-between gap-2 pt-1">
                    <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                      Heartbeat: {a.lastHeartbeatAt ? new Date(a.lastHeartbeatAt).toLocaleString() : 'Never'}
                    </span>
                    {a.status !== 'revoked' ? (
                      <button
                        type="button"
                        onClick={() => handleRevoke(a.id)}
                        className="min-h-[36px] inline-flex items-center gap-1 px-2.5 py-1 text-rose-400 hover:bg-rose-500/10 rounded-md transition-colors shrink-0"
                      >
                        <ShieldOff className="w-3.5 h-3.5" />
                        Revoke
                      </button>
                    ) : (
                      <span className="text-slate-500 text-[11px]">Revoked</span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Desktop Agents Table (>= md) */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-5 py-2.5 font-medium">Name</th>
                    <th className="px-4 py-2.5 font-medium">Environment</th>
                    <th className="px-4 py-2.5 font-medium">Token Prefix</th>
                    <th className="px-4 py-2.5 font-medium">Status</th>
                    <th className="px-4 py-2.5 font-medium">Last Heartbeat</th>
                    <th className="px-5 py-2.5 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {agents.map((a) => (
                    <tr key={a.id}>
                      <td className="px-5 py-3 font-medium text-white">
                        <div>{a.name}</div>
                        {a.hostname && <div className="text-[11px] font-mono text-slate-400">{a.hostname}</div>}
                      </td>
                      <td className="px-4 py-3 text-slate-300 capitalize">{a.environment}</td>
                      <td className="px-4 py-3 font-mono text-slate-400">{a.tokenPrefix}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`font-medium capitalize ${
                            a.status === 'active'
                              ? 'text-emerald-400'
                              : a.status === 'revoked'
                                ? 'text-rose-400'
                                : a.status === 'stale'
                                  ? 'text-amber-400'
                                  : 'text-sky-400'
                          }`}
                        >
                          {a.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-slate-400 tabular-nums">
                        {a.lastHeartbeatAt ? new Date(a.lastHeartbeatAt).toLocaleString() : 'Never'}
                      </td>
                      <td className="px-5 py-3 text-right">
                        {a.status !== 'revoked' ? (
                          <button
                            type="button"
                            onClick={() => handleRevoke(a.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-rose-400 hover:bg-rose-500/10 rounded-md transition-colors"
                          >
                            <ShieldOff className="w-3.5 h-3.5" />
                            Revoke
                          </button>
                        ) : (
                          <span className="text-slate-500">Revoked</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {/* Ingested Agent Reports */}
      {reports.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 text-sm font-semibold text-white">
            Recent Agent Posture Reports ({reports.length})
          </div>
          <div className="divide-y divide-slate-800">
            {reports.map((rep) => {
              const checks = rep.agentDetails?.inspectedChecks;
              const passed = checks?.filter((c) => c.status === 'passed').length || 0;
              const failed = checks?.filter((c) => c.status === 'failed').length || 0;
              const skipped = checks?.filter((c) => c.status === 'skipped').length || 0;
              return (
                <div key={rep.id} className="px-4 sm:px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="min-w-0 space-y-1">
                    <div className="text-xs font-medium text-white break-all">{rep.target}</div>
                    <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400 tabular-nums">
                      <span>{new Date(rep.createdAt).toLocaleString()}</span>
                      <span>·</span>
                      <span>{rep.findings.length} findings</span>
                      {checks && checks.length > 0 && (
                        <>
                          <span>·</span>
                          <span className="text-sky-300">
                            {passed} pass / {failed} fail / {skipped} skip
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                    <span className="text-sm font-bold font-mono tabular-nums text-sky-400">
                      {rep.score}/100 ({rep.grade})
                    </span>
                    <button
                      type="button"
                      onClick={() => onSelectReport(rep)}
                      className="min-h-[38px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-white rounded-lg transition-colors whitespace-nowrap"
                    >
                      Inspect Report
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
