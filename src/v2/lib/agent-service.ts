import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { calculateV2Scores } from './scoring.ts';
import {
  V2AgentRecord,
  V2AuditLog,
  V2Finding,
  V2ScanJob,
  V2ScanResult
} from '../types/v2.ts';

interface StoredAgentInternal extends V2AgentRecord {
  tokenHash: string;
}

interface V2ServerState {
  agents: StoredAgentInternal[];
  auditLogs: V2AuditLog[];
}

const STATE_FILE = path.join('/tmp', 'site-sentinel-v2-state.json');

function loadState(): V2ServerState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = fs.readFileSync(STATE_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as V2ServerState;
      return {
        agents: Array.isArray(parsed.agents) ? parsed.agents : [],
        auditLogs: Array.isArray(parsed.auditLogs) ? parsed.auditLogs : []
      };
    }
  } catch {
    // Fallback to clean state
  }
  return { agents: [], auditLogs: [] };
}

function saveState(state: V2ServerState) {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  } catch {
    // Non-fatal in ephemeral containers
  }
}

const serverState: V2ServerState = loadState();
const scanJobs = new Map<string, V2ScanJob>();

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function toPublicAgent(agent: StoredAgentInternal): V2AgentRecord {
  const { tokenHash: _omit, ...pub } = agent;
  // Mark active agents stale if no heartbeat for > 10 minutes
  if (pub.status === 'active' && pub.lastHeartbeatAt) {
    const ageMs = Date.now() - new Date(pub.lastHeartbeatAt).getTime();
    if (ageMs > 10 * 60 * 1000) {
      return { ...pub, status: 'stale' };
    }
  }
  return pub;
}

export function appendV2AuditLog(entry: Omit<V2AuditLog, 'id' | 'createdAt'>): V2AuditLog {
  const log: V2AuditLog = {
    ...entry,
    id: `v2log_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    createdAt: new Date().toISOString()
  };
  serverState.auditLogs.unshift(log);
  if (serverState.auditLogs.length > 200) {
    serverState.auditLogs = serverState.auditLogs.slice(0, 200);
  }
  saveState(serverState);
  return log;
}

export function listV2AuditLogs(userId?: string): V2AuditLog[] {
  const targetUser = userId && userId.trim() ? userId : 'anonymous';
  return serverState.auditLogs.filter((l) => l.userId === targetUser).slice(0, 50);
}

export function registerV2Agent(params: {
  userId: string;
  name: string;
  environment: string;
}): { agent: V2AgentRecord; plainTextToken: string } {
  const rawSecret = crypto.randomBytes(24).toString('hex');
  const plainTextToken = `ss_agent_${rawSecret}`;
  const tokenPrefix = `${plainTextToken.slice(0, 15)}...${plainTextToken.slice(-4)}`;

  const internal: StoredAgentInternal = {
    id: `agent_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    userId: params.userId || 'anonymous',
    name: params.name.trim().slice(0, 80),
    environment: params.environment.trim().slice(0, 40) || 'production',
    status: 'registered',
    tokenPrefix,
    tokenHash: hashToken(plainTextToken),
    createdAt: new Date().toISOString()
  };

  serverState.agents.unshift(internal);
  saveState(serverState);

  appendV2AuditLog({
    userId: internal.userId,
    action: 'agent.register',
    target: internal.name,
    mode: 'agent',
    status: 'completed',
    detail: `Registered least-privilege agent (${internal.environment}) with prefix ${tokenPrefix}`
  });

  return {
    agent: toPublicAgent(internal),
    plainTextToken
  };
}

export function listV2Agents(userId?: string): V2AgentRecord[] {
  const targetUser = userId && userId.trim() ? userId : 'anonymous';
  return serverState.agents.filter((a) => a.userId === targetUser).map(toPublicAgent);
}

export function revokeV2Agent(agentId: string, userId?: string): V2AgentRecord | null {
  const agent = serverState.agents.find((a) => a.id === agentId);
  if (!agent) return null;
  const requester = userId && userId.trim() ? userId : 'anonymous';
  if (agent.userId !== requester) {
    return null;
  }
  agent.status = 'revoked';
  saveState(serverState);

  appendV2AuditLog({
    userId: userId || agent.userId,
    action: 'agent.revoke',
    target: agent.name,
    mode: 'agent',
    status: 'completed',
    detail: `Revoked agent credential ${agent.tokenPrefix}`
  });

  return toPublicAgent(agent);
}

export function authenticateAgentToken(bearerHeader?: string): StoredAgentInternal | null {
  if (!bearerHeader || !bearerHeader.startsWith('Bearer ')) return null;
  const token = bearerHeader.slice('Bearer '.length).trim();
  if (!token.startsWith('ss_agent_')) return null;

  const incomingHash = hashToken(token);
  const match = serverState.agents.find((a) => {
    if (a.tokenHash.length !== incomingHash.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a.tokenHash), Buffer.from(incomingHash));
  });

  if (!match || match.status === 'revoked') {
    return null;
  }
  return match;
}

export function recordAgentHeartbeat(
  agent: StoredAgentInternal,
  payload: { hostname?: string; osInfo?: string; agentVersion?: string }
): V2AgentRecord {
  agent.status = 'active';
  agent.lastHeartbeatAt = new Date().toISOString();
  if (payload.hostname) agent.hostname = String(payload.hostname).slice(0, 128);
  if (payload.osInfo) agent.osInfo = String(payload.osInfo).slice(0, 128);
  if (payload.agentVersion) agent.agentVersion = String(payload.agentVersion).slice(0, 32);
  saveState(serverState);
  return toPublicAgent(agent);
}

function sanitizeEvidenceSnippet(val?: string): string | undefined {
  if (!val) return undefined;
  return String(val)
    .replace(/ss_agent_[a-zA-Z0-9]+/g, 'ss_agent_****')
    .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA****')
    .slice(0, 200);
}

export function ingestAgentReport(
  agent: StoredAgentInternal,
  payload: {
    hostname: string;
    osPlatform: string;
    runtimeVersion: string;
    checkedPaths: number;
    inspectedChecks?: Array<{
      id: string;
      name: string;
      status: 'passed' | 'failed' | 'warning' | 'skipped';
      detail?: string;
    }>;
    findings: Array<Omit<V2Finding, 'id'>>;
  }
): V2ScanResult {
  const nowIso = new Date().toISOString();
  const normalizedFindings: V2Finding[] = (payload.findings || []).slice(0, 100).map((f, idx) => {
    const severity = (['critical', 'high', 'medium', 'low', 'info'].includes(f.severity) ? f.severity : 'info') as V2Finding['severity'];
    const confidence = (['confirmed', 'probable', 'inconclusive'].includes(f.confidence) ? f.confidence : 'confirmed') as V2Finding['confidence'];
    const accuracyTier = f.accuracyTier || (confidence === 'confirmed' ? 'VERIFIED' : confidence === 'probable' ? 'SUSPECTED' : 'NOT_VERIFIED');
    const cweNum = f.cwe ? f.cwe.replace(/[^0-9]/g, '') : '';
    return {
      id: `v2agent_${idx + 1}`,
      checkId: f.checkId ? String(f.checkId).slice(0, 80) : `agent_check_${idx + 1}`,
      title: String(f.title || 'Host Posture Finding').slice(0, 160),
      severity,
      category: String(f.category || 'Code & Secrets').slice(0, 64),
      confidence,
      accuracyTier,
      detectionMethod: f.detectionMethod ? String(f.detectionMethod).slice(0, 120) : 'Read-Only Host Configuration Agent Inspection',
      affectedResource: String(f.affectedResource || f.evidence?.file || payload.hostname || 'host').slice(0, 200),
      observedAt: f.observedAt || nowIso,
      reference: f.reference || (cweNum ? `https://cwe.mitre.org/data/definitions/${cweNum}.html` : undefined),
      status: 'unresolved',
      plainSummary: f.plainSummary ? String(f.plainSummary).slice(0, 400) : undefined,
      description: String(f.description || '').slice(0, 600),
      impact: String(f.impact || '').slice(0, 400),
      verifySteps: f.verifySteps ? String(f.verifySteps).slice(0, 400) : undefined,
      remediation: String(f.remediation || '').slice(0, 600),
      evidence: {
        ...(f.evidence || {}),
        snippet: sanitizeEvidenceSnippet(f.evidence?.snippet),
        detail: sanitizeEvidenceSnippet(f.evidence?.detail)
      },
      cwe: f.cwe
    };
  });

  const checks = Array.isArray(payload.inspectedChecks) && payload.inspectedChecks.length > 0
    ? payload.inspectedChecks.slice(0, 100).map((c) => ({
        id: String(c.id || 'check').slice(0, 80),
        name: String(c.name || 'Host Check').slice(0, 120),
        status: (['passed', 'failed', 'warning', 'skipped'].includes(c.status) ? c.status : 'skipped') as
          | 'passed'
          | 'failed'
          | 'warning'
          | 'skipped',
        detail: c.detail ? sanitizeEvidenceSnippet(String(c.detail)) : undefined
      }))
    : [
        {
          id: 'agent_config_scan',
          name: 'Host Configuration Files Inspection',
          status: (Number(payload.checkedPaths) > 0 ? 'passed' : 'skipped') as 'passed' | 'skipped',
          detail:
            Number(payload.checkedPaths) > 0
              ? `Checked ${Number(payload.checkedPaths)} path(s)`
              : 'No target paths or check metadata reported by agent'
        }
      ];

  const coverage = {
    totalChecks: checks.length,
    executedChecks: checks.filter((c) => c.status !== 'skipped').length,
    passedChecks: checks.filter((c) => c.status === 'passed').length,
    failedChecks: checks.filter((c) => c.status === 'failed' || c.status === 'warning').length,
    skippedChecks: checks.filter((c) => c.status === 'skipped').length,
    checks
  };

  const scoring = calculateV2Scores(normalizedFindings, coverage);
  const reportId = `v2agent_scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

  agent.status = 'active';
  agent.lastHeartbeatAt = nowIso;
  agent.hostname = String(payload.hostname || agent.hostname || 'unknown').slice(0, 128);
  agent.lastReportScore = scoring.score;
  agent.lastReportId = reportId;
  saveState(serverState);

  appendV2AuditLog({
    userId: agent.userId,
    action: 'agent.report',
    target: agent.hostname || agent.name,
    mode: 'agent',
    status: 'completed',
    detail: `Ingested read-only agent audit report (score ${scoring.score}/100, ${coverage.executedChecks}/${coverage.totalChecks} checks executed, ${scoring.deduplicatedFindings.length} findings)`
  });

  return {
    id: reportId,
    userId: agent.userId,
    version: 'v2',
    mode: 'agent',
    target: `${agent.name} (${agent.hostname})`,
    hostname: agent.hostname,
    score: scoring.score,
    grade: scoring.grade,
    durationMs: 0,
    createdAt: nowIso,
    authorizedAttestation: true,
    technologies: [
      {
        name: payload.osPlatform || 'Linux/Host',
        category: 'server',
        version: payload.runtimeVersion,
        confidence: 'confirmed',
        evidence: 'Reported by Site Sentinel Agent'
      }
    ],
    findings: scoring.deduplicatedFindings,
    categoryScores: scoring.categoryScores,
    summary: scoring.summary,
    coverage,
    scoreBreakdown: scoring.scoreBreakdown,
    agentDetails: {
      agentId: agent.id,
      agentName: agent.name,
      environment: agent.environment,
      hostname: agent.hostname || 'unknown',
      osPlatform: payload.osPlatform || 'unknown',
      runtimeVersion: payload.runtimeVersion || process.version,
      checkedPaths: Number(payload.checkedPaths) || 0,
      inspectedChecks: checks
    }
  };
}

export function createV2ScanJob(): V2ScanJob {
  const job: V2ScanJob = {
    jobId: `v2job_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    status: 'queued',
    progress: 0,
    stage: 'Queued',
    pagesCrawled: 0,
    totalDiscovered: 0,
    createdAt: new Date().toISOString()
  };
  scanJobs.set(job.jobId, job);
  // Keep job store bounded
  if (scanJobs.size > 100) {
    const oldestKey = scanJobs.keys().next().value;
    if (oldestKey) scanJobs.delete(oldestKey);
  }
  return job;
}

export function updateV2ScanJob(jobId: string, patch: Partial<V2ScanJob>) {
  const existing = scanJobs.get(jobId);
  if (!existing) return;
  scanJobs.set(jobId, { ...existing, ...patch });
}

export function getV2ScanJob(jobId: string): V2ScanJob | undefined {
  return scanJobs.get(jobId);
}
