import express, { Request, Response } from 'express';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import { executeUniversalUrlScan } from '../lib/url-crawler.ts';
import { analyzeZipArchive, ZIP_LIMITS } from '../lib/zip-analyzer.ts';
import {
  appendV2AuditLog,
  authenticateAgentToken,
  createV2ScanJob,
  getV2ScanJob,
  ingestAgentReport,
  listV2Agents,
  listV2AuditLogs,
  recordAgentHeartbeat,
  registerV2Agent,
  revokeV2Agent,
  updateV2ScanJob
} from '../lib/agent-service.ts';
import { V2ScanResult } from '../types/v2.ts';

dotenv.config();

const router = express.Router();
router.use(express.json({ limit: '2mb' }));

// Rate limiter for V2 scanning endpoints
const v2RateMap = new Map<string, number[]>();
function isV2RateLimited(ip: string, maxRequests = 20, windowMs = 60000): boolean {
  const now = Date.now();
  const hits = (v2RateMap.get(ip) || []).filter((t) => now - t < windowMs);
  if (hits.length >= maxRequests) {
    v2RateMap.set(ip, hits);
    return true;
  }
  hits.push(now);
  v2RateMap.set(ip, hits);
  return false;
}

// Memory-only upload for ZIP archives (15 MB limit)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: ZIP_LIMITS.maxCompressedBytes,
    files: 1
  }
});

// Keep recent agent-submitted reports in memory for dashboard synchronization
const recentAgentReports: V2ScanResult[] = [];

router.get('/health', (_req: Request, res: Response) => {
  res.json({
    service: 'Site Sentinel V2 API',
    status: 'operational',
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY)
  });
});

/**
 * POST /api/v2/scan/url
 * Universal URL scanner & controlled crawler (sync or async job mode)
 */
router.post('/scan/url', async (req: Request, res: Response) => {
  const clientIp = req.ip || req.socket.remoteAddress || 'local';
  if (isV2RateLimited(clientIp, 20, 60000)) {
    res.setHeader('Retry-After', '60');
    res.status(429).json({ error: 'Rate limit exceeded. Maximum 20 V2 scans per minute.' });
    return;
  }

  const { targetUrl, maxPages, maxDepth, scope, authorizedAttestation, userId, async: asyncMode } = req.body || {};

  if (!targetUrl || typeof targetUrl !== 'string' || targetUrl.length > 512) {
    res.status(400).json({ error: 'A valid targetUrl (<= 512 chars) is required.' });
    return;
  }

  if (!authorizedAttestation) {
    appendV2AuditLog({
      userId: userId || 'anonymous',
      action: 'scan.url',
      target: targetUrl,
      mode: 'url',
      status: 'blocked',
      detail: 'Blocked: explicit authorization attestation not confirmed.'
    });
    res.status(400).json({ error: 'Authorization confirmation is required before scanning any target.' });
    return;
  }

  const parsedScope = scope === 'include-subdomains' ? 'include-subdomains' : 'same-origin';
  const parsedMaxPages = typeof maxPages === 'number' ? Math.min(25, Math.max(1, maxPages)) : 10;
  const parsedMaxDepth = typeof maxDepth === 'number' ? Math.min(3, Math.max(1, maxDepth)) : 2;

  if (asyncMode) {
    const job = createV2ScanJob();
    updateV2ScanJob(job.jobId, { status: 'running', progress: 2, stage: 'Initializing V2 crawler' });

    executeUniversalUrlScan(targetUrl, {
      userId: userId || 'anonymous',
      maxPages: parsedMaxPages,
      maxDepth: parsedMaxDepth,
      scope: parsedScope,
      authorizedAttestation: true,
      onProgress: (update) => {
        updateV2ScanJob(job.jobId, {
          status: 'running',
          progress: update.progress,
          stage: update.stage,
          pagesCrawled: update.pagesCrawled,
          totalDiscovered: update.totalDiscovered
        });
      }
    })
      .then((result) => {
        updateV2ScanJob(job.jobId, {
          status: 'completed',
          progress: 100,
          stage: 'Scan complete',
          pagesCrawled: result.urlDetails?.assets.pages.length || 1,
          result
        });
        appendV2AuditLog({
          userId: userId || 'anonymous',
          action: 'scan.url',
          target: result.target,
          mode: 'url',
          status: 'completed',
          detail: `Completed URL crawl (${result.urlDetails?.assets.pages.length || 1} pages, score ${result.score}/100)`
        });
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        updateV2ScanJob(job.jobId, {
          status: 'failed',
          stage: 'Failed',
          error: msg
        });
        appendV2AuditLog({
          userId: userId || 'anonymous',
          action: 'scan.url',
          target: targetUrl,
          mode: 'url',
          status: msg.includes('SSRF') || msg.includes('Target verification') ? 'blocked' : 'error',
          detail: msg
        });
      });

    res.status(202).json({ jobId: job.jobId, status: 'running' });
    return;
  }

  try {
    const result = await executeUniversalUrlScan(targetUrl, {
      userId: userId || 'anonymous',
      maxPages: parsedMaxPages,
      maxDepth: parsedMaxDepth,
      scope: parsedScope,
      authorizedAttestation: true
    });

    appendV2AuditLog({
      userId: userId || 'anonymous',
      action: 'scan.url',
      target: result.target,
      mode: 'url',
      status: 'completed',
      detail: `Completed URL crawl (${result.urlDetails?.assets.pages.length || 1} pages, score ${result.score}/100)`
    });

    res.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const isClientBlocked =
      msg.includes('Target verification failed') ||
      msg.includes('SSRF Block') ||
      msg.includes('Malformed URL') ||
      msg.includes('Only standard web ports') ||
      msg.includes('Only HTTP and HTTPS');

    appendV2AuditLog({
      userId: userId || 'anonymous',
      action: 'scan.url',
      target: targetUrl,
      mode: 'url',
      status: isClientBlocked ? 'blocked' : 'error',
      detail: msg
    });

    res.status(isClientBlocked ? 400 : 502).json({ error: msg });
  }
});

/**
 * GET /api/v2/scan/jobs/:jobId
 */
router.get('/scan/jobs/:jobId', (req: Request, res: Response) => {
  const job = getV2ScanJob(String(req.params.jobId));
  if (!job) {
    res.status(404).json({ error: 'Scan job not found or expired.' });
    return;
  }
  res.json(job);
});

/**
 * POST /api/v2/scan/zip
 * Hardened ZIP archive static analysis
 */
router.post('/scan/zip', (req: Request, res: Response) => {
  const clientIp = req.ip || req.socket.remoteAddress || 'local';
  if (isV2RateLimited(clientIp, 15, 60000)) {
    res.setHeader('Retry-After', '60');
    res.status(429).json({ error: 'Rate limit exceeded for ZIP uploads.' });
    return;
  }

  upload.single('archive')(req, res, async (uploadErr: unknown) => {
    if (uploadErr) {
      const msg = uploadErr instanceof Error ? uploadErr.message : 'File upload failed.';
      res.status(400).json({ error: msg });
      return;
    }

    const file = req.file;
    const userId = String(req.body?.userId || 'anonymous');
    const attestation = req.body?.authorizedAttestation === 'true' || req.body?.authorizedAttestation === true;

    if (!file) {
      res.status(400).json({ error: 'A .zip archive file field named "archive" is required.' });
      return;
    }

    if (!file.originalname.toLowerCase().endsWith('.zip')) {
      res.status(400).json({ error: 'Only .zip archives are accepted.' });
      return;
    }

    if (!attestation) {
      res.status(400).json({ error: 'Authorization confirmation is required before analyzing source archives.' });
      return;
    }

    try {
      const result = await analyzeZipArchive(file.buffer, file.originalname, {
        userId,
        authorizedAttestation: true
      });

      appendV2AuditLog({
        userId,
        action: 'scan.zip',
        target: file.originalname,
        mode: 'zip',
        status: 'completed',
        detail: `Analyzed ${result.zipDetails?.analyzedFiles || 0} files (score ${result.score}/100, ${result.findings.length} findings)`
      });

      res.json(result);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      appendV2AuditLog({
        userId,
        action: 'scan.zip',
        target: file.originalname,
        mode: 'zip',
        status: msg.includes('Security Block') ? 'blocked' : 'error',
        detail: msg
      });
      res.status(400).json({ error: msg });
    }
  });
});

/**
 * Agent Endpoints
 */
router.post('/agent/register', (req: Request, res: Response) => {
  const { name, environment, userId } = req.body || {};
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    res.status(400).json({ error: 'Agent name (at least 2 characters) is required.' });
    return;
  }

  const created = registerV2Agent({
    userId: typeof userId === 'string' ? userId : 'anonymous',
    name,
    environment: typeof environment === 'string' ? environment : 'production'
  });

  res.status(201).json(created);
});

router.get('/agent/list', (req: Request, res: Response) => {
  const userId = typeof req.query.userId === 'string' ? req.query.userId : undefined;
  res.json({ agents: listV2Agents(userId) });
});

router.post('/agent/revoke', (req: Request, res: Response) => {
  const { agentId, userId } = req.body || {};
  if (!agentId || typeof agentId !== 'string') {
    res.status(400).json({ error: 'agentId is required.' });
    return;
  }
  const updated = revokeV2Agent(agentId, typeof userId === 'string' ? userId : undefined);
  if (!updated) {
    res.status(404).json({ error: 'Agent not found or not owned by user.' });
    return;
  }
  res.json({ agent: updated });
});

router.post('/agent/heartbeat', (req: Request, res: Response) => {
  const agent = authenticateAgentToken(req.headers.authorization);
  if (!agent) {
    res.status(401).json({ error: 'Invalid or revoked agent Bearer token.' });
    return;
  }
  const updated = recordAgentHeartbeat(agent, req.body || {});
  res.json({ ok: true, agent: updated });
});

router.post('/agent/report', (req: Request, res: Response) => {
  const agent = authenticateAgentToken(req.headers.authorization);
  if (!agent) {
    res.status(401).json({ error: 'Invalid or revoked agent Bearer token.' });
    return;
  }
  const body = req.body || {};
  const result = ingestAgentReport(agent, {
    hostname: String(body.hostname || 'unknown-host'),
    osPlatform: String(body.osPlatform || 'linux'),
    runtimeVersion: String(body.runtimeVersion || 'unknown'),
    checkedPaths: Number(body.checkedPaths) || 0,
    inspectedChecks: Array.isArray(body.inspectedChecks) ? body.inspectedChecks : undefined,
    findings: Array.isArray(body.findings) ? body.findings : []
  });
  recentAgentReports.unshift(result);
  if (recentAgentReports.length > 50) recentAgentReports.pop();
  res.status(201).json(result);
});

router.get('/agent/reports', (req: Request, res: Response) => {
  const targetUser = typeof req.query.userId === 'string' && req.query.userId.trim() ? req.query.userId : 'anonymous';
  const filtered = recentAgentReports.filter((r) => r.userId === targetUser);
  res.json({ reports: filtered });
});

router.get('/agent/script', (_req: Request, res: Response) => {
  const scriptPath = path.join(process.cwd(), 'src', 'v2', 'agent', 'site-sentinel-agent.mjs');
  if (!fs.existsSync(scriptPath)) {
    res.status(404).json({ error: 'Agent script file not found.' });
    return;
  }
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="site-sentinel-agent.mjs"');
  res.send(fs.readFileSync(scriptPath, 'utf-8'));
});

router.get('/audit-logs', (req: Request, res: Response) => {
  const userId = typeof req.query.userId === 'string' ? req.query.userId : undefined;
  res.json({ logs: listV2AuditLogs(userId) });
});

/**
 * POST /api/v2/ai/explain
 * Optional Gemini explanation & remediation helper for V2 findings
 */
router.post('/ai/explain', async (req: Request, res: Response) => {
  const { finding, target, mode } = req.body || {};
  if (!finding || !finding.title) {
    res.status(400).json({ error: 'Finding payload is required.' });
    return;
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(503).json({
      error: 'Gemini AI API key is not configured on this server. Built-in remediation instructions remain available.'
    });
    return;
  }

  try {
    const ai = new GoogleGenAI({ apiKey });
    const prompt = `You are a Principal Application Security Engineer.
Explain and provide a defensive mitigation recommendation strictly based ONLY on the observed finding below from Site Sentinel V2.

CRITICAL ACCURACY RULES:
- Do NOT invent new findings, files, URLs, CVEs, or unverified evidence beyond the payload.
- Do NOT upgrade severity or claim the issue is verified unless accuracyTier is VERIFIED.
- NEVER state that a fix is verified without re-scanning the target.
- Present all advice as an AI Recommendation to verify independently before applying.

Observed Finding:
- Scan Mode: ${mode || 'url'}
- Target: ${target || 'application'}
- Check ID: ${finding.checkId || finding.id || 'N/A'}
- Accuracy Tier: ${finding.accuracyTier || finding.confidence || 'NOT_SPECIFIED'}
- Detection Method: ${finding.detectionMethod || 'Automated Check'}
- Title: ${finding.title}
- Severity: ${finding.severity}
- Category: ${finding.category}
- Evidence: ${JSON.stringify(finding.evidence || {})}
- Description: ${finding.description || ''}

Respond cleanly in Markdown with:
1. Observed Evidence & Root Cause
2. Recommended Patch / Configuration Example (Verify Before Applying)
3. Verification & Re-Scan Steps`;

    const models = ['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest'];
    for (const model of models) {
      try {
        const response = await ai.models.generateContent({ model, contents: prompt });
        if (response?.text) {
          res.json({
            explanation: response.text,
            isRecommendation: true,
            disclaimer: 'AI Recommendation — Verify Before Applying. Based strictly on observed scan evidence; re-scan to confirm remediation.'
          });
          return;
        }
      } catch {
        // Fallback to next alias
      }
    }
    res.status(503).json({ error: 'AI explanation service temporarily unavailable.' });
  } catch (err: unknown) {
    res.status(503).json({ error: err instanceof Error ? err.message : 'AI explanation failed.' });
  }
});

export default router;
