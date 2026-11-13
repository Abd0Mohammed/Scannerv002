import express, { Request, Response } from 'express';
import { executeWordPressScan } from '../lib/scanner-engine.ts';
import { safeFetch, validateTargetUrl } from '../lib/ssrf.ts';
import dns from 'node:dns/promises';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const router = express.Router();
router.use(express.json());

// Initialize Gemini Client
const getGeminiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({ apiKey });
};

// In-memory rate limiter: IP -> timestamps
const scanRateLimitMap = new Map<string, number[]>();

function isRateLimited(ip: string, maxRequests: number = 20, windowMs: number = 60000): boolean {
  const now = Date.now();
  const history = (scanRateLimitMap.get(ip) || []).filter(t => now - t < windowMs);
  if (history.length >= maxRequests) {
    scanRateLimitMap.set(ip, history);
    return true;
  }
  history.push(now);
  scanRateLimitMap.set(ip, history);
  return false;
}

/**
 * POST /api/scan
 * Safe, passive WordPress security scan endpoint with SSRF defense
 */
router.post('/scan', async (req: Request, res: Response) => {
  try {
    const clientIp = req.ip || req.socket.remoteAddress || 'local';
    if (isRateLimited(clientIp, 20, 60000)) {
      res.setHeader('Retry-After', '60');
      res.status(429).json({ error: 'Rate limit exceeded. A maximum of 20 scans per minute are allowed.' });
      return;
    }

    const { targetUrl, wpscanApiKey, userId } = req.body;

    if (!targetUrl || typeof targetUrl !== 'string') {
      res.status(400).json({ error: 'Target URL is required.' });
      return;
    }

    if (targetUrl.length > 512) {
      res.status(400).json({ error: 'Target URL exceeds maximum length (512 characters).' });
      return;
    }

    // Run passive WordPress scan
    const result = await executeWordPressScan(targetUrl, {
      userId: userId || 'anonymous',
      wpscanApiKey
    });

    res.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('Scan execution error:', msg);
    if (
      msg.includes('Target verification failed') ||
      msg.includes('SSRF Block') ||
      msg.includes('Malformed URL') ||
      msg.includes('Only standard web ports') ||
      msg.includes('Only HTTP and HTTPS')
    ) {
      res.status(400).json({ error: msg });
      return;
    }
    res.status(502).json({ error: msg });
  }
});

/**
 * POST /api/verify-site
 * Verifies domain ownership via meta tag or DNS TXT
 */
router.post('/verify-site', async (req: Request, res: Response) => {
  try {
    const { targetUrl, token } = req.body;

    if (!targetUrl || !token) {
      res.status(400).json({ error: 'Target URL and verification token are required.' });
      return;
    }

    const validation = await validateTargetUrl(targetUrl);
    if (!validation.valid || !validation.url) {
      res.status(400).json({ error: validation.error || 'Invalid target URL.' });
      return;
    }

    const hostname = validation.url.hostname;
    let verified = false;
    let verificationMethod = '';

    // Method 1: Check HTML Meta Tag <meta name="wp-sentinel-verification" content="...">
    try {
      const pageRes = await safeFetch(`${validation.url.origin}/`, { timeoutMs: 6000 });
      if (pageRes.statusCode === 200) {
        const metaRegex = new RegExp(`<meta[^>]*name=["']wp-sentinel-verification["'][^>]*content=["']${token}["']`, 'i');
        const altMetaRegex = new RegExp(`<meta[^>]*content=["']${token}["'][^>]*name=["']wp-sentinel-verification["']`, 'i');
        if (metaRegex.test(pageRes.body) || altMetaRegex.test(pageRes.body)) {
          verified = true;
          verificationMethod = 'HTML Meta Tag';
        }
      }
    } catch (err) {
      console.warn('Meta tag check failed:', err);
    }

    // Method 2: Check DNS TXT Record
    if (!verified) {
      try {
        const txtRecords = await dns.resolveTxt(hostname);
        const flatRecords = txtRecords.flat();
        for (const record of flatRecords) {
          if (record.includes(token) || record.includes(`wpsentinel=${token}`)) {
            verified = true;
            verificationMethod = 'DNS TXT Record';
            break;
          }
        }
      } catch {
        // DNS TXT resolution error or not set
      }
    }

    if (verified) {
      res.json({
        verified: true,
        method: verificationMethod,
        message: `Successfully verified domain ownership for ${hostname} using ${verificationMethod}!`
      });
    } else {
      res.json({
        verified: false,
        message: `Verification token was not detected in homepage meta tag or DNS TXT records for ${hostname}. Please add <meta name="wp-sentinel-verification" content="${token}"> to your site header and try again.`
      });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: msg });
  }
});

async function generateGeminiWithFallback(ai: GoogleGenAI, prompt: string): Promise<string> {
  const models = ['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest'];
  let lastError: unknown = null;

  for (const model of models) {
    try {
      const response = await ai.models.generateContent({
        model,
        contents: prompt
      });
      if (response && response.text) {
        return response.text;
      }
    } catch (err: unknown) {
      lastError = err;
      console.warn(`Gemini generation failed on model ${model}, attempting fallback if available:`, err instanceof Error ? err.message : String(err));
    }
  }

  throw lastError || new Error('AI generation temporarily unavailable.');
}

/**
 * POST /api/ai/remediate
 * Generates tailored remediation code & deep technical guidance via Gemini
 */
router.post('/ai/remediate', async (req: Request, res: Response) => {
  try {
    const { finding, webServer, hostname } = req.body;

    if (!finding || !finding.title) {
      res.status(400).json({ error: 'Finding payload is required.' });
      return;
    }

    const ai = getGeminiClient();
    if (!ai) {
      res.status(503).json({
        error: 'Gemini AI API key is not configured in this environment. Set GEMINI_API_KEY in environment variables.'
      });
      return;
    }

    const prompt = `You are a Senior WordPress Cybersecurity Engineer and Infrastructure Architect.
Provide an actionable, defensive remediation recommendation strictly based ONLY on the observed scan finding below.

CRITICAL ACCURACY RULES:
- Do NOT invent new vulnerabilities, URLs, files, or unverified evidence not present in the payload.
- Do NOT escalate or alter the finding's severity or claim that an issue is verified if its accuracyTier is LIKELY, SUSPECTED, or NOT_VERIFIED.
- NEVER claim a fix is verified without re-scanning the live target.
- Keep your response clearly framed as an engineering recommendation to verify before applying.

Observed Finding:
- Check ID: ${finding.checkId || finding.id || 'N/A'}
- Accuracy Tier: ${finding.accuracyTier || 'NOT_SPECIFIED'}
- Detection Method: ${finding.detectionMethod || 'Passive Audit'}
- Finding Title: ${finding.title}
- Category: ${finding.category}
- Severity: ${finding.severity}
- Target Hostname: ${hostname || 'example.com'}
- Web Server: ${webServer || 'Apache/Nginx'}
- Impact: ${finding.impact || 'Security risk'}
- Description: ${finding.description || ''}
- Observed Evidence: ${JSON.stringify(finding.evidence || {})}

Please respond in clear Markdown with:
1. **Observed Evidence & Root Cause**: Brief breakdown referencing only the observed evidence above.
2. **Recommended Server/App Mitigation**: Concrete configuration or WordPress filter guidance to review before applying.
3. **Manual Verification & Re-Scan Step**: Read-only curl or testing instruction to verify before re-scanning.`;

    const resultText = await generateGeminiWithFallback(ai, prompt);

    res.json({
      remediationGuide: resultText,
      isRecommendation: true,
      disclaimer: 'AI Recommendation — Verify Before Applying. Generated strictly from observed scan evidence; re-scan target after applying fixes.'
    });
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    console.error('Gemini remediation error:', rawMsg);
    res.status(503).json({
      error: 'SentinAI is currently experiencing high demand. Please try again shortly or refer to the built-in remediation instructions.'
    });
  }
});

/**
 * POST /api/ai/chat
 * Interactive SentinAI Cybersecurity Chat Assistant
 */
router.post('/ai/chat', async (req: Request, res: Response) => {
  try {
    const { message, scanContext } = req.body;

    if (!message || typeof message !== 'string') {
      res.status(400).json({ error: 'Message text is required.' });
      return;
    }

    const ai = getGeminiClient();
    if (!ai) {
      res.status(503).json({
        error: 'Gemini AI API key is not configured in this environment.'
      });
      return;
    }

    const systemContext = `You are SentinAI, the WordPress Cybersecurity Advisor built into WP Sentinel.
You are assisting an administrator with the audit results of target: ${scanContext?.targetUrl || 'WordPress site'}.
Target Security Score: ${scanContext?.score ?? 'N/A'}/100 (Grade ${scanContext?.grade || 'N/A'})
WordPress Version: ${scanContext?.wpVersion || 'Unknown'}
Total Findings: ${scanContext?.findings?.length || 0}
Observed Findings: ${JSON.stringify((scanContext?.findings || []).map((f: any) => ({ title: f.title, severity: f.severity, accuracyTier: f.accuracyTier, category: f.category, evidence: f.evidence })))}
Discovered Plugins: ${JSON.stringify((scanContext?.plugins || []).map((p: any) => ({ name: p.name, version: p.version || 'unknown' })))}

STRICT ACCURACY GUARDRAILS:
- Base your answer ONLY on the observed findings and context above. Never invent additional vulnerabilities, CVEs, or evidence.
- Distinguish between VERIFIED observations, LIKELY version-fingerprint matches, and NOT_VERIFIED items.
- Frame all code/configuration snippets as recommendations to test in staging and verify via re-scan.
- Never provide exploit payloads or offensive instructions.`;

    const chatPrompt = `${systemContext}\n\nUser Question: ${message}`;

    const replyText = await generateGeminiWithFallback(ai, chatPrompt);

    res.json({
      reply: replyText,
      isRecommendation: true,
      disclaimer: 'AI Recommendation — Verify Before Applying.'
    });
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    console.error('Gemini Chat error:', rawMsg);
    res.status(503).json({
      error: 'SentinAI is currently experiencing high demand. Please retry your request in a moment.'
    });
  }
});

/**
 * POST /api/wpscan/test-key
 * Tests a WPScan API token
 */
router.post('/wpscan/test-key', async (req: Request, res: Response) => {
  try {
    const { apiKey } = req.body;
    if (!apiKey) {
      res.status(400).json({ valid: false, message: 'API key is required.' });
      return;
    }

    const testRes = await fetch('https://wpscan.com/api/v3/status', {
      headers: {
        'Authorization': `Token token=${apiKey}`,
        'User-Agent': 'WPSentinel/1.0'
      }
    });

    if (testRes.ok) {
      const data = await testRes.json() as Record<string, any>;
      res.json({
        valid: true,
        message: 'WPScan API key verified successfully!',
        plan: data.plan || 'Standard',
        requestsRemaining: data.requests_remaining
      });
    } else {
      res.status(400).json({
        valid: false,
        message: `WPScan API returned status ${testRes.status}: Invalid token or quota exceeded.`
      });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(500).json({ valid: false, message: `Connection error: ${msg}` });
  }
});

export default router;
