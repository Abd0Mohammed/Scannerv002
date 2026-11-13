import { URL } from 'node:url';
import { calculateV2Scores } from './scoring.ts';
import {
  inspectTlsCertificate,
  isUrlInScope,
  safeFetchV2,
  validateV2TargetUrl
} from './ssrf.ts';
import {
  V2CookieAudit,
  V2CrawledPage,
  V2DiscoveredAssets,
  V2Finding,
  V2FormSummary,
  V2ScanResult,
  V2Technology,
  V2TlsCertificate
} from '../types/v2.ts';

export interface UrlScanOptions {
  userId?: string;
  maxPages?: number;
  maxDepth?: number;
  scope?: 'same-origin' | 'include-subdomains';
  authorizedAttestation?: boolean;
  allowInternalTestTarget?: boolean;
  onProgress?: (update: {
    progress: number;
    stage: string;
    pagesCrawled: number;
    totalDiscovered: number;
  }) => void;
}

const DOCUMENT_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt', '.xml', '.json', '.yaml', '.yml'];

function normalizeHeaderRecord(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    normalized[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
  }
  return normalized;
}

function parseSetCookieHeaders(
  rawHeader: string | string[] | undefined,
  sourceUrl: string
): V2CookieAudit[] {
  if (!rawHeader) return [];
  const entries = Array.isArray(rawHeader) ? rawHeader : [rawHeader];
  const audits: V2CookieAudit[] = [];

  for (const entry of entries) {
    const parts = entry.split(';').map((p) => p.trim());
    const nameVal = parts[0] || '';
    const eqIdx = nameVal.indexOf('=');
    const name = eqIdx > 0 ? nameVal.slice(0, eqIdx).trim() : nameVal;
    if (!name) continue;

    const attrs = parts.slice(1).map((a) => a.toLowerCase());
    const httpOnly = attrs.includes('httponly');
    const secure = attrs.includes('secure');
    const sameSiteAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('samesite='));
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1]?.trim() || null : null;
    const pathAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('path='));
    const path = pathAttr ? pathAttr.split('=')[1]?.trim() : undefined;

    const issues: string[] = [];
    if (!httpOnly) issues.push('Missing HttpOnly flag');
    if (!secure && sourceUrl.startsWith('https://')) issues.push('Missing Secure flag on HTTPS origin');
    if (!sameSite) issues.push('Missing SameSite attribute');
    if (sameSite && sameSite.toLowerCase() === 'none' && !secure) {
      issues.push('SameSite=None requires Secure attribute');
    }

    audits.push({
      name,
      httpOnly,
      secure,
      sameSite,
      path,
      sourceUrl,
      issues
    });
  }

  return audits;
}

function extractHtmlAttributes(html: string, tagName: string, attrName: string): string[] {
  const results: string[] = [];
  const regex = new RegExp(`<${tagName}\\b[^>]*?\\b${attrName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'gi');
  let match: RegExpExecArray | null;
  while ((match = regex.exec(html)) !== null) {
    const val = (match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (val && !val.startsWith('data:') && !val.startsWith('javascript:') && !val.startsWith('mailto:')) {
      results.push(val);
    }
  }
  return results;
}

function extractTitle(html: string): string | undefined {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) : undefined;
}

function extractForms(html: string, pageUrl: string): V2FormSummary[] {
  const forms: V2FormSummary[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  while ((match = formRegex.exec(html)) !== null) {
    const attrs = match[1] || '';
    const inner = match[2] || '';
    const actionMatch = attrs.match(/\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const methodMatch = attrs.match(/\bmethod\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const rawAction = (actionMatch?.[1] ?? actionMatch?.[2] ?? actionMatch?.[3] ?? pageUrl).trim();
    const method = ((methodMatch?.[1] ?? methodMatch?.[2] ?? methodMatch?.[3] ?? 'GET') || 'GET').toUpperCase();
    const hasPasswordInput = /<input\b[^>]*type\s*=\s*["']?password["']?/i.test(inner);

    let resolvedAction = pageUrl;
    try {
      resolvedAction = new URL(rawAction, pageUrl).toString();
    } catch {
      resolvedAction = rawAction;
    }

    forms.push({
      pageUrl,
      action: resolvedAction,
      method,
      hasPasswordInput,
      overInsecureHttp: pageUrl.startsWith('http://') || resolvedAction.startsWith('http://')
    });
  }
  return forms;
}

function detectTechnologies(
  headers: Record<string, string>,
  html: string,
  scriptUrls: string[],
  pageUrl: string
): V2Technology[] {
  const techs = new Map<string, V2Technology>();
  const addTech = (t: V2Technology) => {
    if (!techs.has(t.name)) techs.set(t.name, t);
  };

  const server = headers['server'] || '';
  const poweredBy = headers['x-powered-by'] || '';

  if (/nginx/i.test(server)) {
    const v = server.match(/nginx\/([\d.]+)/i)?.[1];
    addTech({ name: 'Nginx', category: 'server', version: v, confidence: 'confirmed', evidence: `Server: ${server}` });
  }
  if (/apache/i.test(server)) {
    const v = server.match(/apache\/([\d.]+)/i)?.[1];
    addTech({ name: 'Apache', category: 'server', version: v, confidence: 'confirmed', evidence: `Server: ${server}` });
  }
  if (/cloudflare/i.test(server) || headers['cf-ray']) {
    addTech({ name: 'Cloudflare', category: 'cdn', confidence: 'confirmed', evidence: headers['cf-ray'] ? 'CF-Ray header' : `Server: ${server}` });
  }
  if (/php/i.test(poweredBy)) {
    const v = poweredBy.match(/php\/([\d.]+)/i)?.[1];
    addTech({ name: 'PHP', category: 'language', version: v, confidence: 'confirmed', evidence: `X-Powered-By: ${poweredBy}` });
  }
  if (/express/i.test(poweredBy)) {
    addTech({ name: 'Express', category: 'framework', confidence: 'confirmed', evidence: `X-Powered-By: ${poweredBy}` });
  }
  if (/asp\.net/i.test(poweredBy) || headers['x-aspnet-version']) {
    addTech({ name: 'ASP.NET', category: 'framework', version: headers['x-aspnet-version'], confidence: 'confirmed', evidence: 'ASP.NET response headers' });
  }
  if (/next\.js/i.test(poweredBy) || html.includes('/_next/static/') || html.includes('__NEXT_DATA__')) {
    addTech({ name: 'Next.js', category: 'framework', confidence: 'confirmed', evidence: 'Next.js runtime assets (__NEXT_DATA__ / _next/static)' });
  }
  if (
    html.includes('wp-content/') ||
    html.includes('wp-includes/') ||
    /name=["']generator["'][^>]*WordPress/i.test(html)
  ) {
    const wpVer = html.match(/content=["']WordPress\s+([\d.]+)["']/i)?.[1];
    addTech({ name: 'WordPress', category: 'cms', version: wpVer, confidence: 'confirmed', evidence: 'wp-content/wp-includes or meta generator' });
  }
  if (headers['set-cookie']?.includes('laravel_session') || headers['set-cookie']?.includes('XSRF-TOKEN') && html.includes('csrf-token')) {
    addTech({ name: 'Laravel', category: 'framework', confidence: 'probable', evidence: 'laravel_session / XSRF-TOKEN cookie pattern' });
  }
  if (headers['set-cookie']?.includes('csrftoken') && (html.includes('csrfmiddlewaretoken') || headers['server']?.includes('WSGIServer'))) {
    addTech({ name: 'Django', category: 'framework', confidence: 'probable', evidence: 'Django csrfmiddlewaretoken / csrftoken cookie' });
  }
  if (html.includes('data-reactroot') || html.includes('__REACT_DEVTOOLS_GLOBAL_HOOK__') || scriptUrls.some((s) => /react(?:\.min)?\.js/i.test(s))) {
    addTech({ name: 'React', category: 'framework', confidence: 'probable', evidence: 'React DOM or bundle signature' });
  }
  if (html.includes('data-v-') || html.includes('__VUE__') || scriptUrls.some((s) => /vue(?:\.runtime)?(?:\.min)?\.js/i.test(s))) {
    addTech({ name: 'Vue.js', category: 'framework', confidence: 'probable', evidence: 'Vue scoped attribute or bundle signature' });
  }
  if (/ng-version=["']([\d.]+)["']/i.test(html)) {
    const v = html.match(/ng-version=["']([\d.]+)["']/i)?.[1];
    addTech({ name: 'Angular', category: 'framework', version: v, confidence: 'confirmed', evidence: `ng-version="${v}"` });
  }
  if (scriptUrls.some((s) => /jquery/i.test(s))) {
    addTech({ name: 'jQuery', category: 'library', confidence: 'confirmed', evidence: `Script reference on ${pageUrl}` });
  }

  return [...techs.values()];
}

interface Soft404Baseline {
  calibrated: boolean;
  statusCode?: number;
  title?: string;
  bodySample?: string;
  bodyLength?: number;
}

function isSoft404Response(
  res: { statusCode: number; body: string },
  baseline: Soft404Baseline
): boolean {
  if (res.statusCode !== 200) return false;
  const trimmed = res.body.trim();
  const title = extractTitle(trimmed);
  if (baseline.calibrated && baseline.statusCode === 200) {
    if (title && baseline.title && title === baseline.title) return true;
    if (
      baseline.bodySample &&
      trimmed.slice(0, 180).replace(/\s+/g, ' ') === baseline.bodySample
    ) {
      return true;
    }
    if (
      baseline.bodyLength &&
      baseline.bodyLength > 80 &&
      Math.abs(trimmed.length - baseline.bodyLength) <= Math.max(25, baseline.bodyLength * 0.04) &&
      trimmed.toLowerCase().includes('<html')
    ) {
      return true;
    }
  }
  return false;
}

function isConfirmedDirectoryListing(body: string, contentType: string): boolean {
  if (!contentType.includes('html') && !/<html/i.test(body)) return false;
  const hasIndexTitle = /<title>\s*Index of\s*\//i.test(body) || /<h1[^>]*>\s*Index of\s*\//i.test(body);
  const hasDirAnchors =
    (/Parent Directory/i.test(body) || /\[DIR\]|Last modified|Size\s+Description/i.test(body)) &&
    /<a\s+href=/i.test(body);
  return hasIndexTitle && hasDirAnchors;
}

function cweReferenceUrl(cwe?: string): string | undefined {
  if (!cwe) return undefined;
  const num = cwe.replace(/[^0-9]/g, '');
  return num ? `https://cwe.mitre.org/data/definitions/${num}.html` : undefined;
}

export async function executeUniversalUrlScan(
  rawTargetUrl: string,
  options: UrlScanOptions = {}
): Promise<V2ScanResult> {
  const startTime = Date.now();
  const maxPages = Math.min(25, Math.max(1, options.maxPages ?? 10));
  const maxDepth = Math.min(3, Math.max(1, options.maxDepth ?? 2));
  const scope = options.scope ?? 'same-origin';

  const emitProgress = (progress: number, stage: string, pagesCrawled: number, totalDiscovered: number) => {
    options.onProgress?.({ progress, stage, pagesCrawled, totalDiscovered });
  };

  emitProgress(5, 'Validating target URL & SSRF boundaries', 0, 1);

  const validation = await validateV2TargetUrl(rawTargetUrl, {
    allowInternalTestTarget: options.allowInternalTestTarget
  });
  if (!validation.valid || !validation.url || !validation.ip) {
    throw new Error(`Target verification failed: ${validation.error}`);
  }

  const initialUrl = validation.url;
  const findings: V2Finding[] = [];
  let findingCounter = 1;
  const dedupeKeys = new Set<string>();
  const checks: Array<{
    id: string;
    name: string;
    status: 'passed' | 'failed' | 'warning' | 'skipped';
    detail?: string;
  }> = [];

  const recordCheck = (
    id: string,
    name: string,
    status: 'passed' | 'failed' | 'warning' | 'skipped',
    detail?: string
  ) => {
    const existingIdx = checks.findIndex((c) => c.id === id);
    const entry = { id, name, status, detail };
    if (existingIdx >= 0) {
      checks[existingIdx] = entry;
    } else {
      checks.push(entry);
    }
  };

  const addFinding = (
    f: Omit<V2Finding, 'id' | 'observedAt'> & { checkId: string }
  ) => {
    const affectedResource =
      f.affectedResource || f.evidence.url || f.evidence.header || f.evidence.file || initialUrl.origin;
    const key = `${f.checkId}|${affectedResource}`.toLowerCase();
    if (dedupeKeys.has(key)) return;
    dedupeKeys.add(key);
    findings.push({
      ...f,
      affectedResource,
      observedAt: new Date().toISOString(),
      reference: f.reference || cweReferenceUrl(f.cwe),
      id: `v2url_${findingCounter++}`
    });
  };

  emitProgress(12, 'Fetching entry page & auditing transport', 0, 1);

  const entryResponse = await safeFetchV2(initialUrl.toString(), {
    allowInternalTestTarget: options.allowInternalTestTarget,
    enforceScopeRoot: initialUrl,
    scopeMode: scope,
    timeoutMs: 8000
  });

  const finalUrlObj = new URL(entryResponse.url);
  const httpsEnforced = finalUrlObj.protocol === 'https:';
  const entryHeaders = normalizeHeaderRecord(entryResponse.headers);

  // TLS Certificate Inspection & HTTP->HTTPS Redirect Audit
  let tlsInfo: V2TlsCertificate | null = null;
  if (httpsEnforced) {
    recordCheck('transport_https', 'HTTPS Transport Enforcement', 'passed', `Entry served over HTTPS (${entryResponse.url})`);
    emitProgress(20, 'Inspecting TLS certificate & handshake', 1, 1);
    const port = finalUrlObj.port ? parseInt(finalUrlObj.port, 10) : 443;
    tlsInfo = await inspectTlsCertificate(finalUrlObj.hostname, entryResponse.ip, port);

    if (!tlsInfo.valid) {
      recordCheck('tls_certificate', 'TLS Certificate Validity', 'failed', tlsInfo.error || 'Certificate invalid');
      addFinding({
        checkId: 'tls_invalid_cert',
        title: 'TLS Certificate Validation Issue Detected',
        severity: 'high',
        category: 'Transport & TLS',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Direct TLS Handshake & X.509 Certificate Verification',
        affectedResource: finalUrlObj.origin,
        description: `TLS handshake certificate check returned an invalid state: ${tlsInfo.error || 'Untrusted or expired certificate'}.`,
        impact: 'Visitors may encounter browser security warnings or be vulnerable to MitM attacks.',
        remediation: 'Provision a valid CA-signed TLS certificate matching the target hostname and ensure full intermediate chain installation.',
        evidence: { url: finalUrlObj.origin, detail: tlsInfo.error || 'Invalid certificate' },
        cwe: 'CWE-295',
        owasp: 'A02:2021 Cryptographic Failures'
      });
    } else if (tlsInfo.daysRemaining !== undefined && tlsInfo.daysRemaining < 21) {
      recordCheck('tls_certificate', 'TLS Certificate Validity', 'warning', `Expires in ${tlsInfo.daysRemaining} days`);
      addFinding({
        checkId: 'tls_expiring_cert',
        title: `TLS Certificate Expiring Soon (${tlsInfo.daysRemaining} days remaining)`,
        severity: tlsInfo.daysRemaining < 7 ? 'high' : 'medium',
        category: 'Transport & TLS',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Direct TLS Handshake & X.509 Certificate Verification',
        affectedResource: finalUrlObj.origin,
        description: `Certificate expires on ${tlsInfo.validTo}.`,
        impact: 'Imminent expiration will cause outages and browser security blocks.',
        remediation: 'Renew the TLS certificate immediately and verify ACME/auto-renewal automation.',
        evidence: { url: finalUrlObj.origin, detail: `Valid to ${tlsInfo.validTo}` },
        cwe: 'CWE-298'
      });
    } else {
      recordCheck(
        'tls_certificate',
        'TLS Certificate Validity',
        'passed',
        `Valid certificate (${tlsInfo.protocol || 'TLS'}, ${tlsInfo.daysRemaining ?? '?'} days left)`
      );
    }

    if (tlsInfo.protocol && (tlsInfo.protocol === 'TLSv1' || tlsInfo.protocol === 'TLSv1.1')) {
      recordCheck('tls_protocol', 'Modern TLS Protocol Enforcement', 'failed', `Negotiated ${tlsInfo.protocol}`);
      addFinding({
        checkId: 'tls_deprecated_protocol',
        title: `Deprecated TLS Protocol Negotiated (${tlsInfo.protocol})`,
        severity: 'high',
        category: 'Transport & TLS',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Direct TLS Protocol Negotiation',
        affectedResource: finalUrlObj.origin,
        description: `Server negotiated legacy ${tlsInfo.protocol}.`,
        impact: 'Legacy TLS protocols suffer from known cryptographic weaknesses (BEAST/POODLE).',
        remediation: 'Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2 and TLS 1.3 only.',
        evidence: { url: finalUrlObj.origin, detail: `Protocol: ${tlsInfo.protocol}` },
        cwe: 'CWE-326'
      });
    } else if (tlsInfo.protocol) {
      recordCheck('tls_protocol', 'Modern TLS Protocol Enforcement', 'passed', `Negotiated ${tlsInfo.protocol}`);
    }

    // Check whether plain HTTP port 80 redirects cleanly to HTTPS (skip custom non-443 dev ports)
    if (!finalUrlObj.port || finalUrlObj.port === '443') {
      try {
        const httpCheck = await safeFetchV2(`http://${finalUrlObj.hostname}/`, {
          allowInternalTestTarget: options.allowInternalTestTarget,
          enforceScopeRoot: finalUrlObj,
          scopeMode: scope,
          timeoutMs: 4000,
          maxRedirects: 0
        });
        const loc = String(normalizeHeaderRecord(httpCheck.headers)['location'] || '');
        const redirectsToHttps =
          [301, 302, 307, 308].includes(httpCheck.statusCode) &&
          (loc.startsWith('https://') || loc.startsWith(`https://${finalUrlObj.hostname}`));
        if (redirectsToHttps) {
          recordCheck('http_redirect', 'HTTP-to-HTTPS Redirect', 'passed', `HTTP ${httpCheck.statusCode} -> ${loc}`);
        } else {
          recordCheck('http_redirect', 'HTTP-to-HTTPS Redirect', 'failed', `HTTP returned status ${httpCheck.statusCode}`);
          addFinding({
            checkId: 'http_plaintext_no_redirect',
            title: 'Plain HTTP Does Not Redirect to HTTPS',
            severity: 'high',
            category: 'Transport & TLS',
            confidence: 'confirmed',
            accuracyTier: 'VERIFIED',
            detectionMethod: 'Direct Non-Redirecting HTTP Port 80 Request',
            affectedResource: `http://${finalUrlObj.hostname}/`,
            description: `Requesting http://${finalUrlObj.hostname}/ returned HTTP ${httpCheck.statusCode} instead of redirecting to HTTPS.`,
            impact: 'First-time visitors typing the bare hostname may communicate over unencrypted HTTP.',
            remediation: 'Configure a 301 permanent redirect from port 80 (HTTP) to https://.',
            evidence: {
              url: `http://${finalUrlObj.hostname}/`,
              detail: `Status ${httpCheck.statusCode}${loc ? `, Location: ${loc}` : ''}`
            },
            cwe: 'CWE-319',
            owasp: 'A02:2021 Cryptographic Failures'
          });
        }
      } catch (err) {
        recordCheck(
          'http_redirect',
          'HTTP-to-HTTPS Redirect',
          'skipped',
          err instanceof Error ? `Port 80 probe unreachable (${err.message})` : 'Port 80 unreachable'
        );
      }
    } else {
      recordCheck('http_redirect', 'HTTP-to-HTTPS Redirect', 'skipped', `Custom HTTPS port (${finalUrlObj.port}) in use`);
    }
  } else {
    recordCheck('transport_https', 'HTTPS Transport Enforcement', 'failed', `Served over HTTP (${entryResponse.url})`);
    recordCheck('tls_certificate', 'TLS Certificate Validity', 'skipped', 'Target did not use HTTPS');
    addFinding({
      checkId: 'http_unencrypted_origin',
      title: 'Target Served Over Unencrypted HTTP',
      severity: 'high',
      category: 'Transport & TLS',
      confidence: 'confirmed',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'Direct HTTP Response Inspection',
      affectedResource: entryResponse.url,
      description: `The final URL (${entryResponse.url}) did not redirect to HTTPS.`,
      impact: 'All traffic, session cookies, and submitted forms are transmitted in plaintext.',
      remediation: 'Enable TLS with an HTTPS certificate and configure a permanent 301 redirect from HTTP to HTTPS.',
      evidence: { url: entryResponse.url, detail: `Final status ${entryResponse.statusCode} over HTTP` },
      cwe: 'CWE-319',
      owasp: 'A02:2021 Cryptographic Failures'
    });
  }

  // Security Headers Analysis
  const requiredHeaders: Array<{
    checkId: string;
    name: string;
    title: string;
    severity: V2Finding['severity'];
    cwe: string;
    remediation: string;
    httpsOnly?: boolean;
  }> = [
    {
      checkId: 'header_missing_hsts',
      name: 'strict-transport-security',
      title: 'Missing Strict-Transport-Security (HSTS) Header',
      severity: 'medium',
      cwe: 'CWE-523',
      remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" on HTTPS responses.',
      httpsOnly: true
    },
    {
      checkId: 'header_missing_csp',
      name: 'content-security-policy',
      title: 'Missing Content-Security-Policy (CSP) Header',
      severity: 'medium',
      cwe: 'CWE-693',
      remediation: 'Define a restrictive Content-Security-Policy header limiting script-src, object-src, and frame-ancestors.'
    },
    {
      checkId: 'header_missing_xfo',
      name: 'x-frame-options',
      title: 'Missing Clickjacking Protection (X-Frame-Options)',
      severity: 'low',
      cwe: 'CWE-1021',
      remediation: 'Set "X-Frame-Options: DENY" or "SAMEORIGIN" (and/or CSP frame-ancestors).'
    },
    {
      checkId: 'header_missing_xcto',
      name: 'x-content-type-options',
      title: 'Missing X-Content-Type-Options: nosniff Header',
      severity: 'low',
      cwe: 'CWE-16',
      remediation: 'Add "X-Content-Type-Options: nosniff" to prevent MIME-sniffing attacks.'
    },
    {
      checkId: 'header_missing_referrer',
      name: 'referrer-policy',
      title: 'Missing Referrer-Policy Header',
      severity: 'low',
      cwe: 'CWE-200',
      remediation: 'Configure "Referrer-Policy: strict-origin-when-cross-origin" or "no-referrer".'
    }
  ];

  let missingHeadersCount = 0;
  for (const h of requiredHeaders) {
    if (h.httpsOnly && !httpsEnforced) continue;
    if (!entryHeaders[h.name]) {
      if (h.name === 'x-frame-options' && entryHeaders['content-security-policy']?.includes('frame-ancestors')) {
        continue;
      }
      missingHeadersCount++;
      addFinding({
        checkId: h.checkId,
        title: h.title,
        severity: h.severity,
        category: 'Headers & Cookies',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'HTTP Response Header Inspection',
        affectedResource: entryResponse.url,
        description: `HTTP response from ${entryResponse.url} did not include the "${h.name}" security header.`,
        impact: 'Reduces browser-enforced defense-in-depth protections against injection, downgrade, or framing attacks.',
        remediation: h.remediation,
        evidence: { url: entryResponse.url, header: h.name, detail: `Header "${h.name}" absent in HTTP ${entryResponse.statusCode} response` },
        cwe: h.cwe,
        owasp: 'A05:2021 Security Misconfiguration'
      });
    }
  }
  recordCheck(
    'security_headers',
    'HTTP Security Headers Baseline',
    missingHeadersCount === 0 ? 'passed' : 'warning',
    missingHeadersCount === 0 ? 'All baseline security headers present' : `${missingHeadersCount} baseline headers absent`
  );

  if (entryHeaders['x-powered-by']) {
    addFinding({
      checkId: 'header_x_powered_by',
      title: 'Technology Version Disclosure via X-Powered-By Header',
      severity: 'low',
      category: 'Headers & Cookies',
      confidence: 'confirmed',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: entryResponse.url,
      description: `Server exposes runtime details in X-Powered-By: "${entryHeaders['x-powered-by']}".`,
      impact: 'Helps automated scanners fingerprint backend framework/runtime versions.',
      remediation: 'Disable X-Powered-By header in Express (app.disable("x-powered-by")), PHP (expose_php=Off), or reverse proxy.',
      evidence: { url: entryResponse.url, header: `X-Powered-By: ${entryHeaders['x-powered-by']}` },
      cwe: 'CWE-200'
    });
  }

  if (entryHeaders['access-control-allow-origin'] === '*' && entryHeaders['access-control-allow-credentials'] === 'true') {
    addFinding({
      checkId: 'header_insecure_cors',
      title: 'Insecure CORS Configuration (Wildcard Origin with Credentials)',
      severity: 'high',
      category: 'Headers & Cookies',
      confidence: 'confirmed',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: entryResponse.url,
      description: 'Response specifies Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true.',
      impact: 'Allows arbitrary origins to attempt authenticated cross-origin requests if reflected.',
      remediation: 'Replace wildcard origin with explicit allowlisted origins.',
      evidence: { url: entryResponse.url, header: 'Access-Control-Allow-Origin: *' },
      cwe: 'CWE-942'
    });
  }

  // Calibrate Soft-404 Baseline
  emitProgress(28, 'Calibrating Soft-404 response baseline', 1, 1);
  const soft404Baseline: Soft404Baseline = { calibrated: false };
  try {
    const randSuffix = Math.random().toString(36).slice(2, 10);
    const s404Res = await safeFetchV2(`${finalUrlObj.origin}/__sentinel_nonexistent_${randSuffix}`, {
      allowInternalTestTarget: options.allowInternalTestTarget,
      enforceScopeRoot: finalUrlObj,
      scopeMode: scope,
      timeoutMs: 3500,
      maxBytes: 64 * 1024
    });
    soft404Baseline.calibrated = true;
    soft404Baseline.statusCode = s404Res.statusCode;
    soft404Baseline.title = extractTitle(s404Res.body);
    soft404Baseline.bodySample = s404Res.body.trim().slice(0, 180).replace(/\s+/g, ' ');
    soft404Baseline.bodyLength = s404Res.body.trim().length;
    recordCheck(
      'soft404_baseline',
      'Soft-404 Baseline Calibration',
      'passed',
      `Non-existent path returned HTTP ${s404Res.statusCode}`
    );
  } catch (err) {
    recordCheck(
      'soft404_baseline',
      'Soft-404 Baseline Calibration',
      'skipped',
      err instanceof Error ? err.message : 'Baseline probe failed'
    );
  }

  // Inspect robots.txt & sitemap.xml
  emitProgress(34, 'Analyzing robots.txt and sitemap.xml', 1, 1);
  const robotsTxt = { found: false, disallowedPaths: [] as string[], sitemaps: [] as string[] };
  const sitemapXml = { found: false, urlCount: 0, sampleUrls: [] as string[] };
  const queue: Array<{ url: string; depth: number }> = [];
  const queuedOrVisited = new Set<string>();

  const enqueueUrl = (rawCandidate: string, depth: number) => {
    try {
      const u = new URL(rawCandidate, finalUrlObj.origin);
      u.hash = '';
      if (!isUrlInScope(u.toString(), finalUrlObj, scope)) return;
      const lowerPath = u.pathname.toLowerCase();
      if (/\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|mp3|zip|tar|gz|pdf|css|js)$/i.test(lowerPath)) {
        return;
      }
      const key = u.toString();
      if (!queuedOrVisited.has(key) && queuedOrVisited.size < maxPages * 4) {
        queuedOrVisited.add(key);
        queue.push({ url: key, depth });
      }
    } catch {
      // Ignore invalid URL
    }
  };

  const entryCleanUrl = new URL(entryResponse.url);
  entryCleanUrl.hash = '';
  queuedOrVisited.add(entryCleanUrl.toString());

  try {
    const robotsRes = await safeFetchV2(`${finalUrlObj.origin}/robots.txt`, {
      allowInternalTestTarget: options.allowInternalTestTarget,
      timeoutMs: 4000,
      maxBytes: 128 * 1024
    });
    if (
      robotsRes.statusCode === 200 &&
      !robotsRes.body.trim().toLowerCase().startsWith('<!doctype html') &&
      !isSoft404Response(robotsRes, soft404Baseline)
    ) {
      robotsTxt.found = true;
      for (const line of robotsRes.body.split(/\r?\n/)) {
        const clean = line.split('#')[0].trim();
        if (/^disallow:\s*/i.test(clean)) {
          const p = clean.replace(/^disallow:\s*/i, '').trim();
          if (p) robotsTxt.disallowedPaths.push(p);
        } else if (/^sitemap:\s*/i.test(clean)) {
          const s = clean.replace(/^sitemap:\s*/i, '').trim();
          if (s) robotsTxt.sitemaps.push(s);
        }
      }
    }
  } catch {
    // robots.txt unavailable
  }

  const rawSitemapTarget = robotsTxt.sitemaps[0] || '/sitemap.xml';
  try {
    const sitemapTarget = new URL(rawSitemapTarget, finalUrlObj.origin).toString();
    if (isUrlInScope(sitemapTarget, finalUrlObj, scope)) {
      const smRes = await safeFetchV2(sitemapTarget, {
        allowInternalTestTarget: options.allowInternalTestTarget,
        timeoutMs: 4000,
        maxBytes: 512 * 1024
      });
      if (smRes.statusCode === 200 && smRes.body.includes('<loc>')) {
        sitemapXml.found = true;
        const locs = [...smRes.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].trim());
        sitemapXml.urlCount = locs.length;
        sitemapXml.sampleUrls = locs.slice(0, 20);
        for (const locUrl of locs.slice(0, maxPages)) {
          enqueueUrl(locUrl, 1);
        }
      }
    }
  } catch {
    // sitemap unavailable
  }

  // BFS Controlled Crawl
  const pages: V2CrawledPage[] = [];
  const scriptsSet = new Set<string>();
  const stylesheetsSet = new Set<string>();
  const imagesSet = new Set<string>();
  const documentsSet = new Set<string>();
  const forms: V2FormSummary[] = [];
  const cookies: V2CookieAudit[] = [];
  const cookieDedupe = new Set<string>();
  const techList: V2Technology[] = [];
  let cookieIssuesFound = 0;
  let stackTracesFound = 0;

  const processPageResponse = (res: Awaited<ReturnType<typeof safeFetchV2>>, depth: number) => {
    const resHeaders = normalizeHeaderRecord(res.headers);
    const contentType = resHeaders['content-type'] || '';
    pages.push({
      url: res.url,
      statusCode: res.statusCode,
      title: contentType.includes('html') ? extractTitle(res.body) : undefined,
      contentType: contentType.split(';')[0] || undefined,
      depth,
      responseTimeMs: res.durationMs
    });

    // Cookies audit
    const pageCookies = parseSetCookieHeaders(res.headers['set-cookie'], res.url);
    for (const c of pageCookies) {
      const ck = `${c.name}|${c.sourceUrl}`;
      if (!cookieDedupe.has(ck)) {
        cookieDedupe.add(ck);
        cookies.push(c);
        if (c.issues.length > 0) {
          cookieIssuesFound++;
          addFinding({
            checkId: `cookie_insecure_flags_${c.name.toLowerCase()}`,
            title: `Insecure Cookie Attributes on "${c.name}"`,
            severity: !c.httpOnly && /sess|token|auth|sid/i.test(c.name) ? 'medium' : 'low',
            category: 'Headers & Cookies',
            confidence: 'confirmed',
            accuracyTier: 'VERIFIED',
            detectionMethod: 'Set-Cookie Response Header Inspection',
            affectedResource: c.sourceUrl,
            description: `Cookie "${c.name}" set on ${c.sourceUrl} has security gaps: ${c.issues.join(', ')}.`,
            impact: 'Increases risk of session hijacking via XSS, plaintext interception, or CSRF.',
            remediation: 'Set HttpOnly, Secure, and SameSite=Lax (or Strict) attributes on all session/sensitive cookies.',
            evidence: { url: c.sourceUrl, header: `Set-Cookie: ${c.name}`, detail: c.issues.join('; ') },
            cwe: 'CWE-614',
            owasp: 'A05:2021 Security Misconfiguration'
          });
        }
      }
    }

    if (!contentType.includes('html') && !res.body.includes('<html') && !res.body.includes('<body')) {
      return;
    }

    // Stack Trace / Error Disclosure Check
    const debugMatch = res.body.match(
      /(Fatal error:\s+Uncaught|Traceback \(most recent call last\):|Whoops! There was an error\.|SQLSTATE\[|Unhandled Exception: System\.|ReferenceError: .* is not defined\s+at )/i
    );
    if (debugMatch) {
      stackTracesFound++;
      addFinding({
        checkId: 'runtime_stack_trace_exposed',
        title: 'Verbose Stack Trace or Runtime Debug Output Exposed',
        severity: 'high',
        category: 'Attack Surface & Exposure',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Crawled HTTP Response Body Inspection',
        affectedResource: res.url,
        description: `Crawled page "${res.url}" returned raw runtime error/stack trace signatures ("${debugMatch[0].slice(0, 60)}").`,
        impact: 'Discloses internal filesystem paths, framework internals, and potential SQL/code structures.',
        remediation: 'Disable debug/detailed error rendering in production and route exceptions to server logs.',
        evidence: { url: res.url, snippet: debugMatch[0].slice(0, 120) },
        cwe: 'CWE-209',
        owasp: 'A05:2021 Security Misconfiguration'
      });
    }

    const pageScripts = extractHtmlAttributes(res.body, 'script', 'src').map((s) => {
      try {
        return new URL(s, res.url).toString();
      } catch {
        return s;
      }
    });
    pageScripts.forEach((s) => scriptsSet.add(s));

    extractHtmlAttributes(res.body, 'link', 'href').forEach((href) => {
      try {
        const abs = new URL(href, res.url).toString();
        if (/\.css(\?|$)/i.test(abs)) stylesheetsSet.add(abs);
      } catch {
        // ignore
      }
    });

    extractHtmlAttributes(res.body, 'img', 'src').forEach((src) => {
      try {
        imagesSet.add(new URL(src, res.url).toString());
      } catch {
        // ignore
      }
    });

    const pageForms = extractForms(res.body, res.url);
    for (const f of pageForms) {
      forms.push(f);
      if (f.hasPasswordInput && f.overInsecureHttp) {
        addFinding({
          checkId: 'form_insecure_password_submit',
          title: 'Login / Password Form Served or Submitted Over Insecure HTTP',
          severity: 'critical',
          category: 'Transport & TLS',
          confidence: 'confirmed',
          accuracyTier: 'VERIFIED',
          detectionMethod: 'HTML Form Action & Origin Inspection',
          affectedResource: f.pageUrl,
          description: `A password form on "${f.pageUrl}" submits or renders over unencrypted HTTP.`,
          impact: 'Credentials can be intercepted in plaintext on the network.',
          remediation: 'Serve all login pages and form action targets exclusively over HTTPS.',
          evidence: { url: f.pageUrl, detail: `Action: ${f.action}` },
          cwe: 'CWE-319'
        });
      }
    }

    const links = extractHtmlAttributes(res.body, 'a', 'href');
    for (const link of links) {
      try {
        const abs = new URL(link, res.url);
        const lowerPath = abs.pathname.toLowerCase();
        if (DOCUMENT_EXTENSIONS.some((ext) => lowerPath.endsWith(ext))) {
          documentsSet.add(abs.toString());
        } else if (depth < maxDepth) {
          enqueueUrl(abs.toString(), depth + 1);
        }
      } catch {
        // ignore
      }
    }

    const detected = detectTechnologies(resHeaders, res.body, pageScripts, res.url);
    for (const t of detected) {
      if (!techList.some((existing) => existing.name === t.name)) {
        techList.push(t);
      }
    }
  };

  processPageResponse(entryResponse, 0);

  let crawlFailed = 0;
  while (queue.length > 0 && pages.length < maxPages) {
    const next = queue.shift()!;
    const pct = 38 + Math.round((pages.length / maxPages) * 35);
    emitProgress(pct, `Crawling internal pages (${pages.length}/${maxPages})`, pages.length, queuedOrVisited.size);
    try {
      const res = await safeFetchV2(next.url, {
        allowInternalTestTarget: options.allowInternalTestTarget,
        enforceScopeRoot: finalUrlObj,
        scopeMode: scope,
        timeoutMs: 6000
      });
      processPageResponse(res, next.depth);
    } catch {
      crawlFailed++;
    }
  }

  recordCheck(
    'cookie_security',
    'Set-Cookie Security Flags',
    cookieIssuesFound === 0 ? 'passed' : 'warning',
    cookies.length === 0 ? 'No Set-Cookie headers observed' : `${cookies.length} cookies inspected, ${cookieIssuesFound} with missing flags`
  );
  recordCheck(
    'crawl_runtime_errors',
    'Crawled Page Error & Form Inspection',
    stackTracesFound > 0 ? 'failed' : 'passed',
    `Inspected ${pages.length} page(s)${crawlFailed > 0 ? `, ${crawlFailed} unreachable` : ''}`
  );

  // Passive Sensitive File Exposure Probes (with Soft-404 guard & signature verification)
  emitProgress(78, 'Probing sensitive endpoints & directory indexes passively', pages.length, queuedOrVisited.size);
  const sensitiveProbes: Array<{
    checkId: string;
    path: string;
    title: string;
    severity: V2Finding['severity'];
    verifySignature: (body: string, contentType: string) => boolean;
    remediation: string;
  }> = [
    {
      checkId: 'probe_exposed_env',
      path: '/.env',
      title: 'Exposed Environment Configuration File (/.env)',
      severity: 'critical',
      verifySignature: (body, ct) => !ct.includes('html') && /^[A-Z0-9_]{2,}=/m.test(body),
      remediation: 'Block access to dotfiles (/.env*) in Nginx/Apache and move secrets out of web root.'
    },
    {
      checkId: 'probe_exposed_git_head',
      path: '/.git/HEAD',
      title: 'Exposed Git Repository Metadata (/.git/HEAD)',
      severity: 'critical',
      verifySignature: (body, ct) => !ct.includes('html') && /^ref:\s+refs\//m.test(body.trim()),
      remediation: 'Deny HTTP access to /.git/ directories in web server configuration.'
    },
    {
      checkId: 'probe_exposed_package_json',
      path: '/package.json',
      title: 'Publicly Accessible package.json Manifest',
      severity: 'low',
      verifySignature: (body, ct) => (ct.includes('json') || body.trim().startsWith('{')) && body.includes('"dependencies"'),
      remediation: 'Restrict access to project manifest files from public web root.'
    },
    {
      checkId: 'probe_exposed_composer_json',
      path: '/composer.json',
      title: 'Publicly Accessible composer.json Manifest',
      severity: 'low',
      verifySignature: (body, ct) => (ct.includes('json') || body.trim().startsWith('{')) && body.includes('"require"'),
      remediation: 'Restrict public HTTP access to composer.json and composer.lock.'
    },
    {
      checkId: 'probe_exposed_phpinfo',
      path: '/phpinfo.php',
      title: 'Exposed PHP Diagnostics Page (/phpinfo.php)',
      severity: 'high',
      verifySignature: (body) => body.includes('PHP Version') && body.includes('phpinfo()'),
      remediation: 'Delete phpinfo.php from production web directories immediately.'
    },
    {
      checkId: 'probe_exposed_actuator_env',
      path: '/actuator/env',
      title: 'Exposed Spring Boot Actuator Environment Endpoint',
      severity: 'critical',
      verifySignature: (body, ct) => ct.includes('json') && body.includes('activeProfiles'),
      remediation: 'Disable or restrict /actuator/* endpoints behind authentication and internal network policies.'
    },
    {
      checkId: 'probe_exposed_wp_config_bak',
      path: '/wp-config.php.bak',
      title: 'Exposed WordPress Configuration Backup (/wp-config.php.bak)',
      severity: 'critical',
      verifySignature: (body) => !/<html/i.test(body) && (body.includes('DB_NAME') || body.includes('DB_PASSWORD')),
      remediation: 'Remove backup configuration files from web root immediately and rotate database credentials.'
    }
  ];

  const exposedEndpoints: V2DiscoveredAssets['exposedEndpoints'] = [];
  let endpointProbeErrors = 0;
  let exposedCount = 0;

  for (const probe of sensitiveProbes) {
    try {
      const target = `${finalUrlObj.origin}${probe.path}`;
      const res = await safeFetchV2(target, {
        allowInternalTestTarget: options.allowInternalTestTarget,
        enforceScopeRoot: finalUrlObj,
        scopeMode: scope,
        timeoutMs: 4000,
        maxBytes: 64 * 1024
      });
      const ct = normalizeHeaderRecord(res.headers)['content-type'] || '';
      const soft404 = isSoft404Response(res, soft404Baseline);
      const confirmed = res.statusCode === 200 && !soft404 && probe.verifySignature(res.body, ct);

      if (res.statusCode === 200 || res.statusCode === 403) {
        exposedEndpoints.push({
          path: probe.path,
          statusCode: res.statusCode,
          contentType: ct.split(';')[0] || undefined,
          confirmedExposure: confirmed
        });
      }
      if (confirmed) {
        exposedCount++;
        addFinding({
          checkId: probe.checkId,
          title: probe.title,
          severity: probe.severity,
          category: 'Attack Surface & Exposure',
          confidence: 'confirmed',
          accuracyTier: 'VERIFIED',
          detectionMethod: 'Passive Endpoint Probe with Signature & Soft-404 Verification',
          affectedResource: target,
          description: `Passive probe to ${target} returned HTTP 200 with verified file signature (distinguished from Soft-404 baseline).`,
          impact: 'Allows unauthenticated attackers to read sensitive source, dependency, or credential data.',
          remediation: probe.remediation,
          evidence: { url: target, detail: `HTTP 200 (${ct || 'unknown content-type'})` },
          cwe: 'CWE-538',
          owasp: 'A05:2021 Security Misconfiguration'
        });
      }
    } catch {
      endpointProbeErrors++;
    }
  }

  recordCheck(
    'sensitive_endpoints',
    'Sensitive File Exposure Probes',
    endpointProbeErrors === sensitiveProbes.length
      ? 'skipped'
      : exposedCount > 0
      ? 'failed'
      : 'passed',
    endpointProbeErrors === sensitiveProbes.length
      ? 'All sensitive endpoint probes timed out or failed'
      : `Probed ${sensitiveProbes.length - endpointProbeErrors}/${sensitiveProbes.length} sensitive paths (${exposedCount} exposed)`
  );

  // Passive Directory Listing Check on common directories
  emitProgress(88, 'Checking common directories for directory indexing', pages.length, queuedOrVisited.size);
  const candidateDirs = ['/uploads/', '/backup/', '/files/', '/assets/'];
  let dirChecksRun = 0;
  let dirListingsFound = 0;
  for (const dirPath of candidateDirs) {
    try {
      const target = `${finalUrlObj.origin}${dirPath}`;
      const res = await safeFetchV2(target, {
        allowInternalTestTarget: options.allowInternalTestTarget,
        enforceScopeRoot: finalUrlObj,
        scopeMode: scope,
        timeoutMs: 3500,
        maxBytes: 64 * 1024
      });
      dirChecksRun++;
      const ct = normalizeHeaderRecord(res.headers)['content-type'] || '';
      if (res.statusCode === 200 && !isSoft404Response(res, soft404Baseline) && isConfirmedDirectoryListing(res.body, ct)) {
        dirListingsFound++;
        exposedEndpoints.push({
          path: dirPath,
          statusCode: res.statusCode,
          contentType: ct.split(';')[0] || undefined,
          confirmedExposure: true
        });
        addFinding({
          checkId: `directory_listing_${dirPath.replace(/[^a-z0-9]/gi, '_')}`,
          title: `Directory Listing Enabled on ${dirPath}`,
          severity: 'medium',
          category: 'Attack Surface & Exposure',
          confidence: 'confirmed',
          accuracyTier: 'VERIFIED',
          detectionMethod: 'Passive Directory Index Signature Verification',
          affectedResource: target,
          description: `HTTP GET ${target} returned a web server directory index ("Index of ${dirPath}") listing files publicly.`,
          impact: 'Allows visitors to enumerate and download unlinked backups, media, or internal files.',
          remediation: 'Disable autoindex / directory listing globally (Nginx: autoindex off; Apache: Options -Indexes).',
          evidence: { url: target, detail: `HTTP 200 directory index markup detected` },
          cwe: 'CWE-548',
          owasp: 'A05:2021 Security Misconfiguration'
        });
      }
    } catch {
      // Directory unreachable
    }
  }

  recordCheck(
    'directory_listing',
    'Directory Indexing Check',
    dirChecksRun === 0 ? 'skipped' : dirListingsFound > 0 ? 'failed' : 'passed',
    dirChecksRun === 0
      ? 'Directory probes timed out'
      : `Checked ${dirChecksRun} common directories (${dirListingsFound} listing(s) found)`
  );

  const coverage = {
    totalChecks: checks.length,
    executedChecks: checks.filter((c) => c.status !== 'skipped').length,
    passedChecks: checks.filter((c) => c.status === 'passed').length,
    failedChecks: checks.filter((c) => c.status === 'failed' || c.status === 'warning').length,
    skippedChecks: checks.filter((c) => c.status === 'skipped').length,
    checks
  };

  emitProgress(95, 'Computing deterministic risk score', pages.length, queuedOrVisited.size);
  const scoring = calculateV2Scores(findings, coverage);

  const result: V2ScanResult = {
    id: `v2url_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    userId: options.userId || 'anonymous',
    version: 'v2',
    mode: 'url',
    target: entryResponse.url,
    hostname: finalUrlObj.hostname,
    score: scoring.score,
    grade: scoring.grade,
    durationMs: Date.now() - startTime,
    createdAt: new Date().toISOString(),
    authorizedAttestation: Boolean(options.authorizedAttestation),
    technologies: techList,
    findings: scoring.deduplicatedFindings,
    categoryScores: scoring.categoryScores,
    summary: scoring.summary,
    coverage,
    scoreBreakdown: scoring.scoreBreakdown,
    urlDetails: {
      finalUrl: entryResponse.url,
      ipAddress: entryResponse.ip,
      httpStatus: entryResponse.statusCode,
      httpsEnforced,
      tls: tlsInfo,
      headers: entryHeaders,
      cookies,
      assets: {
        pages,
        scripts: [...scriptsSet].slice(0, 100),
        stylesheets: [...stylesheetsSet].slice(0, 60),
        images: [...imagesSet].slice(0, 80),
        documents: [...documentsSet].slice(0, 60),
        forms: forms.slice(0, 40),
        robotsTxt,
        sitemapXml,
        exposedEndpoints
      },
      crawlConfig: {
        maxPages,
        maxDepth,
        scope
      }
    }
  };

  emitProgress(100, 'Scan complete', pages.length, queuedOrVisited.size);
  return result;
}
