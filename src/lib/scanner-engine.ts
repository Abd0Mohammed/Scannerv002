import { safeFetch, validateTargetUrl } from './ssrf.ts';
import { fetchVulnerabilitiesForComponent } from './wpscan-client.ts';
import { isVersionOlder } from './vulnerability-db.ts';
import {
  ScanResult,
  SecurityFinding,
  DetectedPlugin,
  DetectedTheme,
  CategoryScore,
  FindingCategory,
  FindingSeverity,
  ScanCheckRecord,
  ScanCoverage,
  ScoreBreakdown
} from '../types/scanner.ts';

function normalizeBaseUrl(input: string): string {
  let url = input.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.host}`;
}

interface Soft404Baseline {
  calibrated: boolean;
  statusCode?: number;
  title?: string;
  bodySample?: string;
  bodyLength?: number;
}

function extractTitle(html: string): string | undefined {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? m[1].replace(/\s+/g, ' ').trim().slice(0, 120) : undefined;
}

function isSoft404(res: { statusCode: number; body: string }, baseline: Soft404Baseline): boolean {
  if (res.statusCode !== 200) return false;
  const trimmed = res.body.trim();
  const title = extractTitle(trimmed);
  if (baseline.calibrated && baseline.statusCode === 200) {
    if (title && baseline.title && title === baseline.title) return true;
    if (baseline.bodySample && trimmed.slice(0, 180).replace(/\s+/g, ' ') === baseline.bodySample) {
      return true;
    }
    if (
      baseline.bodyLength &&
      baseline.bodyLength > 80 &&
      Math.abs(trimmed.length - baseline.bodyLength) <= Math.max(25, baseline.bodyLength * 0.04) &&
      /<html/i.test(trimmed)
    ) {
      return true;
    }
  }
  return false;
}

function isConfirmedDirListing(body: string): boolean {
  const hasIndexTitle = /<title>\s*Index of\s*\//i.test(body) || /<h1[^>]*>\s*Index of\s*\//i.test(body);
  const hasDirAnchors =
    (/Parent Directory/i.test(body) || /\[DIR\]|Last modified|Size\s+Description/i.test(body)) &&
    /<a\s+href=/i.test(body);
  return hasIndexTitle && hasDirAnchors;
}

export async function executeWordPressScan(
  targetUrl: string,
  options: {
    userId?: string;
    wpscanApiKey?: string;
    allowInternalTestTarget?: boolean;
  } = {}
): Promise<ScanResult> {
  const scanStart = Date.now();
  const baseUrl = normalizeBaseUrl(targetUrl);
  const parsedTarget = new URL(baseUrl);
  const hostname = parsedTarget.hostname;
  const userId = options.userId || 'anonymous';
  const allowInternal = Boolean(options.allowInternalTestTarget);

  // 1. SSRF & Pre-flight validation
  const preflight = await validateTargetUrl(baseUrl, { allowInternalTestTarget: allowInternal });
  if (!preflight.valid || !preflight.ip) {
    throw new Error(`Target verification failed: ${preflight.error || 'Blocked by security policy.'}`);
  }

  const rawFindings: SecurityFinding[] = [];
  const checks: ScanCheckRecord[] = [];
  const recordCheck = (
    id: string,
    name: string,
    status: ScanCheckRecord['status'],
    detail?: string
  ) => {
    const idx = checks.findIndex((c) => c.id === id);
    const entry: ScanCheckRecord = { id, name, status, detail };
    if (idx >= 0) checks[idx] = entry;
    else checks.push(entry);
  };

  const pushFinding = (f: SecurityFinding) => {
    rawFindings.push({
      ...f,
      checkId: f.checkId || f.id,
      accuracyTier: f.accuracyTier || (f.severity === 'info' ? 'INFORMATIONAL' : 'VERIFIED'),
      detectionMethod: f.detectionMethod || 'Direct Passive HTTP Inspection',
      affectedResource: f.affectedResource || f.evidence.url || f.evidence.headerName || baseUrl,
      observedAt: f.observedAt || new Date().toISOString()
    });
  };

  const detectedPlugins: Map<string, DetectedPlugin> = new Map();
  let detectedTheme: DetectedTheme | undefined = undefined;
  let isWordPress = false;
  let detectedWpVersion: string | undefined = undefined;
  let webServer: string | undefined = undefined;
  let phpVersion: string | undefined = undefined;
  let poweredBy: string | undefined = undefined;
  let hstsEnabled = false;
  let httpsEnforced = false;

  // 2. Fetch Homepage
  let homeRes;
  try {
    homeRes = await safeFetch(`${baseUrl}/`, { timeoutMs: 8000, allowInternalTestTarget: allowInternal });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to establish connection to target: ${msg}`);
  }

  const homeHtml = homeRes.body;
  const homeHeaders = homeRes.headers;

  if (homeHeaders['server']) {
    webServer = String(homeHeaders['server']);
  }
  if (homeHeaders['x-powered-by']) {
    poweredBy = String(homeHeaders['x-powered-by']);
    if (poweredBy.toLowerCase().includes('php')) {
      phpVersion = poweredBy;
    }
  }

  // Calibrate Soft-404 Baseline
  const soft404Baseline: Soft404Baseline = { calibrated: false };
  try {
    const nonce = Math.random().toString(36).slice(2, 10);
    const s404 = await safeFetch(`${baseUrl}/__wp_sentinel_404_probe_${nonce}`, {
      timeoutMs: 3500,
      allowInternalTestTarget: allowInternal
    });
    soft404Baseline.calibrated = true;
    soft404Baseline.statusCode = s404.statusCode;
    soft404Baseline.title = extractTitle(s404.body);
    soft404Baseline.bodySample = s404.body.trim().slice(0, 180).replace(/\s+/g, ' ');
    soft404Baseline.bodyLength = s404.body.trim().length;
    recordCheck('wp_soft404_baseline', 'Soft-404 Baseline Calibration', 'passed', `Probe status ${s404.statusCode}`);
  } catch (err) {
    recordCheck(
      'wp_soft404_baseline',
      'Soft-404 Baseline Calibration',
      'skipped',
      err instanceof Error ? err.message : 'Probe unreachable'
    );
  }

  // 3. WordPress Detection Logic
  const generatorMatch = homeHtml.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
  if (generatorMatch && generatorMatch[1]) {
    const gen = generatorMatch[1];
    if (gen.toLowerCase().includes('wordpress')) {
      isWordPress = true;
      const verMatch = gen.match(/WordPress\s+([0-9.]+)/i);
      if (verMatch) {
        detectedWpVersion = verMatch[1];
      }
    }
  }

  if (homeHtml.includes('/wp-content/') || homeHtml.includes('/wp-includes/')) {
    isWordPress = true;
  }
  if (homeHtml.includes('https://api.w.org/') || homeHtml.includes('wp-json')) {
    isWordPress = true;
  }

  try {
    const wpLoginRes = await safeFetch(`${baseUrl}/wp-login.php`, {
      timeoutMs: 5000,
      allowInternalTestTarget: allowInternal
    });
    if (
      wpLoginRes.statusCode === 200 &&
      !isSoft404(wpLoginRes, soft404Baseline) &&
      (wpLoginRes.body.includes('wp-submit') ||
        wpLoginRes.body.includes('loginform') ||
        wpLoginRes.body.includes('Powered by WordPress'))
    ) {
      isWordPress = true;
    }
  } catch {
    // Ignore
  }

  try {
    const wpJsonRes = await safeFetch(`${baseUrl}/wp-json/`, {
      timeoutMs: 5000,
      allowInternalTestTarget: allowInternal
    });
    if (wpJsonRes.statusCode === 200) {
      try {
        const json = JSON.parse(wpJsonRes.body);
        if (json.namespaces && Array.isArray(json.namespaces) && json.namespaces.includes('wp/v2')) {
          isWordPress = true;
        }
      } catch {
        // Not valid JSON
      }
    }
  } catch {
    // Ignore
  }

  try {
    const readmeRes = await safeFetch(`${baseUrl}/readme.html`, {
      timeoutMs: 4000,
      allowInternalTestTarget: allowInternal
    });
    if (
      readmeRes.statusCode === 200 &&
      !isSoft404(readmeRes, soft404Baseline) &&
      readmeRes.body.includes('WordPress') &&
      !readmeRes.body.includes('Page not found')
    ) {
      isWordPress = true;
      const readmeVerMatch = readmeRes.body.match(/<br\s*\/?>\s*Version\s+([0-9.]+)/i);
      if (readmeVerMatch && !detectedWpVersion) {
        detectedWpVersion = readmeVerMatch[1];
      }
    }
  } catch {
    // Ignore
  }

  // 4. SSL & HTTPS Checks
  const finalProto = new URL(homeRes.url).protocol;
  if (finalProto === 'https:') {
    httpsEnforced = true;
    recordCheck('wp_transport_https', 'HTTPS Transport Enforcement', 'passed', `Target served over HTTPS (${homeRes.url})`);

    if (!parsedTarget.port || parsedTarget.port === '443') {
      try {
        const httpCheck = await safeFetch(`http://${hostname}/`, {
          timeoutMs: 5000,
          maxRedirects: 0,
          allowInternalTestTarget: allowInternal
        });
        if ([301, 302, 307, 308].includes(httpCheck.statusCode)) {
          const loc = String(httpCheck.headers['location'] || '');
          if (loc.startsWith('https://')) {
            httpsEnforced = true;
            recordCheck('wp_http_redirect', 'HTTP-to-HTTPS Redirect', 'passed', `HTTP ${httpCheck.statusCode} -> ${loc}`);
          } else {
            recordCheck('wp_http_redirect', 'HTTP-to-HTTPS Redirect', 'failed', `Redirects to non-HTTPS target: ${loc}`);
            pushFinding({
              id: 'http_redirect_insecure',
              checkId: 'wp_http_redirect',
              category: 'ssl_tls',
              title: 'HTTP Does Not Redirect Securely to HTTPS',
              severity: 'high',
              accuracyTier: 'VERIFIED',
              detectionMethod: 'Direct Non-Redirecting HTTP Port 80 Request',
              affectedResource: `http://${hostname}/`,
              cvssScore: 7.4,
              scoreDeduction: 15,
              description: 'Plain HTTP requests to your domain do not redirect to an HTTPS destination.',
              impact: 'Attackers on the same local network can intercept traffic or perform SSL stripping attacks.',
              evidence: {
                url: `http://${hostname}/`,
                statusCode: httpCheck.statusCode,
                headerName: 'Location',
                headerValue: loc || 'None'
              },
              remediation: {
                summary: 'Enforce automatic 301 redirection from HTTP to HTTPS across all hostnames.',
                steps: [
                  'Add an SSL rewrite rule to your .htaccess or Nginx server block.',
                  'Ensure HSTS is enabled with a minimum 1-year max-age.'
                ],
                codeSnippet: {
                  language: 'apache',
                  filename: '.htaccess',
                  code: `RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]`
                }
              }
            });
          }
        } else {
          recordCheck('wp_http_redirect', 'HTTP-to-HTTPS Redirect', 'failed', `Plain HTTP returned ${httpCheck.statusCode}`);
          pushFinding({
            id: 'http_plaintext_available',
            checkId: 'wp_http_redirect',
            category: 'ssl_tls',
            title: 'Plain HTTP Available Without Redirect',
            severity: 'high',
            accuracyTier: 'VERIFIED',
            detectionMethod: 'Direct Non-Redirecting HTTP Port 80 Request',
            affectedResource: `http://${hostname}/`,
            cvssScore: 7.4,
            scoreDeduction: 15,
            description: 'The website is accessible over unencrypted HTTP without redirecting to HTTPS.',
            impact: 'Unencrypted communication exposes cookies, credentials, and page content to sniffing.',
            evidence: {
              url: `http://${hostname}/`,
              statusCode: httpCheck.statusCode
            },
            remediation: {
              summary: 'Redirect all HTTP traffic to HTTPS via web server configuration.',
              steps: ['Enforce 301 redirect in web server', 'Enable HSTS'],
              codeSnippet: {
                language: 'nginx',
                filename: 'nginx.conf',
                code: `server {\n    listen 80;\n    server_name ${hostname};\n    return 301 https://$host$request_uri;\n}`
              }
            }
          });
        }
      } catch (err) {
        recordCheck(
          'wp_http_redirect',
          'HTTP-to-HTTPS Redirect',
          'skipped',
          err instanceof Error ? `Port 80 unreachable (${err.message})` : 'Port 80 unreachable'
        );
      }
    } else {
      recordCheck('wp_http_redirect', 'HTTP-to-HTTPS Redirect', 'skipped', `Custom port ${parsedTarget.port} in use`);
    }
  } else {
    recordCheck('wp_transport_https', 'HTTPS Transport Enforcement', 'failed', `Served over HTTP (${homeRes.url})`);
    pushFinding({
      id: 'no_https_protocol',
      checkId: 'wp_transport_https',
      category: 'ssl_tls',
      title: 'Target Site Does Not Enforce HTTPS Encryption',
      severity: 'critical',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'Direct HTTP Response Protocol Inspection',
      affectedResource: baseUrl,
      cvssScore: 9.1,
      scoreDeduction: 25,
      description: 'The target website was accessed over plain HTTP without transport encryption.',
      impact: 'All transmission, including login credentials and session cookies, is in plain text.',
      evidence: { url: baseUrl, statusCode: homeRes.statusCode },
      remediation: {
        summary: 'Install an SSL/TLS certificate (e.g. Let\'s Encrypt) and force HTTPS redirection.',
        steps: [
          'Generate a free certificate via Let\'s Encrypt / Certbot.',
          'Configure your web server to listen on port 443 with TLS 1.2 and 1.3.'
        ]
      }
    });
  }

  // 5. Security Headers Analysis
  const headers = homeHeaders;
  let headerGapCount = 0;

  const hsts = headers['strict-transport-security'];
  if (hsts) {
    hstsEnabled = true;
    const hstsStr = String(hsts);
    if (!hstsStr.includes('max-age=') || parseInt((hstsStr.match(/max-age=(\d+)/) || [])[1] || '0', 10) < 15552000) {
      headerGapCount++;
      pushFinding({
        id: 'hsts_short_duration',
        checkId: 'wp_header_hsts_duration',
        category: 'security_headers',
        title: 'HSTS Header Has Inadequate max-age Duration',
        severity: 'low',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'HTTP Response Header Inspection',
        affectedResource: baseUrl,
        cvssScore: 3.1,
        scoreDeduction: 3,
        description: 'The HTTP Strict Transport Security (HSTS) header is configured with a duration less than 6 months (15552000 seconds).',
        impact: 'Browsers will downgrade protection sooner, leaving users vulnerable to SSL stripping after expiration.',
        evidence: { url: baseUrl, headerName: 'Strict-Transport-Security', headerValue: hstsStr },
        remediation: {
          summary: 'Increase HSTS max-age to at least 1 year (31536000 seconds) and include subdomains.',
          steps: ['Update your web server configuration headers.'],
          codeSnippet: {
            language: 'apache',
            filename: '.htaccess',
            code: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`
          }
        }
      });
    }
  } else {
    headerGapCount++;
    pushFinding({
      id: 'missing_hsts_header',
      checkId: 'wp_header_missing_hsts',
      category: 'security_headers',
      title: 'Missing HTTP Strict Transport Security (HSTS) Header',
      severity: 'medium',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 5.9,
      scoreDeduction: 8,
      description: 'The Strict-Transport-Security header informs browsers that the site must only be accessed using HTTPS.',
      impact: 'Allows man-in-the-middle attackers to downgrade HTTPS requests to insecure HTTP.',
      evidence: { url: baseUrl, headerName: 'Strict-Transport-Security', details: 'Header was absent from response.' },
      remediation: {
        summary: 'Send Strict-Transport-Security header on all HTTPS responses.',
        steps: ['Add HSTS header in Apache, Nginx, or Cloudflare.'],
        codeSnippet: {
          language: 'nginx',
          filename: 'nginx.conf',
          code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
        }
      }
    });
  }

  const csp = headers['content-security-policy'];
  if (!csp) {
    headerGapCount++;
    pushFinding({
      id: 'missing_csp_header',
      checkId: 'wp_header_missing_csp',
      category: 'security_headers',
      title: 'Missing Content-Security-Policy (CSP) Header',
      severity: 'medium',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 6.1,
      scoreDeduction: 8,
      description: 'Content-Security-Policy protects against Cross-Site Scripting (XSS) and data injection attacks by restricting resource origins.',
      impact: 'XSS vulnerabilities can be weaponized to steal session cookies, token secrets, or deface the site.',
      evidence: { url: baseUrl, headerName: 'Content-Security-Policy', details: 'Header was absent.' },
      remediation: {
        summary: 'Define a Content-Security-Policy tailored to your WordPress theme and plugins.',
        steps: [
          'Start with a report-only CSP or a baseline policy.',
          'Gradually restrict script-src, object-src, and frame-ancestors.'
        ],
        codeSnippet: {
          language: 'apache',
          filename: '.htaccess',
          code: `Header set Content-Security-Policy "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self';"`
        }
      }
    });
  }

  const xfo = headers['x-frame-options'];
  if (!xfo && !(typeof csp === 'string' && csp.includes('frame-ancestors'))) {
    headerGapCount++;
    pushFinding({
      id: 'missing_x_frame_options',
      checkId: 'wp_header_missing_xfo',
      category: 'security_headers',
      title: 'Missing X-Frame-Options Header (Clickjacking Vulnerability)',
      severity: 'medium',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 5.4,
      scoreDeduction: 8,
      description: 'Without X-Frame-Options or CSP frame-ancestors, the site can be embedded inside an iframe on malicious domains.',
      impact: 'Attackers can trick logged-in WordPress administrators into clicking hidden action buttons.',
      evidence: { url: baseUrl, headerName: 'X-Frame-Options', details: 'Header was absent.' },
      remediation: {
        summary: 'Set X-Frame-Options to SAMEORIGIN or DENY.',
        steps: ['Add header in web server configuration.'],
        codeSnippet: {
          language: 'apache',
          filename: '.htaccess',
          code: `Header always set X-Frame-Options "SAMEORIGIN"`
        }
      }
    });
  }

  const xcto = headers['x-content-type-options'];
  if (!xcto || String(xcto).toLowerCase() !== 'nosniff') {
    headerGapCount++;
    pushFinding({
      id: 'missing_x_content_type_options',
      checkId: 'wp_header_missing_xcto',
      category: 'security_headers',
      title: 'Missing X-Content-Type-Options: nosniff Header',
      severity: 'low',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 3.7,
      scoreDeduction: 3,
      description: 'The X-Content-Type-Options: nosniff header prevents browsers from MIME-sniffing a response away from the declared content-type.',
      impact: 'Attackers can execute uploaded user images as executable HTML/JavaScript in older browsers.',
      evidence: { url: baseUrl, headerName: 'X-Content-Type-Options', headerValue: String(xcto || 'Absent') },
      remediation: {
        summary: 'Set X-Content-Type-Options to nosniff.',
        steps: ['Include header in web server configuration.'],
        codeSnippet: {
          language: 'nginx',
          filename: 'nginx.conf',
          code: `add_header X-Content-Type-Options "nosniff" always;`
        }
      }
    });
  }

  const rp = headers['referrer-policy'];
  if (!rp) {
    headerGapCount++;
    pushFinding({
      id: 'missing_referrer_policy',
      checkId: 'wp_header_missing_rp',
      category: 'security_headers',
      title: 'Missing Referrer-Policy Header',
      severity: 'low',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 3.1,
      scoreDeduction: 3,
      description: 'Referrer-Policy governs what referrer information is sent along with outbound links.',
      impact: 'Sensitive query parameters or internal paths may leak in the Referer header to third-party services.',
      evidence: { url: baseUrl, headerName: 'Referrer-Policy', details: 'Header was absent.' },
      remediation: {
        summary: 'Enforce strict-origin-when-cross-origin.',
        steps: ['Add Referrer-Policy header to server configuration.'],
        codeSnippet: {
          language: 'apache',
          filename: '.htaccess',
          code: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`
        }
      }
    });
  }

  if (webServer && (webServer.includes('/') || /[0-9]/.test(webServer))) {
    headerGapCount++;
    pushFinding({
      id: 'server_version_disclosure',
      checkId: 'wp_header_server_version',
      category: 'security_headers',
      title: 'Detailed Web Server Version Disclosed in HTTP Header',
      severity: 'low',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 3.3,
      scoreDeduction: 3,
      description: 'The Server header advertises the exact web server software and version number.',
      impact: 'Assists attackers in targeting known exploits specific to that exact web server build.',
      evidence: { url: baseUrl, headerName: 'Server', headerValue: webServer },
      remediation: {
        summary: 'Suppress version tokens in Apache / Nginx configuration.',
        steps: ['For Apache: ServerTokens Prod, ServerSignature Off', 'For Nginx: server_tokens off;'],
        codeSnippet: {
          language: 'apache',
          filename: 'httpd.conf',
          code: `ServerTokens Prod\nServerSignature Off`
        }
      }
    });
  }

  if (poweredBy) {
    headerGapCount++;
    pushFinding({
      id: 'php_version_disclosure',
      checkId: 'wp_header_x_powered_by',
      category: 'security_headers',
      title: 'PHP / Technology Signature Disclosed (X-Powered-By)',
      severity: 'low',
      accuracyTier: 'VERIFIED',
      detectionMethod: 'HTTP Response Header Inspection',
      affectedResource: baseUrl,
      cvssScore: 3.3,
      scoreDeduction: 3,
      description: 'The X-Powered-By header exposes the backend technology and exact PHP version.',
      impact: 'Aids automated scanners in matching PHP CVEs.',
      evidence: { url: baseUrl, headerName: 'X-Powered-By', headerValue: poweredBy },
      remediation: {
        summary: 'Disable expose_php in php.ini.',
        steps: ['Open php.ini and set expose_php = Off', 'Restart PHP-FPM / Apache.'],
        codeSnippet: {
          language: 'php',
          filename: 'php.ini',
          code: `expose_php = Off`
        }
      }
    });
  }

  recordCheck(
    'wp_security_headers',
    'HTTP Security Headers Inspection',
    headerGapCount === 0 ? 'passed' : 'warning',
    headerGapCount === 0 ? 'All checked headers configured properly' : `${headerGapCount} header issue(s) observed`
  );

  // 6. WordPress Configuration Checks
  // XML-RPC check
  try {
    const xmlRpcRes = await safeFetch(`${baseUrl}/xmlrpc.php`, {
      timeoutMs: 5000,
      allowInternalTestTarget: allowInternal
    });
    const xmlRpcOpen =
      !isSoft404(xmlRpcRes, soft404Baseline) &&
      (xmlRpcRes.body.includes('XML-RPC server accepts POST requests only') ||
        (xmlRpcRes.statusCode === 200 && /XML-RPC/i.test(xmlRpcRes.body)));
    if (xmlRpcOpen) {
      recordCheck('wp_xmlrpc', 'XML-RPC Endpoint Exposure Check', 'failed', `HTTP ${xmlRpcRes.statusCode} XML-RPC signature confirmed`);
      pushFinding({
        id: 'xmlrpc_enabled',
        checkId: 'wp_xmlrpc',
        category: 'core_configuration',
        title: 'WordPress XML-RPC API Interface is Openly Accessible',
        severity: 'high',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Direct Endpoint Response Signature Inspection',
        affectedResource: `${baseUrl}/xmlrpc.php`,
        cvssScore: 7.3,
        scoreDeduction: 15,
        description: 'XML-RPC (xmlrpc.php) is active. The system.multicall method allows testing hundreds of login credentials in a single HTTP request, bypassing rate limits.',
        impact: 'Facilitates high-speed distributed brute force attacks and pingback DDoS amplification.',
        evidence: {
          url: `${baseUrl}/xmlrpc.php`,
          statusCode: xmlRpcRes.statusCode,
          details: 'XML-RPC endpoint responded with standard interface banner.'
        },
        remediation: {
          summary: 'Block access to xmlrpc.php at the web server level unless specifically required by legacy mobile apps.',
          steps: [
            'Add blocking rule to .htaccess or Nginx.',
            'Alternatively, use a plugin like "Disable XML-RPC".'
          ],
          codeSnippet: {
            language: 'apache',
            filename: '.htaccess',
            code: `<Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n</Files>`
          }
        }
      });
    } else {
      recordCheck('wp_xmlrpc', 'XML-RPC Endpoint Exposure Check', 'passed', `Returned HTTP ${xmlRpcRes.statusCode}`);
    }
  } catch (err) {
    recordCheck('wp_xmlrpc', 'XML-RPC Endpoint Exposure Check', 'skipped', err instanceof Error ? err.message : 'Probe unreachable');
  }

  // REST API User Enumeration
  try {
    const usersRes = await safeFetch(`${baseUrl}/wp-json/wp/v2/users`, {
      timeoutMs: 5000,
      allowInternalTestTarget: allowInternal
    });
    let exposedUsers = false;
    if (usersRes.statusCode === 200) {
      try {
        const users = JSON.parse(usersRes.body);
        if (Array.isArray(users) && users.length > 0 && users[0].slug) {
          exposedUsers = true;
          const sampleUsers = users.slice(0, 3).map((u: any) => u.slug).join(', ');
          pushFinding({
            id: 'wp_rest_user_enumeration',
            checkId: 'wp_rest_users',
            category: 'user_enumeration',
            title: 'WordPress REST API Discloses Valid Usernames',
            severity: 'high',
            accuracyTier: 'VERIFIED',
            detectionMethod: 'Direct REST API JSON Payload Inspection',
            affectedResource: `${baseUrl}/wp-json/wp/v2/users`,
            cvssScore: 7.1,
            scoreDeduction: 15,
            description: 'The /wp-json/wp/v2/users endpoint is publicly accessible without authentication and returns valid login usernames.',
            impact: 'Attackers obtain exact usernames, reducing credential guessing attacks from 2D (user+password) to 1D (password only).',
            evidence: {
              url: `${baseUrl}/wp-json/wp/v2/users`,
              statusCode: 200,
              details: `Exposed usernames: ${sampleUsers}`
            },
            remediation: {
              summary: 'Restrict access to /wp-json/wp/v2/users for unauthenticated requests.',
              steps: [
                'Add rest_authentication_errors filter in your theme functions.php or security mu-plugin.',
                'Return WP_Error(rest_cannot_access) if !is_user_logged_in().'
              ],
              codeSnippet: {
                language: 'php',
                filename: 'functions.php',
                code: `add_filter('rest_authentication_errors', function($result) {\n    if (!empty($result)) return $result;\n    if (!is_user_logged_in()) {\n        return new WP_Error('rest_forbidden', 'Authentication required.', array('status' => 401));\n    }\n    return $result;\n});`
              }
            }
          });
        }
      } catch {
        // Not JSON
      }
    }
    recordCheck(
      'wp_rest_users',
      'REST API User Enumeration Check',
      exposedUsers ? 'failed' : 'passed',
      exposedUsers ? 'Public JSON user list returned' : `Returned HTTP ${usersRes.statusCode}`
    );
  } catch (err) {
    recordCheck('wp_rest_users', 'REST API User Enumeration Check', 'skipped', err instanceof Error ? err.message : 'Unreachable');
  }

  // Author Archive Enumeration (?author=1)
  try {
    const authorRes = await safeFetch(`${baseUrl}/?author=1`, {
      timeoutMs: 5000,
      maxRedirects: 0,
      allowInternalTestTarget: allowInternal
    });
    const loc = String(authorRes.headers.location || '');
    if ([301, 302].includes(authorRes.statusCode) && loc.includes('/author/')) {
      const usernameMatch = loc.match(/\/author\/([^/]+)/);
      recordCheck('wp_author_enum', 'Author Archive Enumeration Check', 'warning', `Redirected to ${loc}`);
      pushFinding({
        id: 'author_archive_enumeration',
        checkId: 'wp_author_enum',
        category: 'user_enumeration',
        title: 'Author ID Enumeration Discloses Admin Slugs (?author=1)',
        severity: 'medium',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'HTTP Redirect Location Inspection',
        affectedResource: `${baseUrl}/?author=1`,
        cvssScore: 5.3,
        scoreDeduction: 8,
        description: 'Requesting /?author=1 redirects directly to the primary author archive URL, leaking the administrator username.',
        impact: 'Enables targeted dictionary and brute-force attacks against the discovered administrator account.',
        evidence: {
          url: `${baseUrl}/?author=1`,
          statusCode: authorRes.statusCode,
          headerName: 'Location',
          headerValue: loc,
          details: usernameMatch ? `Discovered author slug: ${usernameMatch[1]}` : undefined
        },
        remediation: {
          summary: 'Block or redirect author archive queries for non-administrators.',
          steps: [
            'Add redirect rule in functions.php or .htaccess to return 404 or redirect to home page when is_author() is triggered.'
          ],
          codeSnippet: {
            language: 'php',
            filename: 'functions.php',
            code: `add_action('template_redirect', function() {\n    if (is_author() && !is_admin()) {\n        wp_redirect(home_url(), 301);\n        exit;\n    }\n});`
          }
        }
      });
    } else {
      recordCheck('wp_author_enum', 'Author Archive Enumeration Check', 'passed', `HTTP ${authorRes.statusCode}`);
    }
  } catch (err) {
    recordCheck('wp_author_enum', 'Author Archive Enumeration Check', 'skipped', err instanceof Error ? err.message : 'Unreachable');
  }

  // Uploads Directory Indexing
  try {
    const uploadsRes = await safeFetch(`${baseUrl}/wp-content/uploads/`, {
      timeoutMs: 5000,
      allowInternalTestTarget: allowInternal
    });
    if (uploadsRes.statusCode === 200 && !isSoft404(uploadsRes, soft404Baseline) && isConfirmedDirListing(uploadsRes.body)) {
      recordCheck('wp_uploads_index', 'Uploads Directory Listing Check', 'failed', 'Directory index exposed');
      pushFinding({
        id: 'directory_listing_uploads',
        checkId: 'wp_uploads_index',
        category: 'core_configuration',
        title: 'Directory Listing Enabled on /wp-content/uploads/',
        severity: 'medium',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Directory Index Signature Verification',
        affectedResource: `${baseUrl}/wp-content/uploads/`,
        cvssScore: 5.8,
        scoreDeduction: 8,
        description: 'Directory browsing is enabled on the uploads directory. Anyone can view, index, and download all stored media and documents.',
        impact: 'Exposes private uploads, customer invoices, internal PDFs, and uploaded file structures.',
        evidence: {
          url: `${baseUrl}/wp-content/uploads/`,
          statusCode: 200,
          details: 'Apache/Nginx index listing page returned.'
        },
        remediation: {
          summary: 'Disable directory indexes globally using Options -Indexes.',
          steps: ['Add Options -Indexes to the root .htaccess file or web server block.'],
          codeSnippet: {
            language: 'apache',
            filename: '.htaccess',
            code: `Options -Indexes`
          }
        }
      });
    } else {
      recordCheck('wp_uploads_index', 'Uploads Directory Listing Check', 'passed', `HTTP ${uploadsRes.statusCode}`);
    }
  } catch (err) {
    recordCheck('wp_uploads_index', 'Uploads Directory Listing Check', 'skipped', err instanceof Error ? err.message : 'Unreachable');
  }

  // Debug Log Leakage
  try {
    const debugRes = await safeFetch(`${baseUrl}/wp-content/debug.log`, {
      timeoutMs: 4000,
      allowInternalTestTarget: allowInternal
    });
    if (
      debugRes.statusCode === 200 &&
      !isSoft404(debugRes, soft404Baseline) &&
      ((debugRes.body.includes('[') && debugRes.body.includes('PHP Warning:')) ||
        debugRes.body.includes('PHP Fatal error:') ||
        debugRes.body.includes('PHP Notice:') ||
        debugRes.body.includes('WordPress database error'))
    ) {
      recordCheck('wp_debug_log', 'WordPress debug.log Exposure Check', 'failed', 'Exposed PHP debug log detected');
      pushFinding({
        id: 'debug_log_exposure',
        checkId: 'wp_debug_log',
        category: 'sensitive_files',
        title: 'Exposed WordPress debug.log File (Critical Information Leak)',
        severity: 'critical',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Direct File Probe + PHP Trace Signature Check',
        affectedResource: `${baseUrl}/wp-content/debug.log`,
        cvssScore: 8.6,
        scoreDeduction: 25,
        description: 'The /wp-content/debug.log file is publicly readable. It contains PHP stack traces, database queries, and potentially API secrets.',
        impact: 'Attackers can inspect application errors, database queries, plugin logic, and sensitive parameters.',
        evidence: {
          url: `${baseUrl}/wp-content/debug.log`,
          statusCode: 200,
          details: 'Exposed debug.log containing PHP execution traces.'
        },
        remediation: {
          summary: 'Disable WP_DEBUG_LOG public storage or deny web server access to .log files.',
          steps: [
            'In wp-config.php, set WP_DEBUG_DISPLAY to false and store logs outside web root.',
            'Deny web access to *.log in .htaccess.'
          ],
          codeSnippet: {
            language: 'apache',
            filename: '.htaccess',
            code: `<FilesMatch "\\.log$">\nOrder Deny,Allow\nDeny from all\n</FilesMatch>`
          }
        }
      });
    } else {
      recordCheck('wp_debug_log', 'WordPress debug.log Exposure Check', 'passed', `HTTP ${debugRes.statusCode}`);
    }
  } catch (err) {
    recordCheck('wp_debug_log', 'WordPress debug.log Exposure Check', 'skipped', err instanceof Error ? err.message : 'Unreachable');
  }

  // Open User Registration
  try {
    const regRes = await safeFetch(`${baseUrl}/wp-login.php?action=register`, {
      timeoutMs: 4000,
      allowInternalTestTarget: allowInternal
    });
    if (
      regRes.statusCode === 200 &&
      !isSoft404(regRes, soft404Baseline) &&
      regRes.body.includes('id="user_login"') &&
      regRes.body.includes('id="user_email"') &&
      !regRes.body.includes('User registration is currently not allowed')
    ) {
      pushFinding({
        id: 'open_user_registration',
        checkId: 'wp_open_registration',
        category: 'core_configuration',
        title: 'Public User Registration is Enabled',
        severity: 'low',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Registration Form DOM Inspection',
        affectedResource: `${baseUrl}/wp-login.php?action=register`,
        cvssScore: 3.8,
        scoreDeduction: 3,
        description: 'Anyone can register an account on the WordPress site. Unless your site requires membership, this increases attack surface.',
        impact: 'Facilitates spam bot account generation and exploits targeting subscriber/contributor privileges.',
        evidence: {
          url: `${baseUrl}/wp-login.php?action=register`,
          statusCode: 200
        },
        remediation: {
          summary: 'Disable "Anyone can register" in Settings > General if not needed.',
          steps: [
            'Go to WP Admin > Settings > General.',
            'Uncheck "Membership: Anyone can register" and save.'
          ]
        }
      });
    }
  } catch {
    // Ignore
  }

  // 7. Sensitive File Exposure Checks
  const sensitiveFilesToCheck = [
    {
      path: '/wp-config.php.bak',
      name: 'wp-config.php Backup File',
      severity: 'critical' as FindingSeverity,
      scoreDeduction: 25,
      verify: (body: string) => !/<html/i.test(body) && body.includes('DB_PASSWORD')
    },
    {
      path: '/wp-config.old',
      name: 'wp-config.old File',
      severity: 'critical' as FindingSeverity,
      scoreDeduction: 25,
      verify: (body: string) => !/<html/i.test(body) && body.includes('DB_NAME')
    },
    {
      path: '/.env',
      name: 'Exposed Environment File (.env)',
      severity: 'critical' as FindingSeverity,
      scoreDeduction: 25,
      verify: (body: string) => !/<html/i.test(body) && /^[A-Z0-9_]{2,}=/m.test(body)
    },
    {
      path: '/.git/HEAD',
      name: 'Exposed Git Repository (.git/HEAD)',
      severity: 'critical' as FindingSeverity,
      scoreDeduction: 25,
      verify: (body: string) => !/<html/i.test(body) && /^ref:\s+refs\//m.test(body.trim())
    },
    {
      path: '/backup.sql',
      name: 'Database Backup File (backup.sql)',
      severity: 'critical' as FindingSeverity,
      scoreDeduction: 25,
      verify: (body: string) => !/<html/i.test(body) && body.includes('CREATE TABLE')
    },
    {
      path: '/readme.html',
      name: 'WordPress Core Readme (readme.html)',
      severity: 'low' as FindingSeverity,
      scoreDeduction: 3,
      verify: (body: string) => body.includes('WordPress') && !body.includes('Page not found')
    }
  ];

  let sensitiveProbeErrors = 0;
  let sensitiveExposedCount = 0;

  for (const item of sensitiveFilesToCheck) {
    try {
      const fileRes = await safeFetch(`${baseUrl}${item.path}`, {
        timeoutMs: 3500,
        allowInternalTestTarget: allowInternal
      });
      const isExposed =
        fileRes.statusCode === 200 &&
        !isSoft404(fileRes, soft404Baseline) &&
        !fileRes.body.includes('404 Not Found') &&
        item.verify(fileRes.body);

      if (isExposed) {
        sensitiveExposedCount++;
        pushFinding({
          id: `sensitive_file_${item.path.replace(/[^a-z0-9]/gi, '_')}`,
          checkId: `wp_sensitive_${item.path.replace(/[^a-z0-9]/gi, '_')}`,
          category: 'sensitive_files',
          title: `Sensitive File Publicly Exposed: ${item.path}`,
          severity: item.severity,
          accuracyTier: 'VERIFIED',
          detectionMethod: 'Passive Endpoint Probe with Signature & Soft-404 Verification',
          affectedResource: `${baseUrl}${item.path}`,
          cvssScore: item.severity === 'critical' ? 9.8 : 4.3,
          scoreDeduction: item.scoreDeduction,
          description: `The file ${item.path} was directly downloaded without authentication.`,
          impact:
            item.severity === 'critical'
              ? 'Critical database credentials, source code, or internal cryptographic salts may be compromised.'
              : 'Discloses WordPress architecture and version details to reconnaissance scanners.',
          evidence: {
            url: `${baseUrl}${item.path}`,
            statusCode: 200,
            details: `File contains verified exposure signature (not Soft-404).`
          },
          remediation: {
            summary: `Delete ${item.path} from your web root or block access in web server configuration.`,
            steps: [
              `SSH into the server and run: rm -f ${item.path}`,
              'Add web server rules to deny access to hidden files and backup extensions.'
            ],
            codeSnippet: {
              language: 'apache',
              filename: '.htaccess',
              code: `<FilesMatch "^(\\.|.*\\.bak|.*\\.old|.*\\.sql)$">\nOrder Deny,Allow\nDeny from all\n</FilesMatch>`
            }
          }
        });
      }
    } catch {
      sensitiveProbeErrors++;
    }
  }

  recordCheck(
    'wp_sensitive_files',
    'Sensitive File Exposure Probes',
    sensitiveProbeErrors === sensitiveFilesToCheck.length
      ? 'skipped'
      : sensitiveExposedCount > 0
      ? 'failed'
      : 'passed',
    sensitiveProbeErrors === sensitiveFilesToCheck.length
      ? 'All sensitive file probes timed out'
      : `Checked ${sensitiveFilesToCheck.length - sensitiveProbeErrors}/${sensitiveFilesToCheck.length} paths (${sensitiveExposedCount} exposed)`
  );

  // 8. Public Plugin and Theme Detection
  const pluginRegex = /\/wp-content\/plugins\/([a-zA-Z0-9_\-]+)\/([^\s"'<>]*)/gi;
  let pMatch;
  while ((pMatch = pluginRegex.exec(homeHtml)) !== null) {
    const slug = pMatch[1].toLowerCase();
    const assetTail = pMatch[2] || '';
    const verMatch = assetTail.match(/[\?&]ver=([0-9.]+)/i);
    const existing = detectedPlugins.get(slug);
    if (!existing) {
      detectedPlugins.set(slug, {
        slug,
        name: slug.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
        version: verMatch ? verMatch[1] : undefined,
        detectedVia: 'HTML script/style asset inspection',
        vulnerabilities: []
      });
    } else if (!existing.version && verMatch) {
      existing.version = verMatch[1];
    }
  }

  const themeRegex = /\/wp-content\/themes\/([a-zA-Z0-9_\-]+)\/([^\s"'<>]*)/gi;
  const tMatch = themeRegex.exec(homeHtml);
  if (tMatch) {
    const slug = tMatch[1].toLowerCase();
    const assetTail = tMatch[2] || '';
    const verMatch = assetTail.match(/[\?&]ver=([0-9.]+)/i);
    detectedTheme = {
      slug,
      name: slug.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
      version: verMatch ? verMatch[1] : undefined,
      detectedVia: 'Theme stylesheet link detection'
    };
  }

  // 9. Query WPScan Intelligence for WordPress Core and Detected Plugins
  let totalVulnsCount = 0;
  let liveApiUsed = false;
  let intelligenceStatus = 'Intelligence analysis complete.';

  if (detectedWpVersion) {
    const coreIntel = await fetchVulnerabilitiesForComponent('core', 'wordpress', detectedWpVersion, options.wpscanApiKey);
    if (coreIntel.source.usedLiveApi) liveApiUsed = true;
    intelligenceStatus = coreIntel.source.statusMessage;

    for (const v of coreIntel.vulnerabilities) {
      totalVulnsCount++;
      pushFinding({
        id: `vuln_core_${v.cveId}`,
        checkId: `wp_core_cve_${v.cveId}`,
        category: 'core_configuration',
        title: v.title,
        severity: v.severity,
        accuracyTier: 'LIKELY',
        detectionMethod: 'WordPress Version Fingerprint + CVE Catalog Match',
        affectedResource: `WordPress Core ${detectedWpVersion}`,
        reference: v.references[0],
        cvssScore: v.cvssScore,
        scoreDeduction: v.severity === 'critical' ? 22 : v.severity === 'high' ? 14 : 7,
        description: v.description,
        impact: `Fingerprint indicates WordPress Core ${detectedWpVersion} (prior to ${v.fixedIn}). Confirm active core version in WP Admin.`,
        evidence: {
          details: `Detected Core Version Fingerprint: ${detectedWpVersion} | Affected: ${v.affectedVersions}`
        },
        remediation: {
          summary: `Verify installed WordPress Core version and update to ${v.fixedIn} or the latest available release.`,
          steps: [
            'Create a full database and files backup.',
            'Navigate to WP Admin > Dashboard > Updates.',
            'Confirm version and click "Update Now" if outdated.'
          ]
        },
        cveReferences: [{
          cveId: v.cveId,
          title: v.title,
          fixedIn: v.fixedIn,
          url: v.references[0]
        }]
      });
    }
  }

  for (const [slug, plugin] of detectedPlugins.entries()) {
    const pluginIntel = await fetchVulnerabilitiesForComponent('plugin', slug, plugin.version, options.wpscanApiKey);
    if (pluginIntel.source.usedLiveApi) liveApiUsed = true;

    // Never treat versionless plugin slug matches as verified CVE deductions!
    if (!plugin.version) {
      if (pluginIntel.vulnerabilities.length > 0) {
        pushFinding({
          id: `vuln_plugin_${slug}_unverified`,
          checkId: `wp_plugin_${slug}_version_unknown`,
          category: 'plugins_themes',
          title: `Plugin [${plugin.name}] Detected Without Public Version Number`,
          severity: 'info',
          accuracyTier: 'NOT_VERIFIED',
          detectionMethod: 'HTML Asset Path Slug Fingerprint (No Version Query String)',
          affectedResource: `/wp-content/plugins/${slug}/`,
          scoreDeduction: 0,
          description: `Plugin "${plugin.name}" was referenced in public HTML without a "?ver=" parameter. ${pluginIntel.vulnerabilities.length} historical advisory record(s) exist for older releases of this plugin, so vulnerability status cannot be verified passively.`,
          impact: 'No confirmed vulnerability — exact installed version must be checked inside WP Admin > Plugins.',
          evidence: {
            details: `Plugin slug: ${slug} | Public Version: Unknown | Historical advisories in catalog: ${pluginIntel.vulnerabilities.map((v) => v.cveId).join(', ')}`
          },
          remediation: {
            summary: `Verify the installed version of "${plugin.name}" inside WordPress Admin > Plugins.`,
            steps: [
              'Log in to WP Admin > Plugins.',
              `Confirm "${plugin.name}" is updated past patched versions (${pluginIntel.vulnerabilities.map((v) => v.fixedIn).join(', ')}).`
            ]
          },
          cveReferences: pluginIntel.vulnerabilities.map((v) => ({
            cveId: v.cveId,
            title: v.title,
            fixedIn: v.fixedIn,
            url: v.references[0]
          }))
        });
      }
      continue;
    }

    for (const v of pluginIntel.vulnerabilities) {
      totalVulnsCount++;
      plugin.vulnerabilities.push({
        cveId: v.cveId,
        title: v.title,
        severity: v.severity,
        fixedIn: v.fixedIn
      });

      pushFinding({
        id: `vuln_plugin_${slug}_${v.cveId}`,
        checkId: `wp_plugin_${slug}_${v.cveId}`,
        category: 'plugins_themes',
        title: `Plugin [${plugin.name}] - ${v.title}`,
        severity: v.severity,
        accuracyTier: 'LIKELY',
        detectionMethod: 'Asset Query Version (?ver=) Fingerprint + CVE Catalog Match',
        affectedResource: `${plugin.slug}@${plugin.version}`,
        reference: v.references[0],
        cvssScore: v.cvssScore,
        scoreDeduction: v.severity === 'critical' ? 22 : v.severity === 'high' ? 14 : 7,
        description: v.description,
        impact: `Asset query string (?ver=${plugin.version}) matches vulnerable range for "${plugin.name}". Confirm active plugin version in WP Admin.`,
        evidence: {
          details: `Plugin slug: ${slug} | Asset ?ver=${plugin.version} | Affected: ${v.affectedVersions}`
        },
        remediation: {
          summary: `Verify plugin version in WP Admin and update ${plugin.name} to ${v.fixedIn} or newer.`,
          steps: [
            `Navigate to WP Admin > Plugins.`,
            `Confirm version of "${plugin.name}" and click "Update now" if below ${v.fixedIn}.`
          ],
          codeSnippet: {
            language: 'apache',
            filename: 'wp-cli',
            code: `wp plugin update ${slug}`
          }
        },
        cveReferences: [{
          cveId: v.cveId,
          title: v.title,
          fixedIn: v.fixedIn,
          url: v.references[0]
        }]
      });
    }
  }

  // 10. Deduplicated Deterministic Security Scoring & Coverage Integrity
  const seenKeys = new Set<string>();
  const findings: SecurityFinding[] = [];
  let deduplicatedCount = 0;
  let excludedInformationalOrUnverified = 0;
  let totalDeductions = 0;

  for (const f of rawFindings) {
    const dedupeKey = `${(f.checkId || f.id).toLowerCase()}|${(f.affectedResource || '').toLowerCase()}`;
    if (seenKeys.has(dedupeKey)) {
      deduplicatedCount++;
      continue;
    }
    seenKeys.add(dedupeKey);
    findings.push(f);

    if (
      f.severity === 'info' ||
      f.accuracyTier === 'INFORMATIONAL' ||
      f.accuracyTier === 'NOT_VERIFIED'
    ) {
      excludedInformationalOrUnverified++;
      continue;
    }
    totalDeductions += f.scoreDeduction;
  }

  const coverage: ScanCoverage = {
    totalChecks: checks.length,
    executedChecks: checks.filter((c) => c.status !== 'skipped').length,
    passedChecks: checks.filter((c) => c.status === 'passed').length,
    failedChecks: checks.filter((c) => c.status === 'failed' || c.status === 'warning').length,
    skippedChecks: checks.filter((c) => c.status === 'skipped').length,
    checks
  };

  let finalScore = Math.max(0, Math.min(100, Math.round(100 - totalDeductions)));
  let coverageNote: string | undefined;

  if (coverage.executedChecks === 0) {
    finalScore = 0;
    coverageNote = `0 of ${coverage.totalChecks} checks executed; unable to assign a passing score.`;
  } else if (coverage.skippedChecks > 0) {
    if (finalScore > 94) finalScore = 94;
    coverageNote = `${coverage.skippedChecks} of ${coverage.totalChecks} checks could not complete (skipped/unreachable); A+ requires 100% check completion.`;
  }

  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  if (finalScore >= 95 && coverage.skippedChecks === 0) grade = 'A+';
  else if (finalScore >= 90) grade = 'A';
  else if (finalScore >= 80) grade = 'B';
  else if (finalScore >= 70) grade = 'C';
  else if (finalScore >= 60) grade = 'D';
  else grade = 'F';

  const scoreBreakdown: ScoreBreakdown = {
    startingScore: 100,
    totalDeductions,
    excludedInformationalOrUnverified,
    deduplicatedCount,
    finalScore,
    formulaNote:
      'Start at 100, subtract deduplicated verified/likely finding penalties; INFORMATIONAL and NOT_VERIFIED advisories (including versionless plugin slugs) deduct 0.',
    coverageNote
  };

  const calculateCategoryScore = (category: FindingCategory, baselineChecks: number): CategoryScore => {
    const catFindings = findings.filter(
      (f) => f.category === category && f.severity !== 'info' && f.accuracyTier !== 'NOT_VERIFIED' && f.accuracyTier !== 'INFORMATIONAL'
    );
    const criticals = catFindings.filter((f) => f.severity === 'critical').length;
    const highs = catFindings.filter((f) => f.severity === 'high').length;
    const mediums = catFindings.filter((f) => f.severity === 'medium').length;
    const lows = catFindings.filter((f) => f.severity === 'low').length;

    const catDeduction = criticals * 30 + highs * 20 + mediums * 10 + lows * 5;
    const catScore = Math.max(0, Math.min(100, 100 - catDeduction));
    const failures = criticals + highs;
    const warnings = mediums + lows;
    const passed = Math.max(0, baselineChecks - (failures + warnings));

    return {
      score: catScore,
      totalChecks: baselineChecks,
      passedChecks: passed,
      warnings,
      failures
    };
  };

  const categories = {
    ssl_tls: calculateCategoryScore('ssl_tls', 5),
    security_headers: calculateCategoryScore('security_headers', 7),
    core_configuration: calculateCategoryScore('core_configuration', 6),
    sensitive_files: calculateCategoryScore('sensitive_files', 6),
    plugins_themes: calculateCategoryScore('plugins_themes', Math.max(5, detectedPlugins.size))
  };

  const durationMs = Date.now() - scanStart;
  const nowIso = new Date().toISOString();

  return {
    id: `scan_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    userId,
    targetUrl: baseUrl,
    hostname,
    ipAddress: preflight.ip,
    scanTimestamp: nowIso,
    createdAt: nowIso,
    durationMs,
    isWordPress,
    wpVersion: detectedWpVersion,
    wpVersionLatest: '6.7.1',
    isVersionOutdated: detectedWpVersion ? isVersionOlder(detectedWpVersion, '6.7.0') : false,
    score: finalScore,
    grade,
    categories,
    findings,
    plugins: Array.from(detectedPlugins.values()),
    theme: detectedTheme,
    serverInfo: {
      webServer,
      phpVersion,
      poweredBy,
      hstsEnabled,
      httpsEnforced
    },
    wpscanIntelligence: {
      usedLiveApi: liveApiUsed,
      apiKeyConfigured: Boolean(options.wpscanApiKey || process.env.WPSCAN_API_KEY),
      statusMessage: intelligenceStatus,
      vulnCount: totalVulnsCount
    },
    coverage,
    scoreBreakdown
  };
}
