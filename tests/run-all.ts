import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';
import { executeWordPressScan } from '../src/lib/scanner-engine.ts';
import { executeUniversalUrlScan } from '../src/v2/lib/url-crawler.ts';
import { analyzeZipArchive } from '../src/v2/lib/zip-analyzer.ts';
import { calculateV2Scores } from '../src/v2/lib/scoring.ts';
import { isPrivateOrReservedIp } from '../src/v2/lib/ssrf.ts';
import { inspectReadOnlyPosture } from '../src/v2/agent/site-sentinel-agent.mjs';
import {
  getAccuracyDisplay,
  getAccuracyTier,
  getConfidenceDisplay,
  getPlainExplanation,
  getSafeVerifySteps,
  getStatusDisplay
} from '../src/v2/lib/finding-guidance.ts';

const BASE_URL = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';

async function test(name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    console.log(`PASS: ${name}`);
  } catch (err) {
    console.error(`FAIL: ${name}`);
    throw err;
  }
}

async function run() {
  console.log('=== WP Sentinel V1 + Site Sentinel V2 Automated Verification ===\n');

  // 1. V2 SSRF IP Range Unit Checks
  await test('SSRF private/reserved IPv4 & IPv6 detection', () => {
    assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('10.0.0.5'), true);
    assert.equal(isPrivateOrReservedIp('172.16.4.1'), true);
    assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
    assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
    assert.equal(isPrivateOrReservedIp('::1'), true);
    assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
    assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
  });

  // 2. V2 Controlled URL Crawler against ephemeral local fixture server
  await test('V2 Universal URL Crawler (pages, assets, cookies, headers, exposed .env, determinism)', async () => {
    const server = http.createServer((req, res) => {
      if (req.url === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n');
        return;
      }
      if (req.url === '/sitemap.xml') {
        res.writeHead(200, { 'Content-Type': 'application/xml' });
        res.end(`<urlset><url><loc>http://127.0.0.1:${port}/about</loc></url></urlset>`);
        return;
      }
      if (req.url === '/about') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>About</title></head><body><p>About page</p></body></html>');
        return;
      }
      if (req.url === '/.env') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('APP_KEY=test_secret_123\nDB_HOST=127.0.0.1\n');
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'text/html',
        'X-Powered-By': 'Express',
        'Set-Cookie': 'sid=abc123; Path=/'
      });
      res.end(`<!doctype html><html><head><title>Fixture App</title>
        <link rel="stylesheet" href="/app.css">
        <script src="/bundle.js"></script>
      </head><body>
        <img src="/logo.png" />
        <a href="/about">About</a>
        <a href="/policy.pdf">Policy</a>
        <a href="https://external.example.org/out">Out-of-scope</a>
        <form action="/login" method="POST"><input type="password" name="pw"></form>
      </body></html>`);
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    try {
      const scanA = await executeUniversalUrlScan(`http://127.0.0.1:${port}/`, {
        maxPages: 5,
        maxDepth: 2,
        scope: 'same-origin',
        authorizedAttestation: true,
        allowInternalTestTarget: true
      });
      const scanB = await executeUniversalUrlScan(`http://127.0.0.1:${port}/`, {
        maxPages: 5,
        maxDepth: 2,
        scope: 'same-origin',
        authorizedAttestation: true,
        allowInternalTestTarget: true
      });

      // Deterministic score check
      assert.equal(scanA.score, scanB.score);
      assert.equal(scanA.grade, scanB.grade);

      // Asset discovery checks
      assert.ok(scanA.urlDetails, 'urlDetails present');
      assert.equal(scanA.urlDetails.assets.robotsTxt.found, true);
      assert.equal(scanA.urlDetails.assets.sitemapXml.found, true);
      assert.ok(scanA.urlDetails.assets.pages.length >= 2, 'Crawled root + /about');
      assert.ok(scanA.urlDetails.assets.pages.every((p) => p.url.startsWith(`http://127.0.0.1:${port}`)), 'Scope respected');
      assert.ok(scanA.urlDetails.assets.scripts.some((s) => s.endsWith('/bundle.js')));
      assert.ok(scanA.urlDetails.assets.stylesheets.some((s) => s.endsWith('/app.css')));
      assert.ok(scanA.urlDetails.assets.images.some((s) => s.endsWith('/logo.png')));
      assert.ok(scanA.urlDetails.assets.documents.some((s) => s.endsWith('/policy.pdf')));

      // Tech, cookie, exposure findings
      assert.ok(scanA.technologies.some((t) => t.name === 'Express'));
      assert.ok(scanA.urlDetails.cookies.some((c) => c.name === 'sid' && !c.httpOnly));
      assert.ok(scanA.findings.some((f) => f.title.includes('/.env')));
      assert.ok(scanA.findings.some((f) => f.title.includes('Password Form')));
    } finally {
      server.close();
    }
  });

  // 3. V2 ZIP Analyzer: Secrets redaction, CVE detection, line-level SAST
  await test('V2 ZIP Analyzer (SAST line numbers, secret redaction, dependency CVEs)', async () => {
    const zip = new JSZip();
    const fakeAwsKey = 'AKIA' + '1234567890ABCDEF';
    zip.file(
      'package.json',
      JSON.stringify({
        name: 'demo-app',
        dependencies: { react: '^19.0.0', lodash: '3.10.1' }
      })
    );
    zip.file('.env', 'DEBUG=True\nPORT=3000\n');
    zip.file(
      'src/app.js',
      `const key = "${fakeAwsKey}";\nconst out = eval("1 + 1");\n`
    );
    const buffer = await zip.generateAsync({ type: 'nodebuffer' });

    const result = await analyzeZipArchive(buffer, 'demo-app.zip', {
      authorizedAttestation: true
    });

    assert.equal(result.mode, 'zip');
    assert.ok(result.technologies.some((t) => t.name === 'React'));
    assert.ok(result.findings.some((f) => f.evidence.package?.includes('lodash@3.10.1')));
    assert.ok(result.findings.some((f) => f.title.includes('.env')));
    const secretFinding = result.findings.find((f) => f.title.includes('AWS Access Key'));
    assert.ok(secretFinding, 'Detected AWS key pattern');
    assert.equal(secretFinding.evidence.file, 'src/app.js');
    assert.equal(secretFinding.evidence.line, 1);
    assert.ok(!JSON.stringify(result).includes(fakeAwsKey), 'Raw secret must be redacted');

    const evalFinding = result.findings.find((f) => f.title.includes('eval()'));
    assert.ok(evalFinding, 'Detected eval() SAST sink');
    assert.equal(evalFinding.evidence.line, 2);
  });

  // 4. V2 ZIP Security Blocks (Path Traversal & ZIP Bomb ratio)
  await test('V2 ZIP Analyzer rejects path traversal and ZIP bombs', async () => {
    const traversalZip = new JSZip();
    traversalZip.file('../../etc/passwd', 'root:x:0:0:root:/root:/bin/bash');
    const travBuf = await traversalZip.generateAsync({ type: 'nodebuffer' });
    await assert.rejects(() => analyzeZipArchive(travBuf, 'evil.zip'), /Unsafe path traversal/);

    const bombZip = new JSZip();
    bombZip.file('zeros.txt', Buffer.alloc(600 * 1024, 'A'));
    const bombBuf = await bombZip.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: { level: 9 }
    });
    await assert.rejects(() => analyzeZipArchive(bombBuf, 'bomb.zip'), /ZIP bomb|compression ratio/);
  });

  // 5. Scoring determinism unit check
  await test('V2 Scoring deterministic ordering invariance', () => {
    const f1 = {
      id: 'b',
      title: 'T2',
      severity: 'high' as const,
      category: 'Headers & Cookies',
      confidence: 'confirmed' as const,
      description: '',
      impact: '',
      remediation: '',
      evidence: {}
    };
    const f2 = {
      id: 'a',
      title: 'T1',
      severity: 'medium' as const,
      category: 'Transport & TLS',
      confidence: 'probable' as const,
      description: '',
      impact: '',
      remediation: '',
      evidence: {}
    };
    assert.deepEqual(calculateV2Scores([f1, f2]), calculateV2Scores([f2, f1]));
  });

  // 6. Live HTTP Integration Tests against running server on port 3000 (V1 + V2 + Cross-Version)
  await test('Live Server Cross-Version V1 & V2 HTTP API Verification', async () => {
    const v2Health = await fetch(`${BASE_URL}/api/v2/health`);
    assert.equal(v2Health.status, 200);

    // V1 SSRF block preserved
    const v1Ssrf = await fetch(`${BASE_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'http://127.0.0.1' })
    });
    assert.equal(v1Ssrf.status, 400);

    // V2 SSRF block + Authorization enforcement
    const v2NoAuth = await fetch(`${BASE_URL}/api/v2/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'https://example.com', authorizedAttestation: false })
    });
    assert.equal(v2NoAuth.status, 400);

    const v2Ssrf = await fetch(`${BASE_URL}/api/v2/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'http://169.254.169.254/latest/meta-data', authorizedAttestation: true })
    });
    assert.equal(v2Ssrf.status, 400);

    // V2 Real URL Scan (example.com)
    const v2UrlRes = await fetch(`${BASE_URL}/api/v2/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetUrl: 'https://example.com',
        maxPages: 3,
        maxDepth: 1,
        authorizedAttestation: true
      })
    });
    assert.equal(v2UrlRes.status, 200);
    const v2Scan = await v2UrlRes.json();
    assert.equal(v2Scan.version, 'v2');
    assert.equal(v2Scan.mode, 'url');
    assert.ok(v2Scan.urlDetails?.tls?.valid === true);

    // V2 Agent Lifecycle: Register -> Heartbeat -> Report -> Revoke -> 401
    const regRes = await fetch(`${BASE_URL}/api/v2/agent/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'qa-test-host', environment: 'staging' })
    });
    assert.equal(regRes.status, 201);
    const { agent, plainTextToken } = await regRes.json();
    assert.ok(plainTextToken.startsWith('ss_agent_'));

    const hbRes = await fetch(`${BASE_URL}/api/v2/agent/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${plainTextToken}`
      },
      body: JSON.stringify({ hostname: 'qa-box', osInfo: 'Linux', agentVersion: '2.0.0' })
    });
    assert.equal(hbRes.status, 200);

    const repRes = await fetch(`${BASE_URL}/api/v2/agent/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${plainTextToken}`
      },
      body: JSON.stringify({
        hostname: 'qa-box',
        osPlatform: 'linux',
        runtimeVersion: process.version,
        checkedPaths: 4,
        findings: []
      })
    });
    assert.equal(repRes.status, 201);

    const revRes = await fetch(`${BASE_URL}/api/v2/agent/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId: agent.id })
    });
    assert.equal(revRes.status, 200);

    const postRevokeRes = await fetch(`${BASE_URL}/api/v2/agent/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${plainTextToken}`
      },
      body: JSON.stringify({ hostname: 'qa-box' })
    });
    assert.equal(postRevokeRes.status, 401);

    // V2 Agent Script download & Audit logs
    const scriptRes = await fetch(`${BASE_URL}/api/v2/agent/script`);
    assert.equal(scriptRes.status, 200);
    const scriptText = await scriptRes.text();
    assert.ok(scriptText.includes('site-sentinel-agent') || scriptText.includes('SENTINEL_TOKEN'));

    const auditRes = await fetch(`${BASE_URL}/api/v2/audit-logs`);
    assert.equal(auditRes.status, 200);
    const auditData = await auditRes.json();
    assert.ok(Array.isArray(auditData.logs) && auditData.logs.length > 0);

    // V2 HTTP Multipart ZIP upload
    const httpZip = new JSZip();
    httpZip.file('package.json', JSON.stringify({ name: 'http-test', dependencies: { axios: '0.21.1' } }));
    httpZip.file('index.js', 'const html = x => { document.write(x); };\n');
    const httpZipBuf = await httpZip.generateAsync({ type: 'nodebuffer' });
    const form = new FormData();
    form.append('archive', new Blob([new Uint8Array(httpZipBuf)], { type: 'application/zip' }), 'http-test.zip');
    form.append('authorizedAttestation', 'true');
    const zipUploadRes = await fetch(`${BASE_URL}/api/v2/scan/zip`, {
      method: 'POST',
      body: form
    });
    assert.equal(zipUploadRes.status, 200);
    const zipUploadJson = await zipUploadRes.json();
    assert.equal(zipUploadJson.mode, 'zip');
    assert.ok(zipUploadJson.findings.some((f: { evidence?: { package?: string } }) => f.evidence?.package?.includes('axios@0.21.1')));

    // V1 Real Scan still intact
    const v1Real = await fetch(`${BASE_URL}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: 'https://example.com' })
    });
    assert.equal(v1Real.status, 200);
    const v1Data = await v1Real.json();
    assert.equal(v1Data.isWordPress, false);
    assert.ok(v1Data.createdAt);

    // 7. Strict Per-User Tenant Isolation (Agents, Reports, Revocation, Audit Logs)
    const regUserA = await fetch(`${BASE_URL}/api/v2/agent/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'alpha-host', environment: 'production', userId: 'uid_alpha_test' })
    });
    assert.equal(regUserA.status, 201);
    const { agent: agentA, plainTextToken: tokenA } = await regUserA.json();

    const repUserA = await fetch(`${BASE_URL}/api/v2/agent/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${tokenA}`
      },
      body: JSON.stringify({
        hostname: 'alpha-host.internal',
        osPlatform: 'linux',
        runtimeVersion: process.version,
        checkedPaths: 2,
        findings: []
      })
    });
    assert.equal(repUserA.status, 201);

    // User B and anonymous must NOT see User A's agent, reports, or audit logs
    const listUserB = await fetch(`${BASE_URL}/api/v2/agent/list?userId=uid_beta_test`).then((r) => r.json());
    assert.equal(listUserB.agents.some((a: { id: string }) => a.id === agentA.id), false);

    const listAnon = await fetch(`${BASE_URL}/api/v2/agent/list`).then((r) => r.json());
    assert.equal(listAnon.agents.some((a: { id: string }) => a.id === agentA.id), false);

    const reportsUserB = await fetch(`${BASE_URL}/api/v2/agent/reports?userId=uid_beta_test`).then((r) => r.json());
    assert.equal(
      reportsUserB.reports.some((r: { userId: string }) => r.userId === 'uid_alpha_test'),
      false
    );

    const auditUserB = await fetch(`${BASE_URL}/api/v2/audit-logs?userId=uid_beta_test`).then((r) => r.json());
    assert.equal(
      auditUserB.logs.some((l: { userId: string }) => l.userId === 'uid_alpha_test'),
      false
    );

    // User B must NOT be able to revoke User A's agent
    const crossRevoke = await fetch(`${BASE_URL}/api/v2/agent/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId: agentA.id, userId: 'uid_beta_test' })
    });
    assert.equal(crossRevoke.status, 404);

    // Cleanup revoke by owner User A succeeds
    const ownerRevoke = await fetch(`${BASE_URL}/api/v2/agent/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId: agentA.id, userId: 'uid_alpha_test' })
    });
    assert.equal(ownerRevoke.status, 200);
  });

  // 8. Actionable Finding Guidance Helpers (Plain English, 5-Tier Accuracy Distinction, Safe Verification)
  await test('Actionable finding guidance helpers distinguish 5 accuracy tiers', () => {
    assert.equal(getConfidenceDisplay('confirmed').label, 'Verified');
    assert.equal(getConfidenceDisplay('probable').label, 'Suspected');
    assert.equal(getConfidenceDisplay('inconclusive').label, 'Not Verified');

    assert.equal(getAccuracyDisplay('VERIFIED').label, 'Verified');
    assert.equal(getAccuracyDisplay('LIKELY').label, 'Likely');
    assert.equal(getAccuracyDisplay('SUSPECTED').label, 'Suspected');
    assert.equal(getAccuracyDisplay('INFORMATIONAL').label, 'Informational');
    assert.equal(getAccuracyDisplay('NOT_VERIFIED').label, 'Not Verified');

    assert.equal(getStatusDisplay(undefined).label, 'Unresolved');
    assert.equal(getStatusDisplay('resolved').label, 'Resolved');
    assert.equal(getStatusDisplay('accepted_risk').label, 'Accepted Risk');

    const sampleFinding = {
      id: 'f1',
      title: 'Missing Strict-Transport-Security Header',
      severity: 'medium' as const,
      category: 'Headers & Cookies',
      confidence: 'confirmed' as const,
      accuracyTier: 'VERIFIED' as const,
      description: 'HSTS header is absent.',
      impact: 'First visit could be downgraded.',
      remediation: 'Enable HSTS.',
      evidence: {
        url: 'https://example.com',
        header: 'Strict-Transport-Security: Missing'
      }
    };
    assert.equal(getAccuracyTier(sampleFinding), 'VERIFIED');
    const plain = getPlainExplanation(sampleFinding);
    const verify = getSafeVerifySteps(sampleFinding);
    assert.ok(plain.includes('HTTPS'));
    assert.ok(verify.includes('curl -sI'));
  });

  // 9. V1 WordPress Controlled Accuracy Fixtures (Soft-404, Semver, Directory Index, Versionless Plugin)
  await test('V1 WordPress scanner accuracy (Soft-404, 6.10.0 semver, strict dir listing, versionless plugin)', async () => {
    const server = http.createServer((req, res) => {
      const reqUrl = req.url || '/';
      if (reqUrl === '/' || reqUrl === '') {
        res.writeHead(200, { 'Content-Type': 'text/html', Server: 'nginx' });
        res.end(`<!doctype html><html><head>
          <meta name="generator" content="WordPress 6.10.0" />
          <link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.css" />
          <script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.3.0"></script>
        </head><body><h1>Fixture WordPress</h1></body></html>`);
        return;
      }
      if (reqUrl === '/wp-content/uploads/' || reqUrl === '/wp-content/uploads') {
        // Mentions "Parent Directory" in normal prose, NOT an actual Apache/Nginx directory index
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>Uploads Info</title></head><body><p>Parent Directory docs are protected.</p></body></html>');
        return;
      }
      if (reqUrl === '/wp-json/wp/v2/users' || reqUrl === '/xmlrpc.php' || reqUrl === '/wp-login.php') {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }
      // Soft-404 handler for every missing route (including /.env, /.git/HEAD, /wp-config.php.bak)
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>Not Found</title></head><body><h1>Custom Page Not Found</h1><p>Fallback template.</p></body></html>');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    try {
      const scan = await executeWordPressScan(`http://127.0.0.1:${port}/`, {
        allowInternalTestTarget: true
      });

      assert.equal(scan.isWordPress, true);
      assert.equal(scan.wpVersion, '6.10.0');
      assert.equal(scan.isVersionOutdated, false, '6.10.0 must NOT be treated as older than 6.7.0');
      assert.equal(
        scan.findings.some((f) => f.title.includes('.env') || f.title.includes('.git') || f.title.includes('wp-config')),
        false,
        'Soft-404 200 HTML must NOT trigger sensitive file exposures'
      );
      assert.equal(
        scan.findings.some((f) => f.title.includes('Directory Listing')),
        false,
        'Normal HTML mentioning Parent Directory without Index structure must NOT trigger directory listing'
      );

      const unversionedElementor = scan.findings.find(
        (f) =>
          ((f.affectedResource || '').toLowerCase().includes('elementor') ||
            f.title.toLowerCase().includes('elementor')) &&
          f.accuracyTier === 'NOT_VERIFIED'
      );
      assert.ok(unversionedElementor, 'Versionless plugin must be classified NOT_VERIFIED');
      assert.equal(unversionedElementor.scoreDeduction, 0, 'NOT_VERIFIED plugin must deduct 0 points');
      assert.equal(unversionedElementor.severity, 'info');

      const cf7Finding = scan.findings.find(
        (f) =>
          (f.affectedResource || '').toLowerCase().includes('contact-form-7') ||
          f.title.toLowerCase().includes('contact form 7')
      );
      assert.ok(cf7Finding, 'Versioned vulnerable plugin should be flagged');
      assert.equal(cf7Finding.accuracyTier, 'LIKELY');

      assert.ok(scan.coverage && scan.coverage.executedChecks > 0, 'Coverage tracked');
      assert.ok(scan.scoreBreakdown && scan.scoreBreakdown.formulaNote.length > 0, 'Score breakdown tracked');
    } finally {
      server.close();
    }
  });

  // 10. V2 URL Crawler Soft-404 & Confirmed Directory Listing Accuracy Fixtures
  await test('V2 URL Crawler Soft-404 filtering and confirmed directory index detection', async () => {
    const server = http.createServer((req, res) => {
      const reqUrl = req.url || '/';
      if (reqUrl === '/' || reqUrl === '') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>Home</title></head><body><a href="/uploads/">Uploads</a></body></html>');
        return;
      }
      if (reqUrl === '/uploads/' || reqUrl === '/uploads') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><a href="Parent">Parent Directory</a><a href="secret.tar">secret.tar</a></body></html>');
        return;
      }
      // Soft-404 catch-all for missing paths (/.env, /.git/HEAD, etc.)
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>Fallback</title></head><body><p>Nothing matched your route.</p></body></html>');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    try {
      const result = await executeUniversalUrlScan(`http://127.0.0.1:${port}/`, {
        maxPages: 5,
        maxDepth: 1,
        authorizedAttestation: true,
        allowInternalTestTarget: true
      });
      assert.equal(
        result.findings.some((f) => f.title.includes('/.env') || f.title.includes('.git/HEAD')),
        false,
        'Soft-404 200 HTML must NOT trigger sensitive file exposures in V2'
      );
      const dirListing = result.findings.find((f) => f.title.includes('Directory Listing'));
      assert.ok(dirListing, 'Real Apache/Nginx Index of /uploads/ must be detected');
      assert.equal(dirListing.accuracyTier, 'VERIFIED');
      assert.ok(result.coverage && result.coverage.executedChecks > 0);
      assert.ok(result.scoreBreakdown);
    } finally {
      server.close();
    }
  });

  // 11. V2 ZIP Analyzer Semver Boundaries & Comment SAST Filtering
  await test('V2 ZIP Analyzer semver boundaries & comment filtering prevent false positives', async () => {
    const zip = new JSZip();
    zip.file(
      'package.json',
      JSON.stringify({
        name: 'clean-edge',
        dependencies: {
          lodash: '^4.17.21',
          express: '4.19.2'
        }
      })
    );
    zip.file(
      'src/safe.js',
      `// eval(userInput)\n/* el.innerHTML = untrustedHtml; */\nexport const ok = true;\n`
    );
    const cleanBuf = await zip.generateAsync({ type: 'nodebuffer' });
    const cleanRes = await analyzeZipArchive(cleanBuf, 'clean.zip', { authorizedAttestation: true });
    assert.equal(cleanRes.findings.some((f) => f.evidence.package?.includes('lodash')), false, '4.17.21 is patched');
    assert.equal(cleanRes.findings.some((f) => f.title.includes('eval()')), false, 'Commented eval() ignored');
    assert.equal(cleanRes.findings.some((f) => f.title.includes('innerHTML')), false, 'Commented innerHTML ignored');

    const vulnZip = new JSZip();
    vulnZip.file('package.json', JSON.stringify({ dependencies: { lodash: '4.17.15' } }));
    const vulnBuf = await vulnZip.generateAsync({ type: 'nodebuffer' });
    const vulnRes = await analyzeZipArchive(vulnBuf, 'vuln.zip', { authorizedAttestation: true });
    const lodashVuln = vulnRes.findings.find((f) => f.evidence.package?.includes('lodash@4.17.15'));
    assert.ok(lodashVuln, 'lodash 4.17.15 properly flagged');
    assert.equal(lodashVuln.accuracyTier, 'LIKELY');
  });

  // 12. V2 Server Agent Posture & Scoring Invariants (No Fake 100/A+ on 0 Checks; Partial Cap <= 94)
  await test('V2 Agent posture inspection & scoring zero-coverage / partial-coverage invariants', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-agent-fixture-'));
    try {
      const envPath = path.join(tmpDir, '.env');
      fs.writeFileSync(envPath, 'DEBUG=true\nNODE_ENV=development\n', 'utf-8');
      fs.chmodSync(envPath, 0o644);

      const posture = inspectReadOnlyPosture(tmpDir);
      assert.ok(posture.inspectedChecks.some((c: { id: string; status: string }) => c.id === 'agent_perm_.env' && c.status === 'failed'));
      assert.ok(posture.findings.some((f: { checkId: string }) => f.checkId === 'agent_perm_.env'));
      assert.ok(posture.findings.some((f: { checkId: string }) => f.checkId === 'agent_debug_.env'));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    const zeroCoverageResult = calculateV2Scores([], {
      totalChecks: 3,
      executedChecks: 0,
      passedChecks: 0,
      failedChecks: 0,
      skippedChecks: 3,
      checks: []
    });
    assert.equal(zeroCoverageResult.score, 0);
    assert.equal(zeroCoverageResult.grade, 'N/A');

    const partialCoverageResult = calculateV2Scores(
      [
        {
          id: 'info-1',
          title: 'Informational Note',
          severity: 'info',
          category: 'Headers & Cookies',
          confidence: 'confirmed',
          accuracyTier: 'INFORMATIONAL',
          description: '',
          impact: '',
          remediation: '',
          evidence: {}
        },
        {
          id: 'unv-1',
          title: 'Unverified Heuristic',
          severity: 'medium',
          category: 'Code & Secrets',
          confidence: 'inconclusive',
          accuracyTier: 'NOT_VERIFIED',
          description: '',
          impact: '',
          remediation: '',
          evidence: {}
        }
      ],
      {
        totalChecks: 5,
        executedChecks: 4,
        passedChecks: 4,
        failedChecks: 0,
        skippedChecks: 1,
        checks: []
      }
    );
    assert.equal(partialCoverageResult.score, 94, 'Partial coverage must cap score at 94 and exclude info/unverified');
    assert.equal(partialCoverageResult.grade, 'A');
  });

  // 13. AI Endpoint Validation & Graceful Degradation Without API Key
  await test('AI remediation & explanation endpoints validate payloads cleanly', async () => {
    const v1Bad = await fetch(`${BASE_URL}/api/ai/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(v1Bad.status, 400);

    const v2Bad = await fetch(`${BASE_URL}/api/v2/ai/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.equal(v2Bad.status, 400);
  });

  console.log('\nALL AUTOMATED TESTS PASSED.');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
