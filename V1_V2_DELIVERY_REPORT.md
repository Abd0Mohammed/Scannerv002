# WP Sentinel V1 & Site Sentinel V2 — Delivery & QA Report

## 1. Architecture & Version Separation
- **Option A (Coexisting Versioned Modules)** was implemented on port `3000`:
  - **V1 (WP Sentinel)** remains preserved in `/src/components/*`, `/src/lib/*`, `/src/server/scanner-routes.ts`, `/api/*`, and Firestore `/users/{uid}/scans` + `/users/{uid}/sites`.
  - **V2 (Site Sentinel)** is cleanly isolated in `/src/v2/*`, mounted at `/api/v2/*` in both `vite.config.ts` and `server.ts`, and stored in separate Firestore subcollections (`/users/{uid}/v2_scans`, `/users/{uid}/v2_agents`, `/users/{uid}/v2_audit_logs`).
  - Users can switch seamlessly between editions via the top edition bar (`?v=1` / `?v=2`).

## 2. V1 Preserved & Maintenance Bugs Fixed
### V1 Preserved Functionality
- Landing page, Email/Password & Google Auth (`AuthContext.tsx`), Dashboard, Monitored Sites verification (`meta` tag & DNS TXT), Scan Comparison modal, SentinAI Gemini endpoints (`/api/ai/remediate`, `/api/ai/chat`), WPScan token validation (`/api/wpscan/test-key`), and V1 PDF generation (`pdf-report.ts`).

### V1 Bugs Found & Fixed
1. **Node v22 `safeFetch` DNS Pinning Failure (`src/lib/ssrf.ts`)**: Node v22 invokes custom `lookup(hostname, { all: true }, cb)`; the original callback always returned `(null, ip, family)`, causing `Invalid IP address: undefined` (HTTP 502) on real scans (`example.com`). Fixed to inspect `lookupOptions.all` and return `[{ address: ip, family }]`.
2. **Firestore Rule Schema Mismatch (`src/types/scanner.ts`, `src/lib/scanner-engine.ts`)**: `ScanResult` omitted `createdAt`, which `firestore.rules` `isValidScan()` requires. Added `createdAt: nowIso`.
3. **Firestore `undefined` Crash & Missing Error Handlers (`src/App.tsx`)**: Added recursive `stripUndefined()` before `setDoc()` calls, wrapped scan/site writes in `try/catch` with `handleFirestoreError()`, replaced `window.alert` in `handleOpenCompare`, and cleared `monitoredSites` on logout.
4. **Settings Modal State Sync (`src/components/SettingsModal.tsx`)**: Synced `apiKey` state with `userProfile?.wpscanApiKey` on modal reopen and added visible `saveError` feedback when unauthenticated.

## 3. V2 Implemented Features
- **Universal URL Scanner & Crawler (`/src/v2/lib/url-crawler.ts`, `/src/v2/lib/ssrf.ts`)**:
  - Authorization attestation gate, SSRF IPv4/IPv6 + metadata blocking, DNS pinning, redirect scope enforcement (`same-origin` / `include-subdomains`), configurable `maxPages` (1–25) & `maxDepth` (1–3).
  - Live `node:tls` certificate inspection, HTTP->HTTPS enforcement, security headers, `Set-Cookie` flag auditing, `robots.txt` + `sitemap.xml` parsing, asset inventory (pages, JS, CSS, images, documents, password forms), multi-stack tech fingerprinting, stack trace detection, and soft-404-verified sensitive file probes.
  - Async scan jobs with live progress polling (`GET /api/v2/scan/jobs/:jobId`).
- **Hardened ZIP Project Analyzer (`/src/v2/lib/zip-analyzer.ts`)**:
  - In-memory analysis (`multer` + `jszip`) with zero code execution.
  - Rejects ZIP bombs (15 MB compressed, 60 MB uncompressed, 5 MB/file, 2,000 files, 50:1 compression ratio), path traversal (`..`, absolute paths), and Unix symlinks.
  - Multi-ecosystem manifest parsing & CVE advisories (`npm`, `composer`, `pip`, `go`, `maven`, `nuget`), secret pattern & high-entropy detection with strict value redaction, config checks, and line-level SAST with `file:line` evidence.
- **Authorized Read-Only Server Agent (`/src/v2/lib/agent-service.ts`, `/src/v2/agent/site-sentinel-agent.mjs`)**:
  - Revocable `ss_agent_...` bearer credentials stored exclusively as SHA-256 hashes server-side; heartbeats, read-only posture checks, report ingestion, and revocation (`401` immediately enforced).
- **Deterministic Scoring, Reporting, Audit Logs & UI**:
  - Order-invariant scoring engine (`/src/v2/lib/scoring.ts`), multi-section V2 PDF & JSON export (`/src/v2/lib/v2-pdf-report.ts`), server audit log (`/api/v2/audit-logs`), optional Gemini finding explainer (`/api/v2/ai/explain`), and complete V2 React workspace (`/src/v2/components/*`).
- **Firestore Rules Deployed**:
  - Updated `firestore.rules` & `firebase-blueprint.json` with `v2_scans`, `v2_agents`, and immutable `v2_audit_logs` under `/users/{userId}`, and deployed via `deploy_firebase`.

## 4. Verification & Test Evidence
- `npm run lint` (`tsc --noEmit`): Passed (exit code 0).
- `npm run build` (`vite build`): Passed.
- `npm test` (`tsx tests/run-all.ts`): Passed all 6 test suites:
  - `PASS: SSRF private/reserved IPv4 & IPv6 detection`
  - `PASS: V2 Universal URL Crawler (pages, assets, cookies, headers, exposed .env, determinism)`
  - `PASS: V2 ZIP Analyzer (SAST line numbers, secret redaction, dependency CVEs)`
  - `PASS: V2 ZIP Analyzer rejects path traversal and ZIP bombs`
  - `PASS: V2 Scoring deterministic ordering invariance`
  - `PASS: Live Server Cross-Version V1 & V2 HTTP API Verification` (including V1 `example.com`, V2 `example.com`, SSRF blocks, multipart ZIP upload, agent register/heartbeat/report/revoke->401, script download, and audit logs).
- Live CLI Agent E2E (`node src/v2/agent/site-sentinel-agent.mjs`): Executed against a temporary directory with world-readable `.env` (`APP_DEBUG=true`); uploaded report (`Score: 65/100 (Grade C), Findings: 3`).

## 5. Limitations & Deployment Readiness
- **Unauthenticated / Ephemeral Runtime State**: V2 agent credentials, async scan jobs, and server-side audit logs persist to `/tmp/site-sentinel-v2-state.json` (plus Firestore mirroring when signed in on the client); for multi-instance horizontal scaling, move server-side agent token hashes to a shared database/Firebase Admin SDK.
- **SPA Rendering**: The V2 URL crawler performs passive HTTP HTML fetching (no headless browser JS execution), so client-only SPAs without SSR may yield fewer DOM links.
- **Gemini AI Assistant**: Server-side `/api/v2/ai/explain` and V1 `/api/ai/*` require `GEMINI_API_KEY` in the runtime environment; when absent, endpoints cleanly return HTTP `503` while deterministic scanning and scoring operate normally.
- **Production Deployment**: Ready for single-container deployment via `npm run build` followed by `npm run start` (`tsx server.ts` on port `3000`).
