# Site Sentinel & WP Sentinel — Scan Accuracy & Audit Report

## 1. Executive Summary

Both **WP Sentinel V1** (`/src/lib/scanner-engine.ts`) and **Site Sentinel V2** (`/src/v2/lib/url-crawler.ts`, `/src/v2/lib/zip-analyzer.ts`, `/src/v2/agent/site-sentinel-agent.mjs`, `/src/v2/lib/scoring.ts`) were audited end-to-end to eliminate false positives, enforce evidence-based finding classification, separate passive verification from heuristic fingerprinting, and ensure deterministic, reproducible scoring.

All 12 automated test suites in `tests/run-all.ts` passed (`npm test`, exit code `0`), and production compilation (`npm run build`) succeeded in `1.94s`.

---

## 2. Five-Tier Finding Accuracy Classification

Every finding across V1 (`SecurityFinding.accuracyTier` in `/src/types/scanner.ts`) and V2 (`V2Finding.accuracyTier` in `/src/v2/types/v2.ts`) is classified using the shared 5-tier rubric and UI/PDF guidance utilities (`/src/v2/lib/finding-guidance.ts`):

| Tier | Criteria | Scoring Weight |
| :--- | :--- | :--- |
| **`VERIFIED`** | Direct HTTP response, TLS socket inspection, AST/SAST code location, or local agent POSIX/config inspection confirms the tested condition with concrete evidence. | V1: Full finding penalty; V2: `1.0x` |
| **`LIKELY`** | Strong indicators exist (e.g., detected asset `?ver=` query parameter or manifest dependency version inside an affected CVE range), pending host verification. | V1: Full finding penalty; V2: `0.85x` |
| **`SUSPECTED`** | Heuristic or partial indicator suggests a risk without direct exploitation confirmation (e.g., CORS behavior needing review or unconfirmed REST API exposure). | V1: Full finding penalty; V2: `0.6x` |
| **`INFORMATIONAL`** | Contextual architecture, server signature, or non-vulnerability surface inventory (e.g., technology stack fingerprint, open telemetry note). | **`0` deduction** |
| **`NOT_VERIFIED`** | Presence detected without sufficient version or confirmation evidence (e.g., WordPress plugin slug discovered in HTML without a `?ver=` parameter). | **`0` deduction** |

---

## 3. Module-by-Module Audit & Remediation

### 3.1 WP Sentinel V1 (`/src/lib/scanner-engine.ts`, `/src/lib/vulnerability-db.ts`)
- **Soft-404 Baseline Calibration (`isSoft404`)**: Sends an unguessable nonce probe (`/__wp_sentinel_404_probe_<nonce>`) to measure fallback status codes, `<title>`, body prefix samples, and body lengths so SPA/CMS custom 200-OK fallback pages no longer trigger false-positive exposures for `/.env`, `/.git/HEAD`, `/wp-config.php.bak`, `/wp-config.old`, or `/backup.sql`.
- **Content-Signature Verification**: Exposed file probes reject HTML error templates (`!/<html/i.test(body)`) and assert format signatures (`DB_PASSWORD`, `DB_NAME`, `^[A-Z0-9_]{2,}=`, `^ref:\s+refs/`, `CREATE TABLE`).
- **Strict Directory Index Detection (`isConfirmedDirListing`)**: Requires both `<title>Index of /` or `<h1>Index of /` **and** directory anchor markers (`Parent Directory`, `[DIR]`, `Last modified`, `Size Description`, `<a href=`). Normal HTML pages merely mentioning `"Parent Directory"` in body prose no longer trigger false findings.
- **3-Part Semantic Version Comparison (`isVersionOlder`)**: Fixed multi-digit comparison so `6.10.0` is accurately recognized as newer than `6.7.0` (verified in Test 9).
- **Scoped Asset Version Extraction & Versionless Plugin Rule**: Fixed `/wp-content/plugins/<slug>/([^\s"'<>]*)` (and matching theme regex) so adjacent `<link>`/`<script>` `?ver=` parameters cannot bleed across tag boundaries. Versionless plugin slugs with historical catalog entries are emitted as `severity: 'info'`, `accuracyTier: 'NOT_VERIFIED'`, and `scoreDeduction: 0`.
- **Check Coverage Tracking (`ScanCoverage`) & Score Breakdown (`ScoreBreakdown`)**: Tracks `totalChecks`, `executedChecks`, `passedChecks`, `failedChecks`, `skippedChecks`, and deduplication counts. Zero executed checks force score `0`; skipped checks cap max score at `94` (`A`) so `A+` requires 100% check completion.

### 3.2 Site Sentinel V2 URL Crawler (`/src/v2/lib/url-crawler.ts`)
- **SSRF & DNS Rebinding Guard (`/src/v2/lib/ssrf.ts`)**: Rejects loopback, RFC1918 private ranges, CGNAT, link-local, metadata (`169.254.169.254`), and IPv6 ULA/loopback addresses before socket connections.
- **Soft-404 Calibration & Strict Directory Listing**: Calibrates fallback responses prior to sensitive path probing and confirms `<title>Index of /...` / `<a href=...>` structure for `VERIFIED` directory listing findings.
- **Passive HTTP Security Inspections**: Inspects exact headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), TLS certificate metadata (`inspectTlsCertificate`), `Set-Cookie` attributes (`HttpOnly`, `Secure`, `SameSite`), HTML `<form>` password targets, and CORS origin reflection (`Origin: https://untrusted-audit-check.invalid`).
- **Deterministic Ordering & Evidence Fields**: All findings include `checkId`, `detectionMethod`, `affectedResource`, `observedAt`, and concrete evidence (`url`, `statusCode`, `header`, `snippet`).

### 3.3 Site Sentinel V2 Source ZIP Analyzer (`/src/v2/lib/zip-analyzer.ts`)
- **Archive Safety Limits**: Rejects path traversal (`..` segments, backslash escapes, absolute paths) and ZIP bomb entry count / uncompressed byte inflation (verified in Test 4).
- **Line-Accurate SAST & Secret Redaction**: Reports exact file paths and 1-based line numbers while masking captured credential values before persisting findings.
- **Comment Filtering**: Strips single-line (`//`, `#`) and multi-line (`/* ... */`, `<!-- ... -->`) comments before evaluating SAST sink rules (`eval`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`) so commented-out examples do not generate false positives (verified in Test 11).
- **Semver Dependency Auditing**: Evaluates lockfile/manifest ranges (`lodash@^4.17.21` vs `4.17.15`) against curated CVE boundaries so patched upper-bound semver declarations pass cleanly while vulnerable pins surface as `LIKELY` (verified in Test 11).

### 3.4 Site Sentinel V2 Read-Only Server Agent (`/src/v2/agent/site-sentinel-agent.mjs`, `/src/v2/lib/agent-service.ts`)
- **Import-Safe Read-Only Posture Inspection**: Moved `SENTINEL_TOKEN` requirement into `getAuthHeaders()` called inside `main()` so `inspectReadOnlyPosture()` can be imported cleanly for deterministic verification and unit testing without exiting the process.
- **Observable Host Checks**: Inspects POSIX file permissions (`agent_perm_*` for world/group-readable `.env` files), environment debug flags (`agent_debug_*` for `APP_DEBUG=true` / `DEBUG=true`), listening sockets, firewall/TLS markers, and logs `inspectedChecks` (`passed`/`failed`/`skipped`) into agent reports.

### 3.5 Deterministic V2 Scoring & AI Guardrails (`/src/v2/lib/scoring.ts`, `/src/server/scanner-routes.ts`, `/src/v2/server/v2-routes.ts`)
- **Ordering Invariance & Deduplication**: `deduplicateV2Findings()` deduplicates by `(checkId || title) | resource` and sorts findings deterministically by `id` prior to computing score deductions.
- **Coverage Invariants**: `executedChecks === 0` returns score `0` and grade `'N/A'`; `skippedChecks > 0` caps maximum score at `94` (`A`); `INFORMATIONAL` and `NOT_VERIFIED` deduct `0` points (verified in Test 12).
- **AI Output Framing & Input Validation**: Both `/api/ai/remediate` and `/api/v2/ai/explain` validate payloads cleanly (verified returning HTTP 400 on missing/invalid payloads in Test 13), and UI views wrap AI responses with explicit `"AI Recommendation — Verify Against Observed Evidence Before Applying"` disclaimers so inferred AI text is never confused with direct probe findings.

---

## 4. Verified Automated Test Results (`npm test` / `tsx tests/run-all.ts`)

Executed against the live Express server (`http://127.0.0.1:3000`) and controlled local HTTP/FS fixtures:

1. **PASS**: SSRF private/reserved IPv4 & IPv6 detection
2. **PASS**: V2 Universal URL Crawler (pages, assets, cookies, headers, exposed `.env`, determinism)
3. **PASS**: V2 ZIP Analyzer (SAST line numbers, secret redaction, dependency CVEs)
4. **PASS**: V2 ZIP Analyzer rejects path traversal and ZIP bombs
5. **PASS**: V2 Scoring deterministic ordering invariance
6. **PASS**: Live Server Cross-Version V1 & V2 HTTP API Verification
7. **PASS**: Actionable finding guidance helpers distinguish 5 accuracy tiers
8. **PASS**: V1 WordPress scanner accuracy (Soft-404, `6.10.0` semver, strict dir listing, versionless plugin)
9. **PASS**: V2 URL Crawler Soft-404 filtering and confirmed directory index detection
10. **PASS**: V2 ZIP Analyzer semver boundaries & comment filtering prevent false positives
11. **PASS**: V2 Agent posture inspection & scoring zero-coverage / partial-coverage invariants
12. **PASS**: AI remediation & explanation endpoints validate payloads cleanly

*(Note: Live HTTP tests exercise controlled local HTTP fixtures plus `https://example.com` for public header/crawl integration; WPScan external API calls fall back to the built-in curated catalog when `WPSCAN_API_KEY` is absent in the container environment.)*
