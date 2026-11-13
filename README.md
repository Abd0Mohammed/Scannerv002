# WP Sentinel — Enterprise WordPress Security Intelligence & Passive Vulnerability Scanner

WP Sentinel is a production-grade, passive WordPress security auditor and threat intelligence application. It conducts non-intrusive, safe HTTP evaluations of WordPress sites, performs SSRF-hardened audits against 30+ vulnerability vectors, correlates findings with WPScan and NIST CVE intelligence, computes deterministic security scores, generates executive PDF reports, and provides an interactive AI security advisor powered by Gemini 3.8 Flash.

---

## 1. Project Architecture

### Core Modules
- **Safe HTTP & SSRF Defense Layer (`/src/lib/ssrf.ts`)**:
  - DNS pre-flight address validation.
  - Strict blocking of private IP ranges (RFC 1918), loopback (`127.0.0.0/8`, `::1`), link-local / cloud metadata endpoints (`169.254.169.254`), broadcast, and multicast addresses.
  - Re-verifies DNS resolution on every redirect hop (max 3 redirects).
  - Enforces response size bounds (2MB) and connection timeouts (8s) to mitigate Denial of Wallet / Resource Exhaustion attacks.

- **Passive WordPress Audit Engine (`/src/lib/scanner-engine.ts`)**:
  - **WordPress Core Detection**: Meta generator parsing, `/wp-content/` script/style patterns, `/wp-json/` namespace inspection, `/wp-login.php` verification, and version extraction.
  - **Transport Security & SSL/TLS**: HTTPS enforcement, plain HTTP-to-HTTPS redirect audits, and mixed content risk checks.
  - **HTTP Security Headers**: HSTS duration, Content-Security-Policy (CSP), X-Frame-Options (Clickjacking), X-Content-Type-Options: nosniff, Referrer-Policy, and technology leak suppression (`Server`, `X-Powered-By`).
  - **Core Configuration Hardening**: XML-RPC active interface check (`/xmlrpc.php`), unauthenticated REST API user enumeration (`/wp-json/wp/v2/users`), author ID archive redirection (`/?author=1`), directory indexing on uploads (`/wp-content/uploads/`), debug log leakage (`/wp-content/debug.log`), and open user registration.
  - **Sensitive File Exposures**: Passive detection of backup archives (`wp-config.php.bak`, `wp-config.old`), `.env`, `.git/HEAD`, database dumps (`backup.sql`), and version disclosure files (`readme.html`).
  - **Component Detection**: Passive extraction of active plugin slugs and theme stylesheets from public HTML DOM with version query parameter correlation.

- **Threat Intelligence & WPScan Engine (`/src/lib/wpscan-client.ts`, `/src/lib/vulnerability-db.ts`)**:
  - Direct integration with official WPScan API (`https://wpscan.com/api/v3/`).
  - Built-in Curated Intelligence Catalog featuring NIST & WPScan CVE records for WordPress Core and high-impact plugins (Elementor, WooCommerce, LiteSpeed Cache, Contact Form 7, Really Simple SSL, Yoast SEO, Slider Revolution).

- **Deterministic Scoring & Grading Model**:
  - 100-point baseline with weighted CVSS risk deductions:
    - Critical Severity: -25 pts
    - High Severity: -15 pts
    - Medium Severity: -8 pts
    - Low Severity: -3 pts
  - Grading Scale: A+ (95-100), A (90-94), B (80-89), C (70-79), D (60-69), F (<60).
  - Categorical sub-scores for SSL/TLS, Headers, Core Hardening, Sensitive Files, and Plugins/Themes.

- **SentinAI Gemini Security Advisor (`/src/server/scanner-routes.ts`)**:
  - Powered by `@google/genai` model `gemini-3.8-flash`.
  - Generates exact `.htaccess`, `nginx.conf`, `wp-config.php`, and `functions.php` copy-paste server snippets tailored to the user's specific web server and audit findings.
  - Interactive SecOps chat assistant for technical explanations and threat remediation.

- **Executive PDF Report Generator (`/src/lib/pdf-report.ts`)**:
  - Multi-page client-ready PDF generated using `jspdf`.
  - Includes score gauge, categorical breakdown, detected plugins table, finding matrices with CVSS ratings, and step-by-step remediation snippets.

- **Domain Ownership Verification**:
  - Token-based verification via HTML `<meta name="wp-sentinel-verification" content="...">` or DNS TXT records (`wpsentinel=...`).

- **Firebase Data Architecture & Hardened ABAC Security**:
  - Firestore backend storing user profiles, scan records, and monitored fleet websites.
  - Strict Attribute-Based Access Control (`firestore.rules`) enforcing default-deny, `request.auth.uid == userId` checks, size bounds, and immutable owner IDs.

---

## 2. Environment Variables

Create a `.env` file or configure via AI Studio Secrets:

```bash
# GEMINI_API_KEY: Required for SentinAI security advisor and code generation
GEMINI_API_KEY="your-google-gemini-api-key"

# WPSCAN_API_KEY: Optional. If omitted, WP Sentinel uses its built-in curated CVE database
WPSCAN_API_KEY="your-wpscan-api-token"

# PORT: Server listening port (defaults to 3000)
PORT=3000

# APP_URL: Self-referential URL injected in Cloud Run / preview environments
APP_URL="http://localhost:3000"
```

---

## 3. Firebase Configuration

Firebase credentials are auto-injected from `firebase-applet-config.json`. The Firestore database and Auth rules are managed via:
- Schema blueprint: `firebase-blueprint.json`
- Hardened rules: `firestore.rules` (deployed via `DeployRules` RPC)

To enable Google sign-in:
- Google Popup authentication is configured by default.

---

## 4. Development & Build Commands

### Install Dependencies
```bash
npm install
```

### Run Development Server (Vite with API Middleware)
```bash
npm run dev
```
The server will boot on `http://localhost:3000`.

### Type-Check & Lint
```bash
npm run lint
```

### Build for Production
```bash
npm run build
```

### Run Full-Stack Production Server
```bash
npm run start
```

---

## 5. Deployment Instructions

1. **Verify Build**:
   ```bash
   npm run build
   ```
2. **Deploy to Cloud Run / Docker**:
   Use standard Node.js 22+ base image:
   ```dockerfile
   FROM node:22-alpine
   WORKDIR /app
   COPY package*.json ./
   RUN npm ci --omit=dev
   COPY . .
   RUN npm run build
   EXPOSE 3000
   CMD ["npm", "run", "start"]
   ```

---

## 6. Known Limitations & Safe Operations

- **Passive Auditing Only**: WP Sentinel intentionally does not perform intrusive exploits, brute force attacks, or database manipulation.
- **Credential Masking**: If a sensitive file is detected, signatures are verified without displaying or leaking database passwords or cryptographic salts in reports.
- **WPScan Live API Quota**: When operating with a free WPScan API key (25 requests/day), WP Sentinel transparently caches results and switches to its built-in curated catalog when quota is reached.

---

## 7. Site Sentinel V2 (Universal Security Platform)

Site Sentinel V2 operates alongside WP Sentinel V1 via clean version separation (`src/v2/*`, `/api/v2/*`, and separate Firestore subcollections), accessible via the top edition switcher or `?v=2`.

### V2 Capabilities
1. **Universal URL Scanner & Controlled Crawler (`/src/v2/lib/url-crawler.ts`)**:
   - Enforces explicit user authorization attestation, SSRF IP blocking, DNS rebinding pinning, and origin/subdomain scope boundaries.
   - Inspects `robots.txt` and `sitemap.xml`, executes bounded BFS crawling (`maxPages`, `maxDepth`), extracts pages, JS, CSS, images, documents, and HTML forms.
   - Performs live TLS certificate handshake verification (`node:tls`), HTTP security header checks, `Set-Cookie` flag auditing (`HttpOnly`, `Secure`, `SameSite`), multi-stack technology fingerprinting (WordPress, Laravel, React, Next.js, Vue, Angular, Express, Django, ASP.NET, Nginx, Apache, Cloudflare), and soft-404-resistant sensitive file checks.
   - Supports asynchronous job polling (`POST /api/v2/scan/url` with `async: true` and `GET /api/v2/scan/jobs/:jobId`).
2. **Hardened ZIP Project Analyzer (`/src/v2/lib/zip-analyzer.ts`)**:
   - Processes archives strictly in-memory via `jszip` + `multer` (never executes project code or runs package managers).
   - Rejects ZIP bombs (15 MB compressed cap, 60 MB uncompressed cap, 5 MB/file, 2,000 entries, 50:1 max compression ratio), path traversal (`..`, absolute paths), and Unix symlinks.
   - Parses dependency manifests (`package.json`, `composer.json`, `requirements.txt`, `go.mod`, `pom.xml`, `*.csproj`) against known advisories, detects and redacts hardcoded secrets/high-entropy literals, flags config flaws (`.env`, `DEBUG=True`, wildcard CORS), and runs line-level SAST checks with exact `file:line` evidence.
3. **Authorized Read-Only Server Agent (`/src/v2/lib/agent-service.ts`, `/src/v2/agent/site-sentinel-agent.mjs`)**:
   - Generates revocable `ss_agent_...` bearer credentials stored server-side as SHA-256 hashes only.
   - Downloadable zero-dependency Node.js inspection script audits file permissions and production debug flags in read-only mode, posting heartbeats and structured findings to `/api/v2/agent/*`.
4. **V2 Data & Security Rules (`/firestore.rules`, `/firebase-blueprint.json`)**:
   - V2 records are isolated in `/users/{userId}/v2_scans`, `/users/{userId}/v2_agents`, and immutable `/users/{userId}/v2_audit_logs`.

### Automated Verification (`npm test`)
```bash
npm test
```
Runs `tsx tests/run-all.ts` covering V1 regression, SSRF IP validation, V2 local HTTP crawler verification, V2 ZIP SAST/secret-redaction/ZIP-bomb/traversal checks, deterministic scoring, and live `/api/*` + `/api/v2/*` endpoint verification.

