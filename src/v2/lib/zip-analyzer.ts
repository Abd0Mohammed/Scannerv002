import JSZip from 'jszip';
import { calculateV2Scores } from './scoring.ts';
import {
  V2Finding,
  V2ScanResult,
  V2Technology,
  V2ZipDetails,
  V2ZipManifest
} from '../types/v2.ts';

export const ZIP_LIMITS = {
  maxCompressedBytes: 15 * 1024 * 1024, // 15 MB
  maxUncompressedBytes: 60 * 1024 * 1024, // 60 MB
  maxSingleFileBytes: 5 * 1024 * 1024, // 5 MB
  maxEntryCount: 2000,
  maxCompressionRatio: 50
};

const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.php', '.phtml', '.py', '.rb', '.go', '.java', '.cs',
  '.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.config',
  '.env', '.xml', '.html', '.htm', '.vue', '.svelte', '.sql', '.sh',
  '.dockerfile', '.txt', '.md', '.csproj', '.lock'
]);

const SKIP_DIRS = ['node_modules/', '.git/', 'vendor/', 'dist/', 'build/', '__pycache__/', '.next/'];

function redactSecret(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length <= 8) return '****';
  return `${trimmed.slice(0, 4)}****${trimmed.slice(-4)}`;
}

function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getExtension(filePath: string): string {
  const base = (filePath.split('/').pop() || '').toLowerCase();
  if (base === 'dockerfile') return '.dockerfile';
  if (base === '.env' || base.startsWith('.env.')) return '.env';
  const idx = base.lastIndexOf('.');
  return idx >= 0 ? base.slice(idx) : '';
}

function isUnsafeZipPath(entryName: string): boolean {
  if (!entryName || entryName.includes('\0')) return true;
  if (entryName.startsWith('/') || entryName.startsWith('\\')) return true;
  if (/^[a-zA-Z]:/.test(entryName)) return true;
  const normalized = entryName.replace(/\\/g, '/');
  const segments = normalized.split('/');
  return segments.some((seg) => seg === '..');
}

function isSymlinkEntry(entry: JSZip.JSZipObject): boolean {
  const unixPerms = (entry as unknown as { unixPermissions?: number | null }).unixPermissions;
  if (typeof unixPerms === 'number' && (unixPerms & 0o170000) === 0o120000) {
    return true;
  }
  return false;
}

interface AdvisoryRule {
  ecosystem: V2ZipManifest['ecosystem'];
  pkg: string;
  fixedVersion: string;
  severity: V2Finding['severity'];
  cve: string;
  reference: string;
  title: string;
  remediation: string;
}

const KNOWN_ADVISORIES: AdvisoryRule[] = [
  {
    ecosystem: 'npm',
    pkg: 'lodash',
    fixedVersion: '4.17.21',
    severity: 'high',
    cve: 'CVE-2021-23337',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
    title: 'Outdated lodash version vulnerable to Prototype Pollution & Command Injection',
    remediation: 'Upgrade lodash to >= 4.17.21 and run npm audit fix.'
  },
  {
    ecosystem: 'npm',
    pkg: 'axios',
    fixedVersion: '1.6.0',
    severity: 'high',
    cve: 'CVE-2023-45857',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2023-45857',
    title: 'Outdated axios (< 1.6.0) exposes CSRF & SSRF vectors',
    remediation: 'Upgrade axios to >= 1.6.0.'
  },
  {
    ecosystem: 'npm',
    pkg: 'express',
    fixedVersion: '4.19.2',
    severity: 'medium',
    cve: 'CVE-2024-29041',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29041',
    title: 'Outdated Express (< 4.19.2) open redirect vulnerability',
    remediation: 'Upgrade Express to >= 4.19.2 or 5.x.'
  },
  {
    ecosystem: 'npm',
    pkg: 'jsonwebtoken',
    fixedVersion: '9.0.0',
    severity: 'high',
    cve: 'CVE-2022-23529',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-23529',
    title: 'Outdated jsonwebtoken (< 9.0.0) susceptible to key verification bypass',
    remediation: 'Upgrade jsonwebtoken to >= 9.0.0.'
  },
  {
    ecosystem: 'npm',
    pkg: 'next',
    fixedVersion: '14.2.0',
    severity: 'medium',
    cve: 'CVE-2024-34351',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-34351',
    title: 'Outdated Next.js (< 14.2.0) SSRF & cache vulnerability',
    remediation: 'Upgrade Next.js to >= 14.2.x or 15.x.'
  },
  {
    ecosystem: 'pip',
    pkg: 'django',
    fixedVersion: '4.2.0',
    severity: 'high',
    cve: 'CVE-2023-43665',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2023-43665',
    title: 'Legacy Django (< 4.2.0) contains known DoS & SQLi vulnerabilities',
    remediation: 'Upgrade Django to a supported LTS release (>= 4.2 or 5.x).'
  },
  {
    ecosystem: 'pip',
    pkg: 'flask',
    fixedVersion: '2.3.2',
    severity: 'medium',
    cve: 'CVE-2023-30861',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2023-30861',
    title: 'Legacy Flask (< 2.3.2) susceptible to session cookie disclosure on Vary header',
    remediation: 'Upgrade Flask to >= 2.3.2 or 3.x.'
  },
  {
    ecosystem: 'pip',
    pkg: 'pyyaml',
    fixedVersion: '6.0.0',
    severity: 'critical',
    cve: 'CVE-2020-14343',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2020-14343',
    title: 'Outdated PyYAML (< 6.0.0) vulnerable to arbitrary code execution via FullLoader',
    remediation: 'Upgrade PyYAML to >= 6.0 and always use yaml.safe_load().'
  },
  {
    ecosystem: 'composer',
    pkg: 'laravel/framework',
    fixedVersion: '10.0.0',
    severity: 'medium',
    cve: 'CVE-2021-3129',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-3129',
    title: 'Legacy Laravel framework (< 10.0.0) version detected',
    remediation: 'Upgrade laravel/framework to >= 10.x or 11.x and ensure APP_DEBUG=false.'
  },
  {
    ecosystem: 'composer',
    pkg: 'guzzlehttp/guzzle',
    fixedVersion: '7.4.5',
    severity: 'high',
    cve: 'CVE-2022-31090',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31090',
    title: 'Outdated Guzzle (< 7.4.5) leaks Authorization headers across redirects',
    remediation: 'Upgrade guzzlehttp/guzzle to >= 7.4.5.'
  }
];

function parseVersionParts(raw: string): number[] | null {
  const m = raw.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return [
    parseInt(m[1], 10) || 0,
    parseInt(m[2] ?? '0', 10) || 0,
    parseInt(m[3] ?? '0', 10) || 0
  ];
}

function isSemverOlder(version: string, fixedVersion: string): boolean {
  const v1 = parseVersionParts(version);
  const v2 = parseVersionParts(fixedVersion);
  if (!v1 || !v2) return false;
  for (let i = 0; i < 3; i++) {
    if (v1[i] < v2[i]) return true;
    if (v1[i] > v2[i]) return false;
  }
  return false;
}

function isRangeSpecifier(versionSpec: string): boolean {
  const trimmed = versionSpec.trim();
  return /^[\^~><*]/.test(trimmed) || trimmed.includes('x') || trimmed.includes('||');
}

function cweReferenceUrl(cwe?: string): string | undefined {
  if (!cwe) return undefined;
  const num = cwe.replace(/[^0-9]/g, '');
  return num ? `https://cwe.mitre.org/data/definitions/${num}.html` : undefined;
}

function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('<!--')
  );
}

interface SecretPattern {
  id: string;
  title: string;
  severity: V2Finding['severity'];
  regex: RegExp;
  cwe: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key',
    title: 'Hardcoded AWS Access Key ID Detected',
    severity: 'critical',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    cwe: 'CWE-798'
  },
  {
    id: 'github-pat',
    title: 'Hardcoded GitHub Personal Access Token Detected',
    severity: 'critical',
    regex: /\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    cwe: 'CWE-798'
  },
  {
    id: 'stripe-live-key',
    title: 'Hardcoded Stripe Live Secret Key Detected',
    severity: 'critical',
    regex: /\b(sk_live_[0-9a-zA-Z]{16,})\b/g,
    cwe: 'CWE-798'
  },
  {
    id: 'private-key-block',
    title: 'Embedded Private Cryptographic Key Detected',
    severity: 'critical',
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,
    cwe: 'CWE-321'
  },
  {
    id: 'google-api-key',
    title: 'Hardcoded Google API Key Pattern Detected',
    severity: 'high',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    cwe: 'CWE-798'
  },
  {
    id: 'db-uri-creds',
    title: 'Database Connection String with Embedded Credentials',
    severity: 'high',
    regex: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"']+:[^@\s"']+@[^/\s"']+)/gi,
    cwe: 'CWE-798'
  },
  {
    id: 'generic-secret-assign',
    title: 'Hardcoded Secret / Password Assignment Detected',
    severity: 'high',
    regex: /(?:secret_key|jwt_secret|api_secret|db_password|admin_password|private_key)\s*[:=]\s*["']([^"'\n]{8,})["']/gi,
    cwe: 'CWE-798'
  }
];

interface SastPattern {
  id: string;
  title: string;
  severity: V2Finding['severity'];
  category: string;
  regex: RegExp;
  cwe: string;
  owasp: string;
  description: string;
  impact: string;
  remediation: string;
  extensions?: string[];
}

const SAST_PATTERNS: SastPattern[] = [
  {
    id: 'sast-eval-exec',
    title: 'Dynamic Code Execution via eval() or new Function()',
    severity: 'high',
    category: 'Code & Secrets',
    regex: /\b(eval\s*\(|new\s+Function\s*\()/,
    cwe: 'CWE-95',
    owasp: 'A03:2021 Injection',
    description: 'Dynamic code execution evaluates strings as runtime code, introducing severe RCE/XSS risk if user input reaches the call.',
    impact: 'Attackers supplying controlled input can execute arbitrary code or scripts.',
    remediation: 'Replace eval() and new Function() with safe JSON parsing, explicit lookup maps, or structured AST evaluators.',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.php', '.py']
  },
  {
    id: 'sast-command-exec',
    title: 'Potential OS Command Injection Sink',
    severity: 'high',
    category: 'Code & Secrets',
    regex: /\b(child_process\.exec\s*\(|execSync\s*\(.*\$\{|shell_exec\s*\(|system\s*\(\s*\$|os\.system\s*\(|subprocess\.(?:run|Popen)\s*\([^)]*shell\s*=\s*True)/,
    cwe: 'CWE-78',
    owasp: 'A03:2021 Injection',
    description: 'Shell execution API invoked with shell interpolation or shell=True semantics.',
    impact: 'Unsanitized parameters can allow attackers to chain arbitrary operating system commands.',
    remediation: 'Use execFile/spawn or subprocess with argument arrays and shell: false; strictly validate inputs.',
    extensions: ['.js', '.ts', '.mjs', '.cjs', '.php', '.py']
  },
  {
    id: 'sast-xss-sink',
    title: 'Unescaped DOM / HTML Injection Sink',
    severity: 'medium',
    category: 'Code & Secrets',
    regex: /(dangerouslySetInnerHTML\s*=|\.innerHTML\s*=|document\.write\s*\()/,
    cwe: 'CWE-79',
    owasp: 'A03:2021 Injection',
    description: 'Raw HTML insertion sink detected in frontend template or DOM manipulation code.',
    impact: 'If untrusted or user-controlled data flows into this sink, attackers can execute Cross-Site Scripting (XSS).',
    remediation: 'Use framework text bindings instead of raw HTML injection, or sanitize with DOMPurify before rendering.',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.vue', '.html', '.htm']
  },
  {
    id: 'sast-sqli-interp',
    title: 'String-Interpolated SQL Query Construction',
    severity: 'high',
    category: 'Code & Secrets',
    regex: /(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;\n]*(?:\$\{[^}]+\}|\.\s*\$_(?:GET|POST|REQUEST)|%\s*\()/i,
    cwe: 'CWE-89',
    owasp: 'A03:2021 Injection',
    description: 'SQL query appears to concatenate or interpolate runtime variables directly inside SQL syntax.',
    impact: 'Allows SQL Injection attackers to read, modify, or delete database records.',
    remediation: 'Use parameterized queries / prepared statements ($1, ?, PDO bindParam, ORM query builders).',
    extensions: ['.js', '.ts', '.mjs', '.cjs', '.php', '.py', '.java', '.go', '.cs']
  },
  {
    id: 'sast-tls-bypass',
    title: 'TLS Certificate Verification Disabled',
    severity: 'high',
    category: 'Transport & TLS',
    regex: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true)/,
    cwe: 'CWE-295',
    owasp: 'A02:2021 Cryptographic Failures',
    description: 'Code explicitly disables TLS certificate validation for outbound connections.',
    impact: 'Exposes outbound API calls and credentials to Man-in-the-Middle (MitM) interception.',
    remediation: 'Remove TLS verification bypass flags and configure valid CA trust stores.',
    extensions: ['.js', '.ts', '.mjs', '.cjs', '.py', '.go', '.env', '.yaml', '.yml']
  },
  {
    id: 'sast-weak-hash',
    title: 'Weak Cryptographic Hash Algorithm (MD5 / SHA1)',
    severity: 'low',
    category: 'Code & Secrets',
    regex: /(createHash\s*\(\s*['"](?:md5|sha1)['"]\)|hashlib\.(?:md5|sha1)\s*\(|\b(?:md5|sha1)\s*\()/i,
    cwe: 'CWE-328',
    owasp: 'A02:2021 Cryptographic Failures',
    description: 'Usage of collision-prone MD5 or SHA-1 hash function detected.',
    impact: 'Unsuitable for password hashing, signatures, or integrity verification.',
    remediation: 'Use SHA-256/SHA-512 for digests and Argon2id/bcrypt/scrypt for password hashing.',
    extensions: ['.js', '.ts', '.mjs', '.cjs', '.php', '.py', '.go']
  }
];

export async function analyzeZipArchive(
  buffer: Buffer,
  archiveName: string,
  options: { userId?: string; authorizedAttestation?: boolean } = {}
): Promise<V2ScanResult> {
  const startTime = Date.now();

  if (buffer.length > ZIP_LIMITS.maxCompressedBytes) {
    throw new Error(
      `Archive exceeds maximum compressed size limit (${Math.round(ZIP_LIMITS.maxCompressedBytes / (1024 * 1024))} MB).`
    );
  }

  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch {
    throw new Error('Invalid or corrupted ZIP archive.');
  }

  const allEntries = Object.values(zip.files);
  const fileEntries = allEntries.filter((e) => !e.dir);

  if (fileEntries.length > ZIP_LIMITS.maxEntryCount) {
    throw new Error(`Archive contains ${fileEntries.length} files, exceeding the safety cap of ${ZIP_LIMITS.maxEntryCount}.`);
  }

  // Pre-decompression security audit (traversal, symlink, header ZIP bomb ratios)
  let declaredUncompressedTotal = 0;
  for (const entry of allEntries) {
    if (isUnsafeZipPath(entry.name)) {
      throw new Error(`Security Block: Unsafe path traversal entry detected ("${entry.name}").`);
    }
    if (isSymlinkEntry(entry)) {
      throw new Error(`Security Block: Symbolic link entries are rejected ("${entry.name}").`);
    }

    const internalData = (entry as unknown as {
      _data?: { compressedSize?: number; uncompressedSize?: number };
    })._data;
    if (internalData) {
      const comp = internalData.compressedSize || 0;
      const uncomp = internalData.uncompressedSize || 0;
      declaredUncompressedTotal += uncomp;
      if (uncomp > ZIP_LIMITS.maxSingleFileBytes) {
        throw new Error(`Security Block: Entry "${entry.name}" exceeds 5MB per-file extraction limit.`);
      }
      if (uncomp > 100 * 1024 && comp > 0 && uncomp / comp > ZIP_LIMITS.maxCompressionRatio) {
        throw new Error(`Security Block: Potential ZIP bomb detected in "${entry.name}" (compression ratio > ${ZIP_LIMITS.maxCompressionRatio}:1).`);
      }
    }
  }

  if (declaredUncompressedTotal > ZIP_LIMITS.maxUncompressedBytes) {
    throw new Error('Security Block: Total uncompressed archive size exceeds 60MB safety limit.');
  }

  const findings: V2Finding[] = [];
  const techMap = new Map<string, V2Technology>();
  const langCounts = new Map<string, number>();
  const manifests: V2ZipManifest[] = [];
  const fileTreeSample: string[] = [];

  let actualUncompressedTotal = 0;
  let analyzedFiles = 0;
  let skippedFiles = 0;
  let findingCounter = 1;
  const dedupeKeys = new Set<string>();

  type AddZipFindingInput = Omit<V2Finding, 'id' | 'observedAt'> & { checkId: string };
  const addFinding = (f: AddZipFindingInput) => {
    const affectedResource =
      f.affectedResource ||
      (f.evidence.file ? `${f.evidence.file}${f.evidence.line ? `:${f.evidence.line}` : ''}` : f.evidence.package || archiveName);
    const key = `${f.checkId}|${affectedResource}|${f.evidence.package || ''}`.toLowerCase();
    if (dedupeKeys.has(key)) return;
    dedupeKeys.add(key);
    findings.push({
      ...f,
      affectedResource,
      observedAt: new Date().toISOString(),
      reference: f.reference || cweReferenceUrl(f.cwe),
      id: `v2zip_${findingCounter++}`
    });
  };

  let envFilesFound = 0;
  let secretsFound = 0;
  let sastFindingsCount = 0;
  let configIssuesFound = 0;
  let dependencyAdvisoriesFound = 0;

  for (const entry of fileEntries) {
    const normalizedPath = entry.name.replace(/\\/g, '/');
    if (fileTreeSample.length < 60) {
      fileTreeSample.push(normalizedPath);
    }

    const lowerPath = normalizedPath.toLowerCase();
    if (SKIP_DIRS.some((dir) => lowerPath.includes(`/${dir}`) || lowerPath.startsWith(dir))) {
      skippedFiles++;
      continue;
    }

    const ext = getExtension(normalizedPath);
    if (!TEXT_EXTENSIONS.has(ext)) {
      skippedFiles++;
      continue;
    }

    const rawBytes = await entry.async('uint8array');
    actualUncompressedTotal += rawBytes.byteLength;
    if (
      rawBytes.byteLength > ZIP_LIMITS.maxSingleFileBytes ||
      actualUncompressedTotal > ZIP_LIMITS.maxUncompressedBytes ||
      (actualUncompressedTotal > 256 * 1024 &&
        buffer.length > 0 &&
        actualUncompressedTotal / buffer.length > ZIP_LIMITS.maxCompressionRatio)
    ) {
      throw new Error('Security Block: Decompressed stream exceeded maximum memory or compression ratio safety limit.');
    }

    analyzedFiles++;
    const content = Buffer.from(rawBytes).toString('utf-8');

    const langLabel =
      ext === '.ts' || ext === '.tsx' ? 'TypeScript' :
      ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs' ? 'JavaScript' :
      ext === '.php' || ext === '.phtml' ? 'PHP' :
      ext === '.py' ? 'Python' :
      ext === '.go' ? 'Go' :
      ext === '.java' ? 'Java' :
      ext === '.cs' ? 'C# / .NET' :
      ext === '.vue' ? 'Vue' :
      ext === '.sql' ? 'SQL' :
      null;
    if (langLabel) {
      langCounts.set(langLabel, (langCounts.get(langLabel) || 0) + 1);
    }

    const baseName = normalizedPath.split('/').pop()?.toLowerCase() || '';
    if (baseName === '.env' || baseName === '.env.local' || baseName === '.env.production') {
      envFilesFound++;
      addFinding({
        checkId: 'zip_committed_env',
        title: `Committed Environment File Detected (${baseName})`,
        severity: 'high',
        category: 'Code & Secrets',
        confidence: 'confirmed',
        accuracyTier: 'VERIFIED',
        detectionMethod: 'Archive Entry Filename Inspection',
        affectedResource: normalizedPath,
        description: `Sensitive environment configuration file "${normalizedPath}" was packaged directly inside the archive.`,
        impact: 'Environment files commonly store database credentials, signing keys, and third-party API secrets.',
        remediation: 'Remove .env files from source archives/git history, add .env* to .gitignore, and rotate any exposed secrets.',
        evidence: { file: normalizedPath, detail: `${rawBytes.byteLength} bytes` },
        cwe: 'CWE-538',
        owasp: 'A05:2021 Security Misconfiguration'
      });
    }

    if (baseName.startsWith('.env') || ext === '.py' || ext === '.php' || ext === '.json' || ext === '.yml' || ext === '.yaml') {
      if (/\bDEBUG\s*=\s*True\b/i.test(content) || /\bAPP_DEBUG\s*=\s*true\b/i.test(content)) {
        const lines = content.split(/\r?\n/);
        const lineIdx = lines.findIndex((l) => !isCommentLine(l) && /\b(?:DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true)\b/i.test(l));
        if (lineIdx >= 0) {
          configIssuesFound++;
          addFinding({
            checkId: 'zip_debug_enabled',
            title: 'Debug Mode Enabled in Application Configuration',
            severity: 'medium',
            category: 'Code & Secrets',
            confidence: 'confirmed',
            accuracyTier: 'VERIFIED',
            detectionMethod: 'Configuration File Line Inspection',
            affectedResource: `${normalizedPath}:${lineIdx + 1}`,
            description: 'Debug mode is explicitly enabled in configuration, which can expose stack traces and environment variables in production.',
            impact: 'Attackers triggering errors receive internal file paths, query strings, and configuration secrets.',
            remediation: 'Set DEBUG=False / APP_DEBUG=false in production configuration templates.',
            evidence: {
              file: normalizedPath,
              line: lineIdx + 1,
              snippet: lines[lineIdx].trim().slice(0, 120)
            },
            cwe: 'CWE-489',
            owasp: 'A05:2021 Security Misconfiguration'
          });
        }
      }
    }

    if (/cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]/i.test(content) || /Access-Control-Allow-Origin['":\s]+\*/i.test(content)) {
      const lines = content.split(/\r?\n/);
      const lineIdx = lines.findIndex(
        (l) => !isCommentLine(l) && /origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['":\s]+\*/i.test(l)
      );
      if (lineIdx >= 0) {
        configIssuesFound++;
        addFinding({
          checkId: 'zip_wildcard_cors',
          title: 'Wildcard CORS Policy Configured (*)',
          severity: 'medium',
          category: 'Headers & Cookies',
          confidence: 'probable',
          accuracyTier: 'SUSPECTED',
          detectionMethod: 'Static Configuration Pattern Inspection',
          affectedResource: `${normalizedPath}:${lineIdx + 1}`,
          description: 'Cross-Origin Resource Sharing appears configured with wildcard origin (*).',
          impact: 'Permits arbitrary third-party websites to read API responses unless strictly public.',
          remediation: 'Restrict CORS allowed origins to an explicit allowlist of trusted domains.',
          evidence: {
            file: normalizedPath,
            line: lineIdx + 1,
            snippet: lines[lineIdx].trim().slice(0, 120)
          },
          cwe: 'CWE-942',
          owasp: 'A05:2021 Security Misconfiguration'
        });
      }
    }

    if (baseName === 'package.json') {
      try {
        const pkg = JSON.parse(content) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        const deps: Array<{ name: string; version: string; isDev?: boolean }> = [];
        for (const [name, ver] of Object.entries(pkg.dependencies || {})) {
          deps.push({ name, version: String(ver), isDev: false });
        }
        for (const [name, ver] of Object.entries(pkg.devDependencies || {})) {
          deps.push({ name, version: String(ver), isDev: true });
        }
        manifests.push({
          file: normalizedPath,
          ecosystem: 'npm',
          dependencyCount: deps.length,
          dependencies: deps.slice(0, 100)
        });

        const hasDep = (n: string) => deps.some((d) => d.name === n);
        if (hasDep('next')) techMap.set('Next.js', { name: 'Next.js', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
        if (hasDep('react')) techMap.set('React', { name: 'React', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
        if (hasDep('vue')) techMap.set('Vue.js', { name: 'Vue.js', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
        if (hasDep('@angular/core')) techMap.set('Angular', { name: 'Angular', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
        if (hasDep('express')) techMap.set('Express', { name: 'Express', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });

        dependencyAdvisoriesFound += checkManifestAdvisories('npm', deps, normalizedPath, addFinding);
      } catch {
        // Malformed package.json
      }
    } else if (baseName === 'composer.json') {
      try {
        const comp = JSON.parse(content) as { require?: Record<string, string> };
        const deps = Object.entries(comp.require || {}).map(([name, version]) => ({
          name,
          version: String(version)
        }));
        manifests.push({
          file: normalizedPath,
          ecosystem: 'composer',
          dependencyCount: deps.length,
          dependencies: deps
        });
        if (deps.some((d) => d.name.includes('laravel/framework'))) {
          techMap.set('Laravel', { name: 'Laravel', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
        }
        if (deps.some((d) => d.name.includes('wordpress'))) {
          techMap.set('WordPress', { name: 'WordPress', category: 'cms', confidence: 'confirmed', evidence: normalizedPath });
        }
        dependencyAdvisoriesFound += checkManifestAdvisories('composer', deps, normalizedPath, addFinding);
      } catch {
        // Ignore
      }
    } else if (baseName === 'requirements.txt') {
      const deps: Array<{ name: string; version: string }> = [];
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;
        const m = line.match(/^([a-zA-Z0-9._-]+)\s*(?:==|>=|<=|~=|!=)?\s*([^\s;#]+)?/);
        if (m) {
          deps.push({ name: m[1].toLowerCase(), version: m[2] || 'unspecified' });
        }
      }
      manifests.push({
        file: normalizedPath,
        ecosystem: 'pip',
        dependencyCount: deps.length,
        dependencies: deps
      });
      if (deps.some((d) => d.name === 'django')) techMap.set('Django', { name: 'Django', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
      if (deps.some((d) => d.name === 'flask')) techMap.set('Flask', { name: 'Flask', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
      if (deps.some((d) => d.name === 'fastapi')) techMap.set('FastAPI', { name: 'FastAPI', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
      dependencyAdvisoriesFound += checkManifestAdvisories('pip', deps, normalizedPath, addFinding);
    } else if (baseName === 'go.mod') {
      const deps: Array<{ name: string; version: string }> = [];
      for (const line of content.split(/\r?\n/)) {
        const m = line.trim().match(/^([^\s]+)\s+(v[^\s]+)/);
        if (m && !m[1].startsWith('module') && !m[1].startsWith('go')) {
          deps.push({ name: m[1], version: m[2] });
        }
      }
      manifests.push({ file: normalizedPath, ecosystem: 'go', dependencyCount: deps.length, dependencies: deps });
      techMap.set('Go', { name: 'Go', category: 'language', confidence: 'confirmed', evidence: normalizedPath });
    } else if (baseName === 'pom.xml') {
      const artifactMatches = [...content.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)].map((m) => m[1]);
      manifests.push({
        file: normalizedPath,
        ecosystem: 'maven',
        dependencyCount: artifactMatches.length,
        dependencies: artifactMatches.slice(0, 50).map((name) => ({ name, version: 'maven' }))
      });
      if (artifactMatches.some((a) => a.includes('spring-boot'))) {
        techMap.set('Spring Boot', { name: 'Spring Boot', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
      }
    } else if (ext === '.csproj') {
      const pkgRefs = [...content.matchAll(/PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g)].map((m) => ({
        name: m[1],
        version: m[2]
      }));
      manifests.push({ file: normalizedPath, ecosystem: 'nuget', dependencyCount: pkgRefs.length, dependencies: pkgRefs });
      techMap.set('ASP.NET Core', { name: 'ASP.NET Core', category: 'framework', confidence: 'confirmed', evidence: normalizedPath });
    }

    if (baseName === 'wp-config.php' || lowerPath.includes('wp-content/')) {
      techMap.set('WordPress', { name: 'WordPress', category: 'cms', confidence: 'confirmed', evidence: normalizedPath });
    }
    if (baseName === 'dockerfile') {
      techMap.set('Docker', { name: 'Docker', category: 'server', confidence: 'confirmed', evidence: normalizedPath });
      if (/^\s*USER\s+root\s*$/im.test(content) || !/^\s*USER\s+/im.test(content)) {
        configIssuesFound++;
        addFinding({
          checkId: 'zip_dockerfile_root',
          title: 'Dockerfile Runs Without Non-Root USER Directive',
          severity: 'low',
          category: 'Code & Secrets',
          confidence: 'probable',
          accuracyTier: 'LIKELY',
          detectionMethod: 'Dockerfile Directive Inspection',
          affectedResource: normalizedPath,
          description: 'Container image may execute processes as root inside the container runtime.',
          impact: 'Increases blast radius if a runtime vulnerability leads to container escape or file tampering.',
          remediation: 'Create and switch to an unprivileged USER (e.g., USER node or USER 1001) in Dockerfile.',
          evidence: { file: normalizedPath, line: 1 },
          cwe: 'CWE-250',
          owasp: 'A05:2021 Security Misconfiguration'
        });
      }
    }

    // Secret & SAST Line-by-Line Scanning (skip lockfiles & comment-only lines for SAST)
    if (!lowerPath.endsWith('-lock.json') && !lowerPath.endsWith('.lock')) {
      const lines = content.split(/\r?\n/);
      let inBlockComment = false;
      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        if (!lineText || lineText.length > 1500) continue;
        const trimmedLine = lineText.trim();

        if (trimmedLine.startsWith('/*')) inBlockComment = true;
        const lineIsComment = inBlockComment || isCommentLine(lineText);
        if (inBlockComment && trimmedLine.includes('*/')) {
          inBlockComment = false;
        }

        // Secret regex checks (run even in comments unless placeholder)
        for (const sp of SECRET_PATTERNS) {
          sp.regex.lastIndex = 0;
          const match = sp.regex.exec(lineText);
          if (match) {
            const secretVal = match[1] || match[0];
            if (/^(?:your_|example|placeholder|changeme|xxxx|dummy|test_)/i.test(secretVal)) {
              continue;
            }
            const redacted = redactSecret(secretVal);
            secretsFound++;
            addFinding({
              checkId: `zip_secret_${sp.id}`,
              title: sp.title,
              severity: sp.severity,
              category: 'Code & Secrets',
              confidence: 'confirmed',
              accuracyTier: 'VERIFIED',
              detectionMethod: 'Deterministic Secret Signature Inspection (Redacted)',
              affectedResource: `${normalizedPath}:${i + 1}`,
              description: `A high-risk credential pattern was detected in "${normalizedPath}" at line ${i + 1}. Secret value has been redacted in output.`,
              impact: 'Committed credentials enable unauthorized access to cloud accounts, databases, or payment APIs.',
              remediation: 'Remove the hardcoded secret immediately, inject via environment/secret manager, and rotate the credential.',
              evidence: {
                file: normalizedPath,
                line: i + 1,
                snippet: lineText.replace(secretVal, redacted).trim().slice(0, 140)
              },
              cwe: sp.cwe,
              owasp: 'A07:2021 Identification and Authentication Failures'
            });
          }
        }

        // Skip comment lines for entropy heuristics & SAST pattern matching
        if (lineIsComment) continue;

        const tokenAssign = lineText.match(/(?:token|secret|apikey|api_key|auth_key)\s*[:=]\s*["']([A-Za-z0-9+/=_-]{24,})["']/i);
        if (tokenAssign && tokenAssign[1]) {
          const candidate = tokenAssign[1];
          if (shannonEntropy(candidate) >= 4.2 && !/example|placeholder|sample/i.test(candidate)) {
            const redacted = redactSecret(candidate);
            secretsFound++;
            addFinding({
              checkId: 'zip_high_entropy_literal',
              title: 'High-Entropy Secret Literal Detected',
              severity: 'medium',
              category: 'Code & Secrets',
              confidence: 'probable',
              accuracyTier: 'SUSPECTED',
              detectionMethod: 'Shannon Entropy Secret Assignment Heuristic',
              affectedResource: `${normalizedPath}:${i + 1}`,
              description: `High-entropy string assigned to a credential-like identifier in "${normalizedPath}" at line ${i + 1}.`,
              impact: 'May represent an exposed production token or signing key.',
              remediation: 'Move credential values to runtime environment variables or a secret vault.',
              evidence: {
                file: normalizedPath,
                line: i + 1,
                snippet: lineText.replace(candidate, redacted).trim().slice(0, 140)
              },
              cwe: 'CWE-798',
              owasp: 'A07:2021 Identification and Authentication Failures'
            });
          }
        }

        for (const rule of SAST_PATTERNS) {
          if (rule.extensions && !rule.extensions.includes(ext)) continue;
          if (rule.regex.test(lineText)) {
            sastFindingsCount++;
            addFinding({
              checkId: rule.id,
              title: rule.title,
              severity: rule.severity,
              category: rule.category,
              confidence: 'probable',
              accuracyTier: 'SUSPECTED',
              detectionMethod: 'Static Pattern SAST Heuristic',
              affectedResource: `${normalizedPath}:${i + 1}`,
              description: `${rule.description} Detected in ${normalizedPath}:${i + 1}.`,
              impact: rule.impact,
              remediation: rule.remediation,
              evidence: {
                file: normalizedPath,
                line: i + 1,
                snippet: lineText.trim().slice(0, 140)
              },
              cwe: rule.cwe,
              owasp: rule.owasp
            });
          }
        }
      }
    }
  }

  const languages = [...langCounts.entries()]
    .map(([name, fileCount]) => ({ name, fileCount }))
    .sort((a, b) => b.fileCount - a.fileCount);

  for (const lang of languages.slice(0, 4)) {
    if (!techMap.has(lang.name)) {
      techMap.set(lang.name, {
        name: lang.name,
        category: 'language',
        confidence: 'confirmed',
        evidence: `${lang.fileCount} source files`
      });
    }
  }

  const checks: Array<{
    id: string;
    name: string;
    status: 'passed' | 'failed' | 'warning' | 'skipped';
    detail?: string;
  }> = [
    {
      id: 'zip_archive_safety',
      name: 'Archive Traversal & Decompression Guard',
      status: 'passed',
      detail: `${fileEntries.length} archive entries validated (${analyzedFiles} text files analyzed, ${skippedFiles} skipped)`
    },
    {
      id: 'zip_committed_env',
      name: 'Committed Environment Files Check',
      status: analyzedFiles === 0 ? 'skipped' : envFilesFound > 0 ? 'failed' : 'passed',
      detail: envFilesFound > 0 ? `${envFilesFound} .env file(s) packaged in archive` : 'No committed .env files found'
    },
    {
      id: 'zip_secrets',
      name: 'Hardcoded Credentials & Keys Scan',
      status: analyzedFiles === 0 ? 'skipped' : secretsFound > 0 ? 'failed' : 'passed',
      detail: secretsFound > 0 ? `${secretsFound} secret pattern(s) matched (redacted)` : 'No hardcoded secrets matched'
    },
    {
      id: 'zip_sast',
      name: 'Static Source Pattern (SAST) Audit',
      status: analyzedFiles === 0 ? 'skipped' : sastFindingsCount > 0 ? 'warning' : 'passed',
      detail: sastFindingsCount > 0 ? `${sastFindingsCount} risky sink pattern(s) flagged` : 'No SAST sink patterns matched'
    },
    {
      id: 'zip_configs',
      name: 'Configuration & Container Hardening',
      status: analyzedFiles === 0 ? 'skipped' : configIssuesFound > 0 ? 'warning' : 'passed',
      detail: configIssuesFound > 0 ? `${configIssuesFound} configuration issue(s) found` : 'No configuration issues detected'
    },
    {
      id: 'zip_dependencies',
      name: 'Dependency Manifest CVE Audit',
      status: manifests.length === 0 ? 'skipped' : dependencyAdvisoriesFound > 0 ? 'failed' : 'passed',
      detail:
        manifests.length === 0
          ? 'No supported dependency manifests (package.json, requirements.txt, composer.json) found'
          : `Inspected ${manifests.length} manifest(s); ${dependencyAdvisoriesFound} known advisory match(es)`
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

  const scoring = calculateV2Scores(findings, coverage);

  const zipDetails: V2ZipDetails = {
    archiveName,
    compressedBytes: buffer.length,
    uncompressedBytes: actualUncompressedTotal,
    totalFiles: fileEntries.length,
    analyzedFiles,
    skippedFiles,
    languages,
    manifests,
    fileTreeSample
  };

  return {
    id: `v2scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    userId: options.userId || 'anonymous',
    version: 'v2',
    mode: 'zip',
    target: archiveName,
    score: scoring.score,
    grade: scoring.grade,
    durationMs: Date.now() - startTime,
    createdAt: new Date().toISOString(),
    authorizedAttestation: Boolean(options.authorizedAttestation),
    technologies: [...techMap.values()],
    findings: scoring.deduplicatedFindings,
    categoryScores: scoring.categoryScores,
    summary: scoring.summary,
    coverage,
    scoreBreakdown: scoring.scoreBreakdown,
    zipDetails
  };
}

function checkManifestAdvisories(
  ecosystem: V2ZipManifest['ecosystem'],
  deps: Array<{ name: string; version: string }>,
  file: string,
  addFinding: (f: Omit<V2Finding, 'id' | 'observedAt'> & { checkId: string }) => void
): number {
  let matched = 0;
  for (const dep of deps) {
    const rule = KNOWN_ADVISORIES.find(
      (a) => a.ecosystem === ecosystem && a.pkg.toLowerCase() === dep.name.toLowerCase()
    );
    if (!rule) continue;
    if (!parseVersionParts(dep.version)) continue;

    if (isSemverOlder(dep.version, rule.fixedVersion)) {
      matched++;
      const ranged = isRangeSpecifier(dep.version);
      addFinding({
        checkId: `zip_dep_${rule.cve.toLowerCase()}`,
        title: `${rule.title} (${dep.name}@${dep.version})`,
        severity: rule.severity,
        category: 'Dependencies & Stack',
        confidence: ranged ? 'probable' : 'confirmed',
        accuracyTier: 'LIKELY',
        detectionMethod: ranged
          ? 'Semver Manifest Range Advisory Match (Verify Lockfile)'
          : 'Manifest Version Advisory Match',
        affectedResource: `${file} (${dep.name}@${dep.version})`,
        reference: rule.reference,
        description: `Manifest "${file}" declares ${dep.name} (${dep.version}), which is below fixed version ${rule.fixedVersion} for ${rule.cve}.${
          ranged ? ' Because a semver range specifier is used, inspect package-lock.json/yarn.lock to verify the resolved version.' : ''
        }`,
        impact: 'Known vulnerable dependency versions can be exploited if reachable in application workflows.',
        remediation: rule.remediation,
        evidence: {
          file,
          package: `${dep.name}@${dep.version}`,
          detail: `${rule.cve} (fixed in >= ${rule.fixedVersion})`
        },
        cwe: 'CWE-1104',
        owasp: 'A06:2021 Vulnerable and Outdated Components'
      });
    }
  }
  return matched;
}
