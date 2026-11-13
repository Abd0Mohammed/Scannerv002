export type V2Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type V2Confidence = 'confirmed' | 'probable' | 'inconclusive';
export type V2AccuracyTier =
  | 'VERIFIED'
  | 'LIKELY'
  | 'SUSPECTED'
  | 'INFORMATIONAL'
  | 'NOT_VERIFIED';
export type V2FindingStatus = 'unresolved' | 'resolved' | 'accepted_risk';
export type V2ScanMode = 'url' | 'zip' | 'agent';

export interface V2FindingEvidence {
  url?: string;
  file?: string;
  line?: number;
  snippet?: string;
  header?: string;
  package?: string;
  detail?: string;
}

export interface V2Finding {
  id: string;
  checkId?: string;
  title: string;
  severity: V2Severity;
  category: string;
  confidence: V2Confidence;
  accuracyTier?: V2AccuracyTier;
  detectionMethod?: string;
  affectedResource?: string;
  observedAt?: string;
  reference?: string;
  status?: V2FindingStatus;
  plainSummary?: string;
  description: string;
  impact: string;
  verifySteps?: string;
  remediation: string;
  evidence: V2FindingEvidence;
  cwe?: string;
  owasp?: string;
}

export interface V2CheckRecord {
  id: string;
  name: string;
  status: 'passed' | 'failed' | 'warning' | 'skipped';
  detail?: string;
}

export interface V2ScanCoverage {
  totalChecks: number;
  executedChecks: number;
  passedChecks: number;
  failedChecks: number;
  skippedChecks: number;
  checks: V2CheckRecord[];
}

export interface V2ScoreBreakdown {
  startingScore: number;
  totalDeductions: number;
  excludedInformationalOrUnverified: number;
  deduplicatedCount: number;
  finalScore: number;
  formulaNote: string;
  coverageNote?: string;
}

export interface V2Technology {
  name: string;
  category: 'cms' | 'framework' | 'language' | 'server' | 'library' | 'cdn';
  version?: string;
  confidence: V2Confidence;
  evidence: string;
}

export interface V2CookieAudit {
  name: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
  path?: string;
  sourceUrl: string;
  issues: string[];
}

export interface V2TlsCertificate {
  valid: boolean;
  protocol?: string;
  cipher?: string;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  selfSigned?: boolean;
  error?: string;
}

export interface V2CrawledPage {
  url: string;
  statusCode: number;
  title?: string;
  contentType?: string;
  depth: number;
  responseTimeMs: number;
}

export interface V2FormSummary {
  pageUrl: string;
  action: string;
  method: string;
  hasPasswordInput: boolean;
  overInsecureHttp: boolean;
}

export interface V2DiscoveredAssets {
  pages: V2CrawledPage[];
  scripts: string[];
  stylesheets: string[];
  images: string[];
  documents: string[];
  forms: V2FormSummary[];
  robotsTxt: {
    found: boolean;
    disallowedPaths: string[];
    sitemaps: string[];
  };
  sitemapXml: {
    found: boolean;
    urlCount: number;
    sampleUrls: string[];
  };
  exposedEndpoints: Array<{
    path: string;
    statusCode: number;
    contentType?: string;
    confirmedExposure: boolean;
  }>;
}

export interface V2ZipManifest {
  file: string;
  ecosystem: 'npm' | 'composer' | 'pip' | 'maven' | 'go' | 'nuget';
  dependencyCount: number;
  dependencies: Array<{ name: string; version: string; isDev?: boolean }>;
}

export interface V2ZipDetails {
  archiveName: string;
  compressedBytes: number;
  uncompressedBytes: number;
  totalFiles: number;
  analyzedFiles: number;
  skippedFiles: number;
  languages: Array<{ name: string; fileCount: number }>;
  manifests: V2ZipManifest[];
  fileTreeSample: string[];
}

export interface V2UrlDetails {
  finalUrl: string;
  ipAddress: string;
  httpStatus: number;
  httpsEnforced: boolean;
  tls: V2TlsCertificate | null;
  headers: Record<string, string>;
  cookies: V2CookieAudit[];
  assets: V2DiscoveredAssets;
  crawlConfig: {
    maxPages: number;
    maxDepth: number;
    scope: 'same-origin' | 'include-subdomains';
  };
}

export interface V2AgentReportDetails {
  agentId: string;
  agentName: string;
  environment: string;
  hostname: string;
  osPlatform: string;
  runtimeVersion: string;
  checkedPaths: number;
  inspectedChecks?: V2CheckRecord[];
}

export interface V2ScanResult {
  id: string;
  userId: string;
  version: 'v2';
  mode: V2ScanMode;
  target: string;
  hostname?: string;
  score: number;
  grade: string;
  durationMs: number;
  createdAt: string;
  authorizedAttestation: boolean;
  technologies: V2Technology[];
  findings: V2Finding[];
  categoryScores: Record<string, number>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    confirmedCount: number;
    verifiedCount?: number;
    likelyCount?: number;
    suspectedCount?: number;
    informationalCount?: number;
    notVerifiedCount?: number;
  };
  coverage?: V2ScanCoverage;
  scoreBreakdown?: V2ScoreBreakdown;
  urlDetails?: V2UrlDetails;
  zipDetails?: V2ZipDetails;
  agentDetails?: V2AgentReportDetails;
}

export interface V2ScanJob {
  jobId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  stage: string;
  pagesCrawled: number;
  totalDiscovered: number;
  createdAt: string;
  result?: V2ScanResult;
  error?: string;
}

export interface V2AgentRecord {
  id: string;
  userId: string;
  name: string;
  environment: string;
  hostname?: string;
  status: 'registered' | 'active' | 'stale' | 'revoked';
  tokenPrefix: string;
  createdAt: string;
  lastHeartbeatAt?: string;
  osInfo?: string;
  agentVersion?: string;
  lastReportScore?: number;
  lastReportId?: string;
}

export interface V2AuditLog {
  id: string;
  userId: string;
  action: string;
  target: string;
  mode: V2ScanMode | 'system' | 'agent';
  status: 'allowed' | 'blocked' | 'completed' | 'error';
  detail: string;
  createdAt: string;
}
