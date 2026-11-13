export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingAccuracyTier =
  | 'VERIFIED'
  | 'LIKELY'
  | 'SUSPECTED'
  | 'INFORMATIONAL'
  | 'NOT_VERIFIED';

export type FindingCategory =
  | 'ssl_tls'
  | 'security_headers'
  | 'core_configuration'
  | 'sensitive_files'
  | 'plugins_themes'
  | 'user_enumeration';

export interface SecurityFinding {
  id: string;
  checkId?: string;
  category: FindingCategory;
  title: string;
  severity: FindingSeverity;
  accuracyTier?: FindingAccuracyTier;
  detectionMethod?: string;
  affectedResource?: string;
  observedAt?: string;
  reference?: string;
  cvssScore?: number;
  scoreDeduction: number;
  description: string;
  impact: string;
  evidence: {
    url?: string;
    statusCode?: number;
    headerName?: string;
    headerValue?: string;
    details?: string;
    signature?: string;
  };
  remediation: {
    summary: string;
    steps: string[];
    codeSnippet?: {
      language: 'apache' | 'nginx' | 'php' | 'json';
      filename: string;
      code: string;
    };
  };
  cveReferences?: {
    cveId: string;
    title: string;
    published?: string;
    fixedIn?: string;
    url?: string;
  }[];
}

export interface ScanCheckRecord {
  id: string;
  name: string;
  status: 'passed' | 'failed' | 'warning' | 'skipped';
  detail?: string;
}

export interface ScanCoverage {
  totalChecks: number;
  executedChecks: number;
  passedChecks: number;
  failedChecks: number;
  skippedChecks: number;
  checks: ScanCheckRecord[];
}

export interface ScoreBreakdown {
  startingScore: number;
  totalDeductions: number;
  excludedInformationalOrUnverified: number;
  deduplicatedCount: number;
  finalScore: number;
  formulaNote: string;
  coverageNote?: string;
}

export interface CategoryScore {
  score: number; // 0-100
  totalChecks: number;
  passedChecks: number;
  warnings: number;
  failures: number;
}

export interface DetectedPlugin {
  slug: string;
  name: string;
  version?: string;
  detectedVia: string;
  vulnerabilities: {
    cveId: string;
    title: string;
    severity: FindingSeverity;
    fixedIn?: string;
  }[];
}

export interface DetectedTheme {
  slug: string;
  name?: string;
  version?: string;
  detectedVia: string;
}

export interface WpScanIntelligenceSource {
  usedLiveApi: boolean;
  apiKeyConfigured: boolean;
  statusMessage: string;
  vulnCount: number;
}

export interface ScanResult {
  id: string;
  userId: string;
  targetUrl: string;
  hostname: string;
  ipAddress?: string;
  scanTimestamp: string;
  createdAt?: string;
  durationMs: number;
  
  // WordPress Discovery
  isWordPress: boolean;
  wpVersion?: string;
  wpVersionLatest?: string;
  isVersionOutdated?: boolean;
  
  // Overall Health
  score: number; // 0-100
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  
  // Categorical Breakdowns
  categories: {
    ssl_tls: CategoryScore;
    security_headers: CategoryScore;
    core_configuration: CategoryScore;
    sensitive_files: CategoryScore;
    plugins_themes: CategoryScore;
  };
  
  // Findings
  findings: SecurityFinding[];
  
  // Discovered Components
  plugins: DetectedPlugin[];
  theme?: DetectedTheme;
  
  // Server Info
  serverInfo?: {
    webServer?: string;
    phpVersion?: string;
    poweredBy?: string;
    hstsEnabled: boolean;
    httpsEnforced: boolean;
    ipCountry?: string;
  };

  wpscanIntelligence: WpScanIntelligenceSource;
  coverage?: ScanCoverage;
  scoreBreakdown?: ScoreBreakdown;
  
  // AI Assessment (Optional / cached)
  aiSummary?: string;
}

export interface MonitoredSite {
  id: string;
  userId: string;
  url: string;
  hostname: string;
  verified: boolean;
  verificationToken: string;
  lastScannedAt?: string;
  lastScore?: number;
  lastGrade?: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  scanCount: number;
  createdAt: string;
}

export interface UserProfile {
  userId: string;
  email: string;
  displayName?: string;
  wpscanApiKey?: string;
  onboardingCompleted?: boolean;
  authProvider?: string;
  createdAt: string;
}
