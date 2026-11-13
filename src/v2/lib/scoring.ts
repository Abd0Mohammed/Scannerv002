import {
  V2AccuracyTier,
  V2Finding,
  V2ScanCoverage,
  V2ScoreBreakdown,
  V2Severity
} from '../types/v2.ts';

const SEVERITY_PENALTIES: Record<V2Severity, number> = {
  critical: 22,
  high: 14,
  medium: 7,
  low: 3,
  info: 0
};

const ACCURACY_MULTIPLIER: Record<V2AccuracyTier, number> = {
  VERIFIED: 1.0,
  LIKELY: 0.85,
  SUSPECTED: 0.6,
  INFORMATIONAL: 0,
  NOT_VERIFIED: 0
};

export function resolveV2AccuracyTier(finding: V2Finding): V2AccuracyTier {
  if (finding.accuracyTier) return finding.accuracyTier;
  if (finding.severity === 'info') return 'INFORMATIONAL';
  if (finding.confidence === 'confirmed') return 'VERIFIED';
  if (finding.confidence === 'probable') return 'SUSPECTED';
  return 'NOT_VERIFIED';
}

export function calculateV2Grade(score: number, coverage?: V2ScanCoverage): string {
  if (coverage && coverage.executedChecks === 0) return 'N/A';
  if (score >= 95 && (!coverage || coverage.skippedChecks === 0)) return 'A+';
  if (score >= 88) return 'A';
  if (score >= 78) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

export function deduplicateV2Findings(findings: V2Finding[]): {
  unique: V2Finding[];
  deduplicatedCount: number;
} {
  const seen = new Set<string>();
  const unique: V2Finding[] = [];
  let deduplicatedCount = 0;

  for (const f of findings) {
    const resource =
      f.affectedResource ||
      f.evidence?.url ||
      (f.evidence?.file ? `${f.evidence.file}:${f.evidence.line || ''}` : '') ||
      f.evidence?.header ||
      f.evidence?.package ||
      '';
    const key = `${(f.checkId || f.title).toLowerCase()}|${resource.toLowerCase()}`;
    if (seen.has(key)) {
      deduplicatedCount++;
      continue;
    }
    seen.add(key);
    unique.push(f);
  }

  return { unique, deduplicatedCount };
}

export function calculateV2Scores(
  findings: V2Finding[],
  coverage?: V2ScanCoverage
): {
  score: number;
  grade: string;
  categoryScores: Record<string, number>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    confirmedCount: number;
    verifiedCount: number;
    likelyCount: number;
    suspectedCount: number;
    informationalCount: number;
    notVerifiedCount: number;
  };
  scoreBreakdown: V2ScoreBreakdown;
  deduplicatedFindings: V2Finding[];
} {
  let totalDeduction = 0;
  let excludedInformationalOrUnverified = 0;
  const categoryDeductions: Record<string, number> = {
    'Transport & TLS': 0,
    'Headers & Cookies': 0,
    'Attack Surface & Exposure': 0,
    'Dependencies & Stack': 0,
    'Code & Secrets': 0
  };

  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    confirmedCount: 0,
    verifiedCount: 0,
    likelyCount: 0,
    suspectedCount: 0,
    informationalCount: 0,
    notVerifiedCount: 0
  };

  const { unique, deduplicatedCount } = deduplicateV2Findings(findings);
  const sorted = [...unique].sort((a, b) => a.id.localeCompare(b.id));

  for (const finding of sorted) {
    summary[finding.severity]++;
    const tier = resolveV2AccuracyTier(finding);

    if (tier === 'VERIFIED') {
      summary.verifiedCount++;
      summary.confirmedCount++;
    } else if (tier === 'LIKELY') {
      summary.likelyCount++;
    } else if (tier === 'SUSPECTED') {
      summary.suspectedCount++;
    } else if (tier === 'INFORMATIONAL') {
      summary.informationalCount++;
    } else {
      summary.notVerifiedCount++;
    }

    if (tier === 'INFORMATIONAL' || tier === 'NOT_VERIFIED' || finding.severity === 'info') {
      excludedInformationalOrUnverified++;
      continue;
    }

    const basePenalty = SEVERITY_PENALTIES[finding.severity] || 0;
    const weightedPenalty = Math.round(basePenalty * (ACCURACY_MULTIPLIER[tier] ?? 1));
    totalDeduction += weightedPenalty;

    const cat = mapCategoryBucket(finding.category);
    categoryDeductions[cat] = (categoryDeductions[cat] || 0) + weightedPenalty;
  }

  let score = Math.max(0, Math.min(100, 100 - totalDeduction));
  let coverageNote: string | undefined = undefined;

  if (coverage) {
    if (coverage.executedChecks === 0) {
      score = 0;
      coverageNote = `0 of ${coverage.totalChecks} checks could be executed. No passing score can be assigned without executed checks.`;
    } else if (coverage.skippedChecks > 0) {
      if (score > 94) score = 94;
      coverageNote = `${coverage.skippedChecks} of ${coverage.totalChecks} checks were skipped or unreachable. Perfect 100/A+ requires 100% check completion.`;
    }
  }

  const categoryScores: Record<string, number> = {};
  for (const [cat, ded] of Object.entries(categoryDeductions)) {
    categoryScores[cat] =
      coverage && coverage.executedChecks === 0
        ? 0
        : Math.max(0, Math.min(100, 100 - Math.min(100, ded)));
  }

  const grade = calculateV2Grade(score, coverage);

  return {
    score,
    grade,
    categoryScores,
    summary,
    deduplicatedFindings: sorted,
    scoreBreakdown: {
      startingScore: 100,
      totalDeductions: totalDeduction,
      excludedInformationalOrUnverified,
      deduplicatedCount,
      finalScore: score,
      formulaNote:
        'Start at 100, subtract deduplicated severity penalties weighted by accuracy (VERIFIED 1.0x, LIKELY 0.85x, SUSPECTED 0.6x; INFORMATIONAL/NOT_VERIFIED = 0).',
      coverageNote
    }
  };
}

function mapCategoryBucket(category: string): string {
  const lower = category.toLowerCase();
  if (lower.includes('tls') || lower.includes('ssl') || lower.includes('transport') || lower.includes('https')) {
    return 'Transport & TLS';
  }
  if (lower.includes('header') || lower.includes('cookie') || lower.includes('cors')) {
    return 'Headers & Cookies';
  }
  if (lower.includes('secret') || lower.includes('code') || lower.includes('sast') || lower.includes('config')) {
    return 'Code & Secrets';
  }
  if (lower.includes('depend') || lower.includes('cve') || lower.includes('package') || lower.includes('tech')) {
    return 'Dependencies & Stack';
  }
  return 'Attack Surface & Exposure';
}
