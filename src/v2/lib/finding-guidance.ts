import { V2AccuracyTier, V2Confidence, V2Finding, V2FindingStatus } from '../types/v2.ts';

export function getAccuracyTier(finding: V2Finding): V2AccuracyTier {
  if (finding.accuracyTier) return finding.accuracyTier;
  if (finding.severity === 'info') return 'INFORMATIONAL';
  if (finding.confidence === 'confirmed') return 'VERIFIED';
  if (finding.confidence === 'probable') return 'SUSPECTED';
  return 'NOT_VERIFIED';
}

export function getAccuracyDisplay(tierOrFinding: V2AccuracyTier | V2Finding): {
  tier: V2AccuracyTier;
  label: string;
  explanation: string;
} {
  const tier = typeof tierOrFinding === 'string' ? tierOrFinding : getAccuracyTier(tierOrFinding);
  switch (tier) {
    case 'VERIFIED':
      return {
        tier,
        label: 'Verified',
        explanation: 'Direct evidence from an actual network response, archive source file, or host check confirms this condition.'
      };
    case 'LIKELY':
      return {
        tier,
        label: 'Likely',
        explanation: 'Strong technical indicators (such as a semver manifest range or asset version parameter) point to this issue, though exact runtime reachability should be confirmed.'
      };
    case 'SUSPECTED':
      return {
        tier,
        label: 'Suspected',
        explanation: 'A static heuristic or pattern match flagged a risky construct; manual code or runtime verification is needed.'
      };
    case 'INFORMATIONAL':
      return {
        tier,
        label: 'Informational',
        explanation: 'Contextual observation for security awareness; does not deduct from the security score.'
      };
    case 'NOT_VERIFIED':
    default:
      return {
        tier: 'NOT_VERIFIED',
        label: 'Not Verified',
        explanation: 'Insufficient evidence was available to verify exploitability or exact version status; excluded from score penalties.'
      };
  }
}

export function getConfidenceDisplay(confidence: V2Confidence): {
  label: string;
  explanation: string;
} {
  if (confidence === 'confirmed') {
    return {
      label: 'Verified',
      explanation: 'Directly observed in the target response, archive file, or host configuration.'
    };
  }
  if (confidence === 'probable') {
    return {
      label: 'Suspected',
      explanation: 'A strong risk pattern was matched, but context or runtime reachability should be verified.'
    };
  }
  return {
    label: 'Not Verified',
    explanation: 'Insufficient direct confirmation; verify manually before remediating.'
  };
}

export function getStatusDisplay(status?: V2FindingStatus): {
  label: string;
  value: V2FindingStatus;
} {
  if (status === 'resolved') return { label: 'Resolved', value: 'resolved' };
  if (status === 'accepted_risk') return { label: 'Accepted Risk', value: 'accepted_risk' };
  return { label: 'Unresolved', value: 'unresolved' };
}

export function getPlainExplanation(finding: V2Finding): string {
  if (finding.plainSummary) return finding.plainSummary;

  const title = finding.title.toLowerCase();
  if (title.includes('strict-transport-security') || title.includes('hsts')) {
    return 'Your site does not tell browsers to always require HTTPS automatically. Without HSTS, the first visit over plain HTTP could be intercepted before redirecting.';
  }
  if (title.includes('content-security-policy') || title.includes('csp')) {
    return 'Your server does not list which scripts and resources browsers are allowed to load. A Content Security Policy helps block injected malicious scripts (XSS).';
  }
  if (title.includes('x-frame-options') || title.includes('clickjacking')) {
    return 'Other websites may be able to embed your pages inside an invisible frame, which could trick visitors into clicking buttons unintentionally.';
  }
  if (title.includes('x-content-type-options')) {
    return 'Browsers might try to guess the file type of downloaded content instead of trusting the server label, which can occasionally execute unexpected scripts.';
  }
  if (title.includes('referrer-policy')) {
    return 'When users click links leaving your site, browsers may send the full page address (including query parameters) to the external website.';
  }
  if (title.includes('x-powered-by')) {
    return 'Your server advertises the software framework or language version in response headers, making it easier for automated attackers to look up known flaws.';
  }
  if (title.includes('cookie')) {
    return 'A browser cookie is missing protective flags (such as HttpOnly, Secure, or SameSite) that help stop scripts or unencrypted networks from reading session tokens.';
  }
  if (title.includes('unencrypted http')) {
    return 'The target website loaded over plain HTTP instead of encrypted HTTPS, meaning anyone on the same network path can view or modify traffic.';
  }
  if (title.includes('tls certificate')) {
    return 'The HTTPS security certificate presented by the server could not be fully trusted or is expired, which triggers browser warnings for visitors.';
  }
  if (title.includes('/.env') || title.includes('environment file')) {
    return 'An environment configuration file (.env) appears readable or bundled. These files frequently store database passwords and secret API keys.';
  }
  if (title.includes('.git/head')) {
    return 'Your site exposes internal Git version-control metadata publicly, which can allow strangers to reconstruct source code history.';
  }
  if (title.includes('aws access key') || title.includes('stripe') || title.includes('github') || title.includes('secret') || title.includes('private')) {
    return 'A credential or secret key pattern was found written directly inside a project file. Anyone who can read the source code or repository could reuse that key.';
  }
  if (title.includes('eval()')) {
    return 'The code executes text strings dynamically as program code. If user input ever reaches this call, attackers can run arbitrary commands.';
  }
  if (title.includes('sql')) {
    return 'A database query appears to join variables directly into SQL text instead of using safe parameterized placeholders.';
  }
  if (title.includes('xss') || title.includes('html injection')) {
    return 'Code writes raw HTML directly into the page without automatic escaping, which can let injected scripts run in a visitor’s browser.';
  }
  if (title.includes('outdated') || title.includes('legacy')) {
    return 'A software library declared in your project manifest matches an older version range with publicly documented security vulnerabilities.';
  }
  if (title.includes('permissions')) {
    return 'A sensitive configuration file on the server allows other local system users to read or modify it.';
  }
  return finding.description;
}

export function getSafeVerifySteps(finding: V2Finding): string {
  if (finding.verifySteps) return finding.verifySteps;

  if (finding.evidence.header && finding.evidence.url) {
    return `Run a read-only header check: curl -sI "${finding.evidence.url}" and inspect the "${finding.evidence.header.split(':')[0]}" header.`;
  }
  if (finding.evidence.url && finding.title.toLowerCase().includes('cookie')) {
    return `Open "${finding.evidence.url}" in browser DevTools → Application/Storage → Cookies and check HttpOnly, Secure, and SameSite columns.`;
  }
  if (finding.evidence.url) {
    return `Safely verify in a browser or read-only curl request: curl -iL "${finding.evidence.url}" (check HTTP status and response content).`;
  }
  if (finding.evidence.file && finding.evidence.line) {
    return `Open "${finding.evidence.file}" at line ${finding.evidence.line} in your code editor and review how inputs or secrets are handled.`;
  }
  if (finding.evidence.package && finding.evidence.file) {
    return `Inspect "${finding.evidence.file}" for "${finding.evidence.package}" and check your installed lockfile version before upgrading.`;
  }
  if (finding.evidence.file) {
    return `Inspect "${finding.evidence.file}" locally (for servers: ls -la "${finding.evidence.file}") to confirm file contents and permissions.`;
  }
  return 'Review the observed evidence above and re-run a targeted scan after applying the recommended fix.';
}
