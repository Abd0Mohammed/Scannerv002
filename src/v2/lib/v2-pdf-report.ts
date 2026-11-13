import { jsPDF } from 'jspdf';
import { V2ScanResult } from '../types/v2.ts';
import { getAccuracyTier } from './finding-guidance.ts';

export function exportV2PdfReport(scan: V2ScanResult) {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 18;

  const ensureSpace = (needed: number) => {
    if (y + needed > 276) {
      doc.addPage();
      y = 18;
    }
  };

  // Header Banner
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 38, 'F');

  doc.setTextColor(56, 189, 248);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text('SITE SENTINEL V2', 14, 16);

  doc.setTextColor(226, 232, 240);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const modeLabel =
    scan.mode === 'url'
      ? 'Universal Web Crawler & Surface Audit'
      : scan.mode === 'zip'
        ? 'Static Archive & Dependency Security Audit'
        : 'Authorized Host Posture Audit';
  doc.text(modeLabel, 14, 24);

  doc.setTextColor(148, 163, 184);
  doc.setFontSize(8.5);
  doc.text(`Report ID: ${scan.id}  |  Generated: ${new Date(scan.createdAt).toLocaleString()}`, 14, 31);

  y = 48;

  // Target & Score Summary Card
  doc.setDrawColor(203, 213, 225);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(14, y, pageWidth - 28, 30, 3, 3, 'FD');

  doc.setTextColor(15, 23, 42);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.text(`Target: ${scan.target.slice(0, 68)}`, 18, y + 9);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(
    `Score: ${scan.score}/100 (Grade ${scan.grade})   |   Critical: ${scan.summary.critical}   High: ${scan.summary.high}   Medium: ${scan.summary.medium}   Low: ${scan.summary.low}`,
    18,
    y + 17
  );
  doc.text(
    `Technologies: ${scan.technologies.map((t) => (t.version ? `${t.name} ${t.version}` : t.name)).join(', ').slice(0, 90) || 'None fingerprinted'}`,
    18,
    y + 24
  );

  y += 38;

  // Category Breakdown
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('Domain Category Scores', 14, y);
  y += 6;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  for (const [cat, val] of Object.entries(scan.categoryScores)) {
    ensureSpace(8);
    doc.setTextColor(51, 65, 85);
    doc.text(`${cat}:`, 16, y);
    doc.setFont('helvetica', 'bold');
    doc.text(`${val}/100`, 80, y);
    doc.setFont('helvetica', 'normal');
    y += 6;
  }

  y += 4;

  // Coverage & Score Breakdown Summary
  if (scan.coverage || scan.scoreBreakdown) {
    ensureSpace(22);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Scan Coverage & Score Formula', 14, y);
    y += 6;

    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    if (scan.coverage) {
      doc.text(
        `Checks Executed: ${scan.coverage.executedChecks}/${scan.coverage.totalChecks}  |  Passed: ${scan.coverage.passedChecks}  |  Flagged: ${scan.coverage.failedChecks}  |  Skipped: ${scan.coverage.skippedChecks}`,
        16,
        y
      );
      y += 5;
      if (scan.coverage.skippedChecks > 0) {
        doc.setTextColor(180, 83, 9);
        doc.text(
          scan.coverage.executedChecks === 0
            ? 'No checks executed; overall grade is marked N/A.'
            : 'Partial coverage: maximum grade capped at A (94/100) while skipped checks exist.',
          16,
          y
        );
        y += 5;
        doc.setTextColor(51, 65, 85);
      }
    }
    if (scan.scoreBreakdown) {
      const fLines = doc.splitTextToSize(`Formula: ${scan.scoreBreakdown.formulaNote}`, pageWidth - 32);
      doc.text(fLines, 16, y);
      y += fLines.length * 4.2;
    }
    y += 4;
  }

  // Mode-specific summary
  if (scan.urlDetails) {
    ensureSpace(24);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Attack Surface & Asset Inventory', 14, y);
    y += 6;

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(
      `Pages Crawled: ${scan.urlDetails.assets.pages.length}  |  Scripts: ${scan.urlDetails.assets.scripts.length}  |  Stylesheets: ${scan.urlDetails.assets.stylesheets.length}  |  Documents: ${scan.urlDetails.assets.documents.length}`,
      16,
      y
    );
    y += 5;
    doc.text(
      `HTTPS Enforced: ${scan.urlDetails.httpsEnforced ? 'Yes' : 'No'}  |  TLS Protocol: ${scan.urlDetails.tls?.protocol || 'N/A'}  |  Cookies Audited: ${scan.urlDetails.cookies.length}`,
      16,
      y
    );
    y += 8;
  } else if (scan.zipDetails) {
    ensureSpace(24);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Archive & Dependency Summary', 14, y);
    y += 6;

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(
      `Total Files: ${scan.zipDetails.totalFiles}  |  Analyzed: ${scan.zipDetails.analyzedFiles}  |  Manifests: ${scan.zipDetails.manifests.length}`,
      16,
      y
    );
    y += 5;
    doc.text(
      `Languages: ${scan.zipDetails.languages.map((l) => `${l.name} (${l.fileCount})`).join(', ') || 'N/A'}`,
      16,
      y
    );
    y += 8;
  }

  // Findings Section
  ensureSpace(16);
  doc.setFontSize(12);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(`Detailed Security Findings (${scan.findings.length})`, 14, y);
  y += 7;

  if (scan.findings.length === 0) {
    doc.setFontSize(9.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(22, 163, 74);
    doc.text('No security issues were identified by the automated checks.', 16, y);
  } else {
    for (const f of scan.findings) {
      ensureSpace(32);

      doc.setFontSize(9.5);
      doc.setFont('helvetica', 'bold');
      if (f.severity === 'critical' || f.severity === 'high') {
        doc.setTextColor(220, 38, 38);
      } else if (f.severity === 'medium') {
        doc.setTextColor(217, 119, 6);
      } else {
        doc.setTextColor(37, 99, 235);
      }
      const tier = getAccuracyTier(f);
      const statusLabel = f.status === 'resolved' ? 'Resolved' : f.status === 'accepted_risk' ? 'Accepted Risk' : 'Unresolved';
      const titleLines = doc.splitTextToSize(
        `[${f.severity.toUpperCase()} | ${tier} | ${statusLabel}] ${f.title}`,
        pageWidth - 28
      );
      doc.text(titleLines, 14, y);
      y += titleLines.length * 4.5 + 1;

      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);

      if (f.checkId || f.detectionMethod) {
        const methodLines = doc.splitTextToSize(
          `${f.checkId ? `Check ID: ${f.checkId}` : ''}${f.checkId && f.detectionMethod ? '  |  ' : ''}${f.detectionMethod ? `Method: ${f.detectionMethod}` : ''}`,
          pageWidth - 32
        );
        doc.text(methodLines, 16, y);
        y += methodLines.length * 4.2;
      }

      const evParts: string[] = [];
      if (f.evidence.url) evParts.push(`URL: ${f.evidence.url}`);
      if (f.evidence.file) evParts.push(`File: ${f.evidence.file}${f.evidence.line ? `:${f.evidence.line}` : ''}`);
      if (f.evidence.package) evParts.push(`Package: ${f.evidence.package}`);
      if (f.evidence.header) evParts.push(`Header: ${f.evidence.header}`);
      if (evParts.length > 0) {
        const evLines = doc.splitTextToSize(`Affected Resource: ${evParts.join(' | ')}`, pageWidth - 32);
        doc.text(evLines, 16, y);
        y += evLines.length * 4.2;
      }

      const descLines = doc.splitTextToSize(`What Happened: ${f.plainSummary || f.description}`, pageWidth - 32);
      ensureSpace(descLines.length * 4.2 + 16);
      doc.setTextColor(30, 41, 59);
      doc.text(descLines, 16, y);
      y += descLines.length * 4.2;

      const impactLines = doc.splitTextToSize(`Why It Matters: ${f.impact}`, pageWidth - 32);
      doc.setTextColor(71, 85, 105);
      doc.text(impactLines, 16, y);
      y += impactLines.length * 4.2;

      const remLines = doc.splitTextToSize(`Recommended Fix: ${f.remediation}`, pageWidth - 32);
      doc.setTextColor(21, 128, 61);
      doc.text(remLines, 16, y);
      y += remLines.length * 4.2 + 4;
    }
  }

  const safeSlug = (scan.hostname || scan.target).replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 40);
  doc.save(`site-sentinel-v2-${safeSlug}.pdf`);
}

export function exportV2JsonReport(scan: V2ScanResult) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const safeSlug = (scan.hostname || scan.target).replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 40);
  a.href = url;
  a.download = `site-sentinel-v2-${safeSlug}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
