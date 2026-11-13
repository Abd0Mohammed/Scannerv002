import { jsPDF } from 'jspdf';
import { ScanResult } from '../types/scanner.ts';

export function generateSecurityPdfReport(scan: ScanResult): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  // Helper function to check page break
  const checkPageBreak = (neededHeight: number) => {
    if (y + neededHeight > pageHeight - margin) {
      doc.addPage();
      y = margin;
      drawHeaderSmall();
    }
  };

  const drawHeaderSmall = () => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('WP SENTINEL — CONFIDENTIAL SECURITY AUDIT REPORT', margin, y);
    doc.text(`TARGET: ${scan.hostname}`, pageWidth - margin, y, { align: 'right' });
    y += 12;
    doc.setDrawColor(51, 65, 85);
    doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y);
    y += 15;
  };

  // --- Cover / Header Banner ---
  // Dark cyber background bar
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(margin, y, contentWidth, 75, 'F');

  doc.setFillColor(6, 182, 212); // cyan-500 accent strip
  doc.rect(margin, y, 4, 75, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(248, 250, 252);
  doc.text('WP SENTINEL', margin + 18, y + 28);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text('WORDPRESS PASSIVE SECURITY AUDIT & VULNERABILITY INTELLIGENCE', margin + 18, y + 44);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  doc.text(`Generated: ${new Date(scan.scanTimestamp).toUTCString()}`, margin + 18, y + 60);
  doc.text(`Scan ID: ${scan.id}`, pageWidth - margin - 15, y + 60, { align: 'right' });

  y += 90;

  // --- Executive Summary Box ---
  doc.setFillColor(30, 41, 59);
  doc.rect(margin, y, contentWidth, 90, 'F');

  // Score Badge
  const scoreColor =
    scan.score >= 90
      ? [16, 185, 129] // Emerald
      : scan.score >= 75
      ? [59, 130, 246] // Blue
      : scan.score >= 60
      ? [245, 158, 11] // Amber
      : [239, 68, 68]; // Red

  doc.setFillColor(scoreColor[0], scoreColor[1], scoreColor[2]);
  doc.roundedRect(margin + 15, y + 15, 70, 60, 4, 4, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(255, 255, 255);
  doc.text(String(scan.score), margin + 50, y + 42, { align: 'center' });

  doc.setFontSize(11);
  doc.text(`Grade ${scan.grade}`, margin + 50, y + 62, { align: 'center' });

  // Target Specs
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(241, 245, 249);
  doc.text(`Target URL: ${scan.targetUrl}`, margin + 100, y + 25);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text(`Hostname: ${scan.hostname}  |  IP Address: ${scan.ipAddress || 'Verified'}`, margin + 100, y + 40);
  doc.text(
    `WordPress Core: ${scan.wpVersion ? `v${scan.wpVersion}` : 'Detected'}  |  Duration: ${(scan.durationMs / 1000).toFixed(2)}s`,
    margin + 100,
    y + 55
  );
  doc.text(
    `Web Server: ${scan.serverInfo?.webServer || 'Protected'}  |  Total Findings: ${scan.findings.length}`,
    margin + 100,
    y + 70
  );

  y += 105;

  // --- Categorical Scores ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(30, 41, 59);
  doc.text('CATEGORICAL SECURITY BREAKDOWN', margin, y);
  y += 12;

  const cats = [
    { name: 'SSL/TLS & Encryption', data: scan.categories.ssl_tls },
    { name: 'HTTP Security Headers', data: scan.categories.security_headers },
    { name: 'Core & Hardening Config', data: scan.categories.core_configuration },
    { name: 'Sensitive File Exposure', data: scan.categories.sensitive_files },
    { name: 'Plugins & Themes Security', data: scan.categories.plugins_themes }
  ];

  const colW = contentWidth / 5;
  cats.forEach((cat, idx) => {
    const x = margin + idx * colW;
    doc.setFillColor(241, 245, 249);
    doc.rect(x + 2, y, colW - 4, 45, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    const catScoreCol = cat.data.score >= 80 ? [16, 185, 129] : cat.data.score >= 60 ? [217, 119, 6] : [220, 38, 38];
    doc.setTextColor(catScoreCol[0], catScoreCol[1], catScoreCol[2]);
    doc.text(`${cat.data.score}%`, x + colW / 2, y + 18, { align: 'center' });

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(71, 85, 105);
    doc.text(cat.name, x + colW / 2, y + 32, { align: 'center', maxWidth: colW - 6 });
  });

  y += 60;

  // --- Scan Coverage & Deterministic Score Breakdown ---
  if (scan.coverage || scan.scoreBreakdown) {
    checkPageBreak(70);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(30, 41, 59);
    doc.text('SCAN COVERAGE & SCORE BREAKDOWN', margin, y);
    y += 12;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(51, 65, 85);
    if (scan.coverage) {
      const covLine = `Checks Executed: ${scan.coverage.executedChecks}/${scan.coverage.totalChecks}  |  Passed: ${scan.coverage.passedChecks}  |  Flagged: ${scan.coverage.failedChecks}  |  Skipped: ${scan.coverage.skippedChecks}`;
      doc.text(covLine, margin, y);
      y += 12;
      if (scan.coverage.skippedChecks > 0) {
        doc.setTextColor(180, 83, 9);
        doc.text('Note: Some checks could not be completed; overall grade is capped at A.', margin, y);
        y += 12;
        doc.setTextColor(51, 65, 85);
      }
    }
    if (scan.scoreBreakdown) {
      const formulaLines = doc.splitTextToSize(
        `Scoring: ${scan.scoreBreakdown.formulaNote}`,
        contentWidth
      );
      doc.text(formulaLines, margin, y);
      y += formulaLines.length * 10 + 6;
    }
    y += 6;
  }

  // --- Security Findings Matrix ---
  checkPageBreak(80);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(30, 41, 59);
  doc.text(`SECURITY AUDIT FINDINGS (${scan.findings.length})`, margin, y);
  y += 15;

  if (scan.findings.length === 0) {
    doc.setFillColor(240, 253, 244);
    doc.rect(margin, y, contentWidth, 35, 'F');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(22, 101, 52);
    doc.text('No vulnerabilities or security warnings identified. Exceptional security posture!', margin + 15, y + 21);
    y += 50;
  } else {
    for (const finding of scan.findings) {
      checkPageBreak(95);

      // Severity Color
      let badgeCol = [100, 116, 139];
      if (finding.severity === 'critical') badgeCol = [220, 38, 38];
      else if (finding.severity === 'high') badgeCol = [234, 88, 12];
      else if (finding.severity === 'medium') badgeCol = [217, 119, 6];
      else if (finding.severity === 'low') badgeCol = [37, 99, 235];

      // Finding Header Strip
      doc.setFillColor(248, 250, 252);
      doc.rect(margin, y, contentWidth, 24, 'F');
      doc.setFillColor(badgeCol[0], badgeCol[1], badgeCol[2]);
      doc.rect(margin, y, 4, 24, 'F');

      // Severity Badge
      doc.roundedRect(margin + 10, y + 4, 52, 15, 2, 2, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(255, 255, 255);
      doc.text(finding.severity.toUpperCase(), margin + 36, y + 14, { align: 'center' });

      // Title
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.text(finding.title, margin + 70, y + 15, { maxWidth: contentWidth - 140 });

      // Score Deduction
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(220, 38, 38);
      doc.text(`-${finding.scoreDeduction} pts`, pageWidth - margin - 10, y + 15, { align: 'right' });

      y += 28;

      // Description & Accuracy Metadata
      const accTier =
        finding.accuracyTier ||
        (finding.severity === 'info' ? 'INFORMATIONAL' : 'LIKELY');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      const metaText = `Accuracy: ${accTier}${finding.checkId ? ` | Check: ${finding.checkId}` : ''}${finding.detectionMethod ? ` | Method: ${finding.detectionMethod}` : ''}`;
      const metaLines = doc.splitTextToSize(metaText, contentWidth - 20);
      doc.text(metaLines, margin + 10, y);
      y += metaLines.length * 9 + 3;

      // Description & Impact
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(51, 65, 85);
      const descLines = doc.splitTextToSize(`Description: ${finding.description}`, contentWidth - 20);
      doc.text(descLines, margin + 10, y);
      y += descLines.length * 10 + 4;

      // Evidence & Remediation
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(15, 23, 42);
      doc.text(`Remediation: `, margin + 10, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(71, 85, 105);
      const remLines = doc.splitTextToSize(finding.remediation.summary, contentWidth - 75);
      doc.text(remLines, margin + 65, y);
      y += remLines.length * 10 + 10;
    }
  }

  // --- Discovered Plugins & Intelligence Section ---
  if (scan.plugins.length > 0) {
    checkPageBreak(80);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(30, 41, 59);
    doc.text(`DISCOVERED PLUGINS (${scan.plugins.length})`, margin, y);
    y += 12;

    doc.setFillColor(241, 245, 249);
    doc.rect(margin, y, contentWidth, 20, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    doc.text('PLUGIN NAME / SLUG', margin + 10, y + 13);
    doc.text('VERSION', margin + 220, y + 13);
    doc.text('KNOWN VULNERABILITIES', margin + 340, y + 13);
    y += 24;

    scan.plugins.forEach(p => {
      checkPageBreak(25);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(30, 41, 59);
      doc.text(`${p.name} (${p.slug})`, margin + 10, y);
      doc.text(p.version || 'Unspecified', margin + 220, y);

      if (p.vulnerabilities.length > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(220, 38, 38);
        doc.text(`${p.vulnerabilities.length} CVEs Detected`, margin + 340, y);
      } else {
        doc.setTextColor(22, 101, 52);
        doc.text('No CVEs Detected', margin + 340, y);
      }
      y += 14;
    });

    y += 15;
  }

  // --- Footer on all pages ---
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `WP Sentinel Passive Security Auditor • Page ${i} of ${totalPages} • Confidential Assessment`,
      pageWidth / 2,
      pageHeight - 20,
      { align: 'center' }
    );
  }

  return doc;
}
