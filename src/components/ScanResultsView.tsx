import React, { useState } from 'react';
import {
  ScanResult,
  SecurityFinding,
  FindingSeverity
} from '../types/scanner';
import { generateSecurityPdfReport } from '../lib/pdf-report';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Download,
  RotateCw,
  Sparkles,
  Copy,
  Check,
  Send,
  Loader2,
  Server,
  FileCode,
  Layers,
  ArrowRight,
  ExternalLink,
  Info
} from 'lucide-react';

interface ScanResultsViewProps {
  scan: ScanResult;
  onRescan: (url: string) => void;
  onSaveToSites?: (scan: ScanResult) => void;
  onCompareWith?: (scan: ScanResult) => void;
}

function getAccuracyMeta(tier?: string, severity?: FindingSeverity): {
  code: string;
  label: string;
  textClass: string;
} {
  const normalized = tier || (severity === 'info' ? 'INFORMATIONAL' : 'VERIFIED');
  switch (normalized) {
    case 'VERIFIED':
      return { code: 'VERIFIED', label: 'Verified', textClass: 'text-rose-300' };
    case 'LIKELY':
      return { code: 'LIKELY', label: 'Likely', textClass: 'text-amber-300' };
    case 'SUSPECTED':
      return { code: 'SUSPECTED', label: 'Suspected', textClass: 'text-yellow-300' };
    case 'INFORMATIONAL':
      return { code: 'INFORMATIONAL', label: 'Informational', textClass: 'text-slate-300' };
    case 'NOT_VERIFIED':
    default:
      return { code: 'NOT_VERIFIED', label: 'Not Verified', textClass: 'text-slate-400' };
  }
}

export const ScanResultsView: React.FC<ScanResultsViewProps> = ({
  scan,
  onRescan,
  onSaveToSites,
  onCompareWith
}) => {
  const [activeCategoryFilter, setActiveCategoryFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(scan.findings[0]?.id || null);

  // SentinAI Assistant State
  const [showAiAssistant, setShowAiAssistant] = useState(false);
  const [aiChatMessages, setAiChatMessages] = useState<Array<{ sender: 'user' | 'assistant'; text: string }>>([
    {
      sender: 'assistant',
      text: `I am SentinAI, your WordPress security advisor. I have reviewed the observed audit evidence for ${scan.hostname} (Score: ${scan.score}/100, Grade ${scan.grade}). Ask me for Nginx, Apache, or WordPress hardening recommendations.`
    }
  ]);
  const [aiChatInput, setAiChatInput] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const handleCopyCode = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippetId(id);
    setTimeout(() => setCopiedSnippetId(null), 2500);
  };

  const handleDownloadPdf = () => {
    setDownloadingPdf(true);
    try {
      const doc = generateSecurityPdfReport(scan);
      doc.save(`WP-Sentinel-Audit-${scan.hostname}-${new Date().toISOString().split('T')[0]}.pdf`);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handleSendAiMessage = async (customPrompt?: string) => {
    const textToSend = customPrompt || aiChatInput;
    if (!textToSend.trim() || aiLoading) return;

    const newMessages = [...aiChatMessages, { sender: 'user' as const, text: textToSend }];
    setAiChatMessages(newMessages);
    if (!customPrompt) setAiChatInput('');
    setAiLoading(true);

    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend,
          scanContext: scan
        })
      });

      const data = await res.json();
      if (data.reply) {
        setAiChatMessages([...newMessages, { sender: 'assistant', text: data.reply }]);
      } else if (data.error) {
        setAiChatMessages([
          ...newMessages,
          { sender: 'assistant', text: `SentinAI Notice: ${data.error}` }
        ]);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'AI request failed';
      setAiChatMessages([
        ...newMessages,
        { sender: 'assistant', text: `Connection error with SentinAI: ${msg}` }
      ]);
    } finally {
      setAiLoading(false);
    }
  };

  const handleDeepRemediate = async (finding: SecurityFinding) => {
    setShowAiAssistant(true);
    const prompt = `Provide an AI-assisted server configuration recommendation for finding: "${finding.title}" (Category: ${finding.category}, Severity: ${finding.severity}, Accuracy: ${finding.accuracyTier || 'VERIFIED'}). Provide example Apache and Nginx config snippets based strictly on this observed finding.`;
    await handleSendAiMessage(prompt);
  };

  // Filter findings
  const filteredFindings = scan.findings.filter((f) => {
    if (activeCategoryFilter !== 'all' && f.category !== activeCategoryFilter) return false;
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    return true;
  });

  const criticalCount = scan.findings.filter((f) => f.severity === 'critical').length;
  const highCount = scan.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = scan.findings.filter((f) => f.severity === 'medium').length;
  const lowCount = scan.findings.filter((f) => f.severity === 'low').length;

  const scoreColor =
    scan.score >= 90
      ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10'
      : scan.score >= 75
      ? 'text-cyan-400 border-cyan-500/40 bg-cyan-500/10'
      : scan.score >= 60
      ? 'text-amber-400 border-amber-500/40 bg-amber-500/10'
      : 'text-rose-400 border-rose-500/40 bg-rose-500/10';

  const gradeBadgeColor =
    scan.grade === 'A+' || scan.grade === 'A'
      ? 'bg-emerald-500 text-slate-950'
      : scan.grade === 'B'
      ? 'bg-blue-500 text-slate-950'
      : scan.grade === 'C'
      ? 'bg-amber-500 text-slate-950'
      : 'bg-rose-500 text-white';

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* Top Banner / Actions Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 sm:gap-6">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400 mb-2">
              <span className="font-semibold text-cyan-400">
                {scan.isWordPress ? 'WordPress Detected' : 'Generic Web Application'}
              </span>
              {scan.wpVersion && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-slate-200">Core v{scan.wpVersion}</span>
                </>
              )}
              {scan.isVersionOutdated && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-amber-300 font-semibold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Outdated Core
                  </span>
                </>
              )}
              <span aria-hidden="true">·</span>
              <span className="tabular-nums">{new Date(scan.scanTimestamp).toLocaleString()}</span>
            </div>

            <h1 className="text-xl sm:text-3xl font-extrabold text-white tracking-tight break-all">
              {scan.hostname}
            </h1>
            <p className="text-xs text-slate-400 mt-1 font-mono break-all">
              Target: <span className="text-slate-300">{scan.targetUrl}</span> · IP:{' '}
              <span className="text-slate-300">{scan.ipAddress || 'Verified'}</span> · Duration:{' '}
              <span className="tabular-nums">{(scan.durationMs / 1000).toFixed(2)}s</span>
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setShowAiAssistant(!showAiAssistant)}
              className="min-h-[44px] sm:min-h-0 flex items-center gap-2 px-4 py-2 bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 text-xs font-bold rounded-lg transition-colors whitespace-nowrap"
            >
              <Sparkles className="w-4 h-4 text-cyan-400" />
              SentinAI Advisor
            </button>

            <button
              type="button"
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              className="min-h-[44px] sm:min-h-0 flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              {downloadingPdf ? <Loader2 className="w-4 h-4 animate-spin text-cyan-400" /> : <Download className="w-4 h-4" />}
              Export PDF
            </button>

            {onSaveToSites && (
              <button
                type="button"
                onClick={() => onSaveToSites(scan)}
                className="min-h-[44px] sm:min-h-0 flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors whitespace-nowrap"
              >
                + Monitor Site
              </button>
            )}

            {onCompareWith && (
              <button
                type="button"
                onClick={() => onCompareWith(scan)}
                className="min-h-[44px] sm:min-h-0 flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors whitespace-nowrap"
              >
                Compare
              </button>
            )}

            <button
              type="button"
              onClick={() => onRescan(scan.targetUrl)}
              className="min-w-[44px] min-h-[44px] sm:min-w-0 sm:min-h-0 p-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors flex items-center justify-center"
              title="Re-run Scan"
              aria-label="Re-run scan"
            >
              <RotateCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Primary Score & Categorical Health Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Overall Security Score Card */}
        <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-5 sm:p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-mono text-slate-400 font-semibold">
                Security Posture Score
              </span>
              <span className={`px-2.5 py-0.5 text-xs font-black rounded ${gradeBadgeColor}`}>
                GRADE {scan.grade}
              </span>
            </div>

            <div className="flex items-baseline gap-4 my-3">
              <div className={`text-5xl sm:text-6xl font-black font-mono tabular-nums tracking-tight ${scoreColor.split(' ')[0]}`}>
                {scan.score}
              </div>
              <div className="text-slate-400 text-sm font-mono">
                / 100
                <p className="text-xs text-slate-400 font-sans mt-0.5">
                  {scan.score >= 90
                    ? 'Hardened posture'
                    : scan.score >= 75
                    ? 'Adequate protection'
                    : scan.score >= 60
                    ? 'Security deficiencies'
                    : 'Critical vulnerabilities present'}
                </p>
              </div>
            </div>

            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden my-4">
              <div
                className={`h-full transition-all duration-300 ${
                  scan.score >= 80 ? 'bg-emerald-500' : scan.score >= 60 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${scan.score}%` }}
              ></div>
            </div>
          </div>

          <div className="grid grid-cols-4 gap-2 pt-4 border-t border-slate-800 text-center font-mono tabular-nums">
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-sm font-bold text-rose-400">{criticalCount}</div>
              <div className="text-[10px] text-slate-400">Crit</div>
            </div>
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-sm font-bold text-orange-400">{highCount}</div>
              <div className="text-[10px] text-slate-400">High</div>
            </div>
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-sm font-bold text-amber-400">{mediumCount}</div>
              <div className="text-[10px] text-slate-400">Med</div>
            </div>
            <div className="p-2 bg-slate-950 border border-slate-800 rounded-lg">
              <div className="text-sm font-bold text-blue-400">{lowCount}</div>
              <div className="text-[10px] text-slate-400">Low</div>
            </div>
          </div>
        </div>

        {/* Categorical Breakdown Cards */}
        <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-medium">
                <span className="flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" /> SSL / TLS
                </span>
                <span className="font-bold text-white font-mono tabular-nums">{scan.categories.ssl_tls.score}%</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden my-2">
                <div className="bg-cyan-500 h-full" style={{ width: `${scan.categories.ssl_tls.score}%` }}></div>
              </div>
            </div>
            <p className="text-[11px] text-slate-400">
              HTTPS: {scan.serverInfo?.httpsEnforced ? 'Enforced' : 'Not enforced'} · HSTS: {scan.serverInfo?.hstsEnabled ? 'Active' : 'Missing'}
            </p>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-medium">
                <span className="flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-blue-400" /> HTTP Headers
                </span>
                <span className="font-bold text-white font-mono tabular-nums">{scan.categories.security_headers.score}%</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden my-2">
                <div className="bg-blue-500 h-full" style={{ width: `${scan.categories.security_headers.score}%` }}></div>
              </div>
            </div>
            <p className="text-[11px] text-slate-400">
              CSP, X-Frame-Options, nosniff &amp; Referrer protection.
            </p>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-medium">
                <span className="flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-emerald-400" /> Core Hardening
                </span>
                <span className="font-bold text-white font-mono tabular-nums">{scan.categories.core_configuration.score}%</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden my-2">
                <div className="bg-emerald-500 h-full" style={{ width: `${scan.categories.core_configuration.score}%` }}></div>
              </div>
            </div>
            <p className="text-[11px] text-slate-400">
              XML-RPC, REST API exposure, directory indexes &amp; user leaks.
            </p>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-medium">
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-purple-400" /> Sensitive Files
                </span>
                <span className="font-bold text-white font-mono tabular-nums">{scan.categories.sensitive_files.score}%</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden my-2">
                <div className="bg-purple-500 h-full" style={{ width: `${scan.categories.sensitive_files.score}%` }}></div>
              </div>
            </div>
            <p className="text-[11px] text-slate-400">
              wp-config backups, .env files, git metadata, debug.log.
            </p>
          </div>

          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between sm:col-span-2 md:col-span-2">
            <div>
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5 font-medium">
                <span className="flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-indigo-400" /> Plugins &amp; Themes CVEs
                </span>
                <span className="font-bold text-white font-mono tabular-nums">{scan.categories.plugins_themes.score}%</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden my-2">
                <div className="bg-indigo-500 h-full" style={{ width: `${scan.categories.plugins_themes.score}%` }}></div>
              </div>
            </div>
            <p className="text-[11px] text-slate-400">
              {scan.plugins.length} plugins identified · {scan.theme ? `Theme: ${scan.theme.name}` : 'Theme hidden'} · WPScan threat correlation.
            </p>
          </div>
        </div>
      </div>

      {/* Scan Coverage & Score Formula Transparency */}
      {(scan.coverage || scan.scoreBreakdown) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
          {scan.coverage && (
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-white">Scan Check Coverage</span>
                <span className="font-mono tabular-nums text-cyan-400">
                  {scan.coverage.executedChecks}/{scan.coverage.totalChecks} checks executed
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3 font-mono tabular-nums text-[11px] text-slate-400">
                <span className="text-emerald-400">{scan.coverage.passedChecks} passed</span>
                <span>·</span>
                <span className="text-rose-400">{scan.coverage.failedChecks} flagged</span>
                <span>·</span>
                <span className={scan.coverage.skippedChecks > 0 ? 'text-amber-300' : 'text-slate-400'}>
                  {scan.coverage.skippedChecks} skipped
                </span>
              </div>
              {scan.coverage.skippedChecks > 0 && (
                <p className="text-[11px] text-amber-300">
                  Partial check coverage detected — A+ grade is withheld when any check is skipped or blocked.
                </p>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 pt-1">
                {scan.coverage.checks.slice(0, 8).map((chk) => (
                  <div key={chk.id} className="text-[11px] text-slate-400 flex items-center justify-between gap-2 bg-slate-950 px-2.5 py-1.5 rounded border border-slate-800/80">
                    <span className="truncate text-slate-300">{chk.name}</span>
                    <span
                      className={`font-mono shrink-0 ${
                        chk.status === 'passed'
                          ? 'text-emerald-400'
                          : chk.status === 'skipped'
                            ? 'text-amber-400'
                            : chk.status === 'warning'
                              ? 'text-orange-400'
                              : 'text-rose-400'
                      }`}
                    >
                      {chk.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {scan.scoreBreakdown && (
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-white">Deterministic Score Breakdown</span>
                <span className="font-mono tabular-nums text-white font-bold">
                  {scan.scoreBreakdown.startingScore} - {scan.scoreBreakdown.totalDeductions} = {scan.scoreBreakdown.finalScore}
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed">{scan.scoreBreakdown.formulaNote}</p>
              <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono tabular-nums text-slate-400 pt-1">
                <span>Deduplicated: {scan.scoreBreakdown.deduplicatedCount}</span>
                <span>·</span>
                <span>Info/Unverified excluded: {scan.scoreBreakdown.excludedInformationalOrUnverified}</span>
              </div>
              {scan.scoreBreakdown.coverageNote && (
                <p className="text-[11px] text-amber-300">{scan.scoreBreakdown.coverageNote}</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Intelligence Status Banner */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-start sm:items-center gap-2.5 min-w-0">
          <div className="p-1.5 bg-cyan-500/10 text-cyan-400 rounded-lg shrink-0">
            <Info className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <span className="font-semibold text-slate-200">Threat Intelligence Status: </span>
            <span className="text-slate-400 break-words">{scan.wpscanIntelligence.statusMessage}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-slate-400 shrink-0 font-mono tabular-nums text-[11px]">
          <span>Detected CVEs: <strong className="text-rose-400">{scan.wpscanIntelligence.vulnCount}</strong></span>
          <span>Web Server: <strong className="text-slate-200">{scan.serverInfo?.webServer || 'Protected'}</strong></span>
        </div>
      </div>

      {/* Discovered Plugins */}
      {scan.plugins.length > 0 && (
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-mono font-bold tracking-wider text-slate-300 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Discovered Plugins &amp; Components ({scan.plugins.length})
            </h3>
            <span className="text-[11px] text-slate-400">Extracted from public asset signatures</span>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            {scan.plugins.map((p) => (
              <div
                key={p.slug}
                className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs flex flex-wrap items-center gap-2"
              >
                <div>
                  <span className="font-semibold text-slate-200">{p.name}</span>
                  <span className="ml-1.5 text-[11px] text-slate-400 font-mono">
                    {p.version ? `v${p.version}` : 'version unknown'}
                  </span>
                </div>
                {p.vulnerabilities.length > 0 ? (
                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                    p.version
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-slate-800 text-slate-300 border border-slate-700'
                  }`}>
                    {p.version ? `${p.vulnerabilities.length} CVEs` : `${p.vulnerabilities.length} advisories (unverified ver)`}
                  </span>
                ) : (
                  <span className="px-2 py-0.5 text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded">
                    No Known CVEs
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main Findings & AI Assistant Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 sm:gap-8">
        {/* Findings List */}
        <div className={`${showAiAssistant ? 'lg:col-span-7' : 'lg:col-span-12'} space-y-5 min-w-0`}>
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                Security Audit Findings
                <span className="text-xs text-slate-400 font-mono tabular-nums">
                  ({filteredFindings.length} of {scan.findings.length})
                </span>
              </h2>
              <p className="text-xs text-slate-400">Detailed vulnerability evidence, accuracy classification, and server configuration fixes</p>
            </div>

            <div className="flex items-center gap-1 overflow-x-auto pb-1 sm:pb-0">
              {['all', 'critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`min-h-[36px] px-3 py-1 rounded-lg text-xs font-medium capitalize transition-colors whitespace-nowrap shrink-0 ${
                    severityFilter === sev
                      ? 'bg-cyan-500 text-slate-950 font-bold'
                      : 'bg-slate-900 hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Finding Cards */}
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl">
              <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
              <h3 className="text-base font-bold text-white">No Findings Under Selected Filter</h3>
              <p className="text-xs text-slate-400 mt-1">Try selecting &quot;All&quot; to inspect the full list of audited controls.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredFindings.map((finding) => {
                const isExpanded = expandedFindingId === finding.id;
                const accuracy = getAccuracyMeta(finding.accuracyTier, finding.severity);

                let badgeColor = 'bg-slate-800 text-slate-300 border-slate-700';
                if (finding.severity === 'critical') badgeColor = 'bg-rose-500/20 text-rose-300 border-rose-500/40';
                else if (finding.severity === 'high') badgeColor = 'bg-orange-500/20 text-orange-300 border-orange-500/40';
                else if (finding.severity === 'medium') badgeColor = 'bg-amber-500/20 text-amber-300 border-amber-500/40';
                else if (finding.severity === 'low') badgeColor = 'bg-blue-500/20 text-blue-300 border-blue-500/40';

                return (
                  <div
                    key={finding.id}
                    className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl transition-colors overflow-hidden"
                  >
                    {/* Header Row */}
                    <button
                      type="button"
                      onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                      aria-expanded={isExpanded}
                      className="w-full text-left p-4 sm:p-5 flex items-start justify-between gap-3 cursor-pointer"
                    >
                      <div className="flex-1 min-w-0 space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                          <span className={`px-2 py-0.5 uppercase font-bold rounded border ${badgeColor}`}>
                            {finding.severity}
                          </span>
                          <span className={`font-semibold ${accuracy.textClass}`}>
                            {accuracy.code}
                          </span>
                          {finding.checkId && (
                            <>
                              <span aria-hidden="true" className="text-slate-600">·</span>
                              <span className="text-slate-400">{finding.checkId}</span>
                            </>
                          )}
                        </div>
                        <h4 className="text-sm font-bold text-white break-words">
                          {finding.title}
                        </h4>
                        <p className="text-xs text-slate-400 line-clamp-2 break-words">{finding.description}</p>
                      </div>

                      <div className="flex items-center gap-2.5 shrink-0 pt-0.5">
                        <span className="text-xs font-mono tabular-nums font-bold text-rose-400">
                          {finding.scoreDeduction > 0 ? `-${finding.scoreDeduction} pts` : '0 pts'}
                        </span>
                        <span className="text-slate-400 text-xs">
                          {isExpanded ? '▲' : '▼'}
                        </span>
                      </div>
                    </button>

                    {/* Expanded Detail Accordion */}
                    {isExpanded && (
                      <div className="p-4 sm:p-5 pt-0 border-t border-slate-800/80 space-y-4 text-xs">
                        {/* Accuracy Metadata Strip */}
                        <div className="mt-4 p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400">
                          <span>
                            Classification: <strong className={accuracy.textClass}>{accuracy.code}</strong>
                          </span>
                          {finding.detectionMethod && (
                            <span>
                              Method: <strong className="text-slate-200">{finding.detectionMethod}</strong>
                            </span>
                          )}
                          {finding.observedAt && (
                            <span className="tabular-nums">
                              Observed: <strong className="text-slate-200">{new Date(finding.observedAt).toLocaleString()}</strong>
                            </span>
                          )}
                        </div>

                        {/* Plain English Overview */}
                        <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                          <span className="font-semibold text-sky-400 block">What Happened:</span>
                          <p className="text-slate-200 leading-relaxed break-words">{finding.description}</p>
                        </div>

                        {/* Threat Impact & Details */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                            <span className="font-semibold text-rose-400 block">Why It Matters (Security Impact):</span>
                            <p className="text-slate-300 leading-relaxed break-words">{finding.impact}</p>
                          </div>

                          <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1.5 min-w-0">
                            <span className="font-semibold text-cyan-400 block">Observed Evidence &amp; Safe Verification:</span>
                            {finding.evidence.url && (
                              <p className="text-slate-400 break-all">
                                <strong>Affected URL:</strong> <span className="font-mono text-slate-300">{finding.evidence.url}</span>
                              </p>
                            )}
                            {finding.evidence.statusCode && (
                              <p className="text-slate-400">
                                <strong>HTTP Status:</strong> <span className="font-mono text-slate-300">{finding.evidence.statusCode}</span>
                              </p>
                            )}
                            {finding.evidence.headerName && (
                              <p className="text-slate-400 break-all">
                                <strong>Header:</strong> <span className="font-mono text-slate-300">{finding.evidence.headerName}: {finding.evidence.headerValue || 'Missing'}</span>
                              </p>
                            )}
                            {finding.evidence.details && (
                              <p className="text-slate-300 mt-1 break-words">{finding.evidence.details}</p>
                            )}
                            <p className="text-slate-400 pt-1 break-all">
                              <strong>Verify Safely:</strong> Run <code className="font-mono text-slate-300">curl -sI &quot;{finding.evidence.url || scan.targetUrl}&quot;</code>
                            </p>
                          </div>
                        </div>

                        {/* Remediation Steps */}
                        <div className="space-y-2">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-bold text-white text-xs font-mono">
                              Step-by-Step Remediation:
                            </span>
                            <button
                              type="button"
                              onClick={() => handleDeepRemediate(finding)}
                              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold py-1"
                            >
                              <Sparkles className="w-3.5 h-3.5" />
                              Ask SentinAI to customize
                            </button>
                          </div>
                          <p className="text-slate-300 leading-relaxed">{finding.remediation.summary}</p>
                          {finding.remediation.steps.length > 0 && (
                            <ul className="list-disc list-inside space-y-1 text-slate-400 pl-1">
                              {finding.remediation.steps.map((st, i) => (
                                <li key={i}>{st}</li>
                              ))}
                            </ul>
                          )}
                        </div>

                        {/* Code Snippet */}
                        {finding.remediation.codeSnippet && (
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between text-[11px] text-slate-400 px-1">
                              <span className="font-mono font-medium text-slate-300">
                                {finding.remediation.codeSnippet.filename}
                              </span>
                              <button
                                type="button"
                                onClick={() =>
                                  handleCopyCode(finding.id, finding.remediation.codeSnippet!.code)
                                }
                                className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium py-1"
                              >
                                {copiedSnippetId === finding.id ? (
                                  <>
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                    Copied!
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3.5 h-3.5" />
                                    Copy Patch
                                  </>
                                )}
                              </button>
                            </div>
                            <pre className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto text-[11px] font-mono text-cyan-300 leading-relaxed">
                              <code>{finding.remediation.codeSnippet.code}</code>
                            </pre>
                          </div>
                        )}

                        {/* CVE References */}
                        {finding.cveReferences && finding.cveReferences.length > 0 && (
                          <div className="pt-2 flex flex-wrap gap-2 items-center">
                            <span className="text-[11px] text-slate-400 font-mono">CVE References:</span>
                            {finding.cveReferences.map((cve) => (
                              <a
                                key={cve.cveId}
                                href={cve.url || `https://nvd.nist.gov/vuln/detail/${cve.cveId}`}
                                target="_blank"
                                rel="noreferrer"
                                className="px-2 py-1 bg-slate-950 border border-slate-800 hover:border-cyan-500/50 rounded text-[11px] font-mono text-cyan-400 flex items-center gap-1 transition-colors"
                              >
                                {cve.cveId}
                                <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* SentinAI Interactive Chat Assistant Drawer */}
        {showAiAssistant && (
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col h-[70dvh] max-h-[680px] lg:sticky lg:top-20">
            {/* AI Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="p-2 bg-cyan-500/15 border border-cyan-500/30 rounded-lg text-cyan-400 shrink-0">
                  <Sparkles className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <h3 className="text-sm font-bold text-white truncate">
                    SentinAI Advisor
                  </h3>
                  <p className="text-[11px] text-slate-400 font-mono truncate">WordPress Remediation Assistant</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowAiAssistant(false)}
                className="min-h-[36px] text-slate-300 hover:text-white text-xs px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 shrink-0"
              >
                Hide
              </button>
            </div>

            {/* AI Recommendation Disclaimer */}
            <div className="mt-3 p-2.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-[11px] text-amber-200 leading-relaxed">
              <strong>AI Recommendation:</strong> Explanations and config snippets are assistive recommendations only. Always test changes in staging and re-run a scan to confirm remediation.
            </div>

            {/* AI Messages Container */}
            <div className="flex-1 overflow-y-auto py-3 space-y-3 pr-1 text-xs">
              {aiChatMessages.map((msg, index) => (
                <div
                  key={index}
                  className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}
                >
                  <span className="text-[10px] text-slate-500 font-mono mb-1">
                    {msg.sender === 'user' ? 'Auditor' : 'SentinAI Recommendation'}
                  </span>
                  <div
                    className={`p-3 rounded-xl max-w-[92%] leading-relaxed whitespace-pre-wrap break-words ${
                      msg.sender === 'user'
                        ? 'bg-cyan-600 text-white'
                        : 'bg-slate-950 border border-slate-800 text-slate-200 font-sans'
                    }`}
                  >
                    {msg.text}
                  </div>
                </div>
              ))}
              {aiLoading && (
                <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs text-cyan-400">
                  <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                  SentinAI is preparing server configuration recommendations...
                </div>
              )}
            </div>

            {/* Quick Prompt Chips */}
            <div className="py-2 flex items-center gap-1.5 overflow-x-auto text-[11px] border-t border-slate-800">
              <button
                type="button"
                onClick={() => handleSendAiMessage('Generate a unified hardened Nginx config recommendation that addresses all observed findings.')}
                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg whitespace-nowrap shrink-0"
              >
                + Unified Nginx Conf
              </button>
              <button
                type="button"
                onClick={() => handleSendAiMessage('Explain how to reduce XML-RPC and user enumeration risks safely.')}
                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg whitespace-nowrap shrink-0"
              >
                + XML-RPC &amp; REST Hardening
              </button>
            </div>

            {/* Chat Input */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendAiMessage();
              }}
              className="pt-2 flex gap-2"
            >
              <input
                type="text"
                value={aiChatInput}
                onChange={(e) => setAiChatInput(e.target.value)}
                placeholder="Ask SentinAI about observed findings..."
                aria-label="Ask SentinAI about observed findings"
                className="flex-1 min-h-[44px] px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={aiLoading || !aiChatInput.trim()}
                aria-label="Send message to SentinAI"
                className="min-w-[44px] min-h-[44px] p-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold rounded-lg transition-colors flex items-center justify-center shrink-0"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};
