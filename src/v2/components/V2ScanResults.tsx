import React, { useMemo, useState } from 'react';
import {
  Download,
  FileJson,
  Search,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Loader2,
  ShieldCheck,
  AlertTriangle,
  Globe,
  FileCode2,
  Lock,
  Cookie,
  Layers,
  Scale,
  CheckCircle2,
  Info,
  ExternalLink
} from 'lucide-react';
import { V2AccuracyTier, V2Finding, V2FindingStatus, V2ScanResult, V2Severity } from '../types/v2';
import { exportV2JsonReport, exportV2PdfReport } from '../lib/v2-pdf-report';
import {
  getAccuracyDisplay,
  getAccuracyTier,
  getPlainExplanation,
  getSafeVerifySteps,
  getStatusDisplay
} from '../lib/finding-guidance';

interface V2ScanResultsProps {
  scan: V2ScanResult;
  onBack?: () => void;
  onUpdateFindingStatus?: (scanId: string, findingId: string, status: V2FindingStatus) => void;
  onOpenCompare?: (scan: V2ScanResult) => void;
}

const SEVERITY_ORDER: Record<V2Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const STATUS_ORDER: Record<V2FindingStatus, number> = {
  unresolved: 1,
  accepted_risk: 2,
  resolved: 3
};

const SEVERITY_TEXT_COLORS: Record<V2Severity, string> = {
  critical: 'text-rose-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-sky-400',
  info: 'text-slate-400'
};

const ACCURACY_BADGE_CLASSES: Record<V2AccuracyTier, string> = {
  VERIFIED: 'bg-rose-500/10 border-rose-500/30 text-rose-300',
  LIKELY: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
  SUSPECTED: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300',
  INFORMATIONAL: 'bg-sky-500/10 border-sky-500/30 text-sky-300',
  NOT_VERIFIED: 'bg-slate-800 border-slate-700 text-slate-300'
};

type SortMode = 'severity-desc' | 'severity-asc' | 'status' | 'category';

export const V2ScanResults: React.FC<V2ScanResultsProps> = ({
  scan,
  onBack,
  onUpdateFindingStatus,
  onOpenCompare
}) => {
  const [activeTab, setActiveTab] = useState<'findings' | 'assets' | 'tech'>('findings');
  const [severityFilter, setSeverityFilter] = useState<'all' | V2Severity>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | V2FindingStatus>('all');
  const [sortBy, setSortBy] = useState<SortMode>('severity-desc');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>(() =>
    scan.findings[0]?.id ? { [scan.findings[0].id]: true } : {}
  );
  const [aiExplanations, setAiExplanations] = useState<Record<string, string>>({});
  const [aiLoadingId, setAiLoadingId] = useState<string | null>(null);
  const [aiError, setAiError] = useState<Record<string, string>>({});

  const statusCounts = useMemo(() => {
    const counts = { unresolved: 0, resolved: 0, accepted_risk: 0 };
    for (const f of scan.findings) {
      const s = f.status || 'unresolved';
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [scan.findings]);

  const filteredAndSortedFindings = useMemo(() => {
    const filtered = scan.findings.filter((f) => {
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      const effectiveStatus: V2FindingStatus = f.status || 'unresolved';
      if (statusFilter !== 'all' && effectiveStatus !== statusFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          getPlainExplanation(f).toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q) ||
          (f.evidence.file || '').toLowerCase().includes(q) ||
          (f.evidence.url || '').toLowerCase().includes(q) ||
          (f.evidence.package || '').toLowerCase().includes(q)
        );
      }
      return true;
    });

    return [...filtered].sort((a, b) => {
      if (sortBy === 'severity-desc') {
        return SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      }
      if (sortBy === 'severity-asc') {
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      }
      if (sortBy === 'status') {
        return STATUS_ORDER[a.status || 'unresolved'] - STATUS_ORDER[b.status || 'unresolved'];
      }
      return a.category.localeCompare(b.category);
    });
  }, [scan.findings, severityFilter, statusFilter, searchQuery, sortBy]);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const expandAllVisible = () => {
    const next: Record<string, boolean> = {};
    for (const f of filteredAndSortedFindings) next[f.id] = true;
    setExpandedIds(next);
  };

  const collapseAll = () => {
    setExpandedIds({});
  };

  const handleExplainFinding = async (finding: V2Finding) => {
    setAiLoadingId(finding.id);
    setAiError((prev) => ({ ...prev, [finding.id]: '' }));
    try {
      const res = await fetch('/api/v2/ai/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding,
          target: scan.target,
          mode: scan.mode
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'AI explanation unavailable.');
      }
      setAiExplanations((prev) => ({ ...prev, [finding.id]: data.explanation }));
    } catch (err: unknown) {
      setAiError((prev) => ({
        ...prev,
        [finding.id]: err instanceof Error ? err.message : 'Unable to generate explanation.'
      }));
    } finally {
      setAiLoadingId(null);
    }
  };

  const scoreColor =
    scan.score >= 80
      ? 'text-emerald-400'
      : scan.score >= 50
        ? 'text-amber-400'
        : 'text-rose-400';

  const healthLabel =
    scan.score >= 80
      ? 'Secure Posture'
      : scan.score >= 50
        ? 'Needs Attention (Warning)'
        : 'Critical Action Required';

  return (
    <div className="space-y-6">
      {/* Header Summary */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            {onBack && (
              <button
                type="button"
                onClick={onBack}
                className="text-xs font-medium text-sky-400 hover:text-sky-300 transition-colors mb-1 min-h-[36px] inline-flex items-center"
              >
                ← Back to History
              </button>
            )}
            <h2 className="text-lg sm:text-xl font-semibold text-white break-all">{scan.target}</h2>
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
              <span className="text-slate-200 uppercase">{scan.mode} audit</span>
              <span aria-hidden="true">·</span>
              <span>{new Date(scan.createdAt).toLocaleString()}</span>
              <span aria-hidden="true">·</span>
              <span>{scan.durationMs}ms</span>
              {scan.urlDetails?.ipAddress && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>IP {scan.urlDetails.ipAddress}</span>
                </>
              )}
              <span aria-hidden="true">·</span>
              <span className={scoreColor}>{healthLabel}</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <div className="px-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-left sm:text-right">
              <div className="text-[11px] text-slate-400">Security Score</div>
              <div className={`text-xl sm:text-2xl font-bold font-mono tabular-nums ${scoreColor}`}>
                {scan.score}/100 <span className="text-sm text-slate-300">({scan.grade})</span>
              </div>
            </div>

            {onOpenCompare && (
              <button
                type="button"
                onClick={() => onOpenCompare(scan)}
                className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
              >
                <Scale className="w-3.5 h-3.5 text-sky-400" />
                Compare Scan
              </button>
            )}

            <button
              type="button"
              onClick={() => exportV2PdfReport(scan)}
              className="min-h-[40px] inline-flex items-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Export PDF
            </button>

            <button
              type="button"
              onClick={() => exportV2JsonReport(scan)}
              className="min-h-[40px] inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <FileJson className="w-3.5 h-3.5" />
              Export JSON
            </button>
          </div>
        </div>

        {/* Category Scores */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mt-6 pt-5 border-t border-slate-800">
          {Object.entries(scan.categoryScores).map(([category, val]) => (
            <div key={category} className="space-y-1">
              <div className="text-xs text-slate-400 truncate">{category}</div>
              <div className="text-base font-semibold font-mono tabular-nums text-white">{val}/100</div>
            </div>
          ))}
        </div>
      </div>

      {/* Scan Coverage & Deterministic Score Breakdown */}
      {(scan.coverage || scan.scoreBreakdown) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
          {scan.coverage && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-white">Scan Check Coverage</span>
                <span className="font-mono tabular-nums text-sky-400 font-semibold">
                  {scan.coverage.executedChecks}/{scan.coverage.totalChecks} checks executed
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-3 font-mono tabular-nums text-[11px]">
                <span className="text-emerald-400">{scan.coverage.passedChecks} passed</span>
                <span className="text-amber-400">{scan.coverage.failedChecks} flagged</span>
                <span className={scan.coverage.skippedChecks > 0 ? 'text-rose-300' : 'text-slate-400'}>
                  {scan.coverage.skippedChecks} skipped
                </span>
              </div>
              {scan.coverage.skippedChecks > 0 && (
                <p className="text-[11px] text-amber-300/90 leading-relaxed">
                  {scan.coverage.executedChecks === 0
                    ? 'No checks executed; overall grade is marked N/A instead of reporting a false clean posture.'
                    : 'Partial check coverage: maximum grade is capped at A (94/100) whenever checks are skipped.'}
                </p>
              )}
              {scan.coverage.checks && scan.coverage.checks.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {scan.coverage.checks.slice(0, 8).map((chk) => (
                    <span
                      key={chk.id}
                      title={chk.detail || chk.name}
                      className={`px-2 py-0.5 rounded border text-[10px] font-mono ${
                        chk.status === 'passed'
                          ? 'bg-emerald-500/10 border-emerald-500/25 text-emerald-300'
                          : chk.status === 'skipped'
                            ? 'bg-slate-800 border-slate-700 text-slate-400'
                            : 'bg-amber-500/10 border-amber-500/25 text-amber-300'
                      }`}
                    >
                      {chk.name}: {chk.status}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {scan.scoreBreakdown && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-white">Deterministic Score Breakdown</span>
                <span className="font-mono tabular-nums text-slate-200">
                  {scan.scoreBreakdown.startingScore} − {scan.scoreBreakdown.totalDeductions} ={' '}
                  <strong className={scoreColor}>{scan.scoreBreakdown.finalScore}</strong>
                </span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed break-words">
                {scan.scoreBreakdown.formulaNote}
              </p>
              {scan.scoreBreakdown.coverageNote && (
                <p className="text-[11px] text-amber-300/90 leading-relaxed break-words">
                  {scan.scoreBreakdown.coverageNote}
                </p>
              )}
              <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono tabular-nums text-slate-400">
                <span>Deduplicated: {scan.scoreBreakdown.deduplicatedCount}</span>
                <span>Excluded info/unverified: {scan.scoreBreakdown.excludedInformationalOrUnverified}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 5-Tier Finding Accuracy Legend */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl px-4 sm:px-5 py-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs">
        <div className="flex items-start gap-2 text-slate-300">
          <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <strong className="text-white">Accuracy Classification:</strong>{' '}
            <span className="text-rose-300 font-medium">VERIFIED</span> (direct evidence) ·{' '}
            <span className="text-amber-300 font-medium">LIKELY</span> (semver/version range) ·{' '}
            <span className="text-yellow-300 font-medium">SUSPECTED</span> (heuristic pattern) ·{' '}
            <span className="text-sky-300 font-medium">INFORMATIONAL</span> (context, 0 pts) ·{' '}
            <span className="text-slate-300 font-medium">NOT VERIFIED</span> (insufficient evidence, 0 pts)
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 font-mono tabular-nums text-slate-400 shrink-0">
          <span>Unresolved: <strong className="text-white">{statusCounts.unresolved}</strong></span>
          <span>Resolved: <strong className="text-emerald-400">{statusCounts.resolved}</strong></span>
          <span>Accepted: <strong className="text-slate-300">{statusCounts.accepted_risk}</strong></span>
        </div>
      </div>

      {/* Section Tabs */}
      <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg w-full sm:w-fit overflow-x-auto">
        <button
          type="button"
          onClick={() => setActiveTab('findings')}
          className={`min-h-[38px] px-4 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'findings'
              ? 'bg-slate-800 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Security Findings ({scan.findings.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('assets')}
          className={`min-h-[38px] px-4 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'assets'
              ? 'bg-slate-800 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          {scan.mode === 'url' ? 'Surface & Assets' : scan.mode === 'zip' ? 'Files & Manifests' : 'Host Details'}
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('tech')}
          className={`min-h-[38px] px-4 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'tech'
              ? 'bg-slate-800 text-white'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Detected Stack ({scan.technologies.length})
        </button>
      </div>

      {/* TAB 1: FINDINGS */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto">
                {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-3 py-1 text-xs font-medium rounded-md capitalize transition-colors whitespace-nowrap shrink-0 ${
                      severityFilter === sev
                        ? 'bg-slate-800 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                    {sev !== 'all' && (
                      <span className="ml-1.5 font-mono tabular-nums text-slate-400">
                        {scan.summary[sev]}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as 'all' | V2FindingStatus)}
                aria-label="Filter by finding status"
                className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500"
              >
                <option value="all">All Statuses</option>
                <option value="unresolved">Unresolved ({statusCounts.unresolved})</option>
                <option value="resolved">Resolved ({statusCounts.resolved})</option>
                <option value="accepted_risk">Accepted Risk ({statusCounts.accepted_risk})</option>
              </select>

              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as SortMode)}
                aria-label="Sort findings"
                className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500"
              >
                <option value="severity-desc">Sort: Highest Severity</option>
                <option value="severity-asc">Sort: Lowest Severity</option>
                <option value="status">Sort: Unresolved First</option>
                <option value="category">Sort: Category</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <div className="relative flex-1 sm:w-64">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search title, file, URL, package..."
                  className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
                />
              </div>
              {filteredAndSortedFindings.length > 0 && (
                <>
                  <button
                    type="button"
                    onClick={expandAllVisible}
                    className="px-2.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-300 rounded-lg whitespace-nowrap shrink-0"
                  >
                    Expand All
                  </button>
                  <button
                    type="button"
                    onClick={collapseAll}
                    className="px-2.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] text-slate-300 rounded-lg whitespace-nowrap shrink-0"
                  >
                    Collapse All
                  </button>
                </>
              )}
            </div>
          </div>

          {filteredAndSortedFindings.length === 0 ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-10 text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
              <p className="text-sm font-medium text-white">No findings match the current filters</p>
              <p className="text-xs text-slate-400">
                {scan.findings.length === 0
                  ? 'All automated checks passed without security warnings.'
                  : 'Adjust the severity filter, status filter, or search query to view findings.'}
              </p>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800">
              {filteredAndSortedFindings.map((finding) => {
                const isOpen = Boolean(expandedIds[finding.id]);
                const accuracyTier = getAccuracyTier(finding);
                const accInfo = getAccuracyDisplay(finding);
                const statusInfo = getStatusDisplay(finding.status);
                const plainText = getPlainExplanation(finding);
                const verifySteps = getSafeVerifySteps(finding);
                const affectedLocation = finding.affectedResource || (
                  finding.evidence.file
                    ? `${finding.evidence.file}${finding.evidence.line ? `:${finding.evidence.line}` : ''}`
                    : finding.evidence.url || finding.evidence.package || finding.evidence.header || scan.target
                );

                return (
                  <div key={finding.id} className="p-4 sm:p-5">
                    <div className="flex items-start justify-between gap-3">
                      <button
                        type="button"
                        onClick={() => toggleExpand(finding.id)}
                        aria-expanded={isOpen}
                        className="flex-1 text-left space-y-1.5 min-w-0"
                      >
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className={`font-semibold uppercase font-mono ${SEVERITY_TEXT_COLORS[finding.severity]}`}>
                            {finding.severity}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 border rounded font-mono text-[10px] font-semibold uppercase ${ACCURACY_BADGE_CLASSES[accuracyTier]}`}
                          >
                            {accuracyTier.replace('_', ' ')}
                          </span>
                          <span className="text-slate-400">{finding.category}</span>
                          {finding.checkId && (
                            <span className="font-mono text-[11px] text-slate-500">{finding.checkId}</span>
                          )}
                          {finding.cwe && (
                            <span className="font-mono text-slate-400">{finding.cwe}</span>
                          )}
                          <span
                            className={`font-medium ${
                              statusInfo.value === 'resolved'
                                ? 'text-emerald-400'
                                : statusInfo.value === 'accepted_risk'
                                  ? 'text-slate-400'
                                  : 'text-sky-400'
                            }`}
                          >
                            · {statusInfo.label}
                          </span>
                        </div>
                        <h3 className="text-sm font-semibold text-white break-words">{finding.title}</h3>
                        <p className="text-xs text-slate-400 line-clamp-2 break-words">{plainText}</p>
                        <p className="text-[11px] font-mono text-slate-500 break-all">
                          Location: <span className="text-slate-300">{affectedLocation}</span>
                        </p>
                      </button>

                      <button
                        type="button"
                        onClick={() => toggleExpand(finding.id)}
                        aria-label={isOpen ? 'Collapse finding' : 'Expand finding'}
                        aria-expanded={isOpen}
                        className="min-h-[40px] min-w-[40px] flex items-center justify-center text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 shrink-0"
                      >
                        {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>

                    {isOpen && (
                      <div className="mt-4 pt-4 border-t border-slate-800/80 space-y-4 text-xs">
                        {/* Accuracy Classification & Resolution Status Controls */}
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-950 border border-slate-800 rounded-lg">
                          <div className="text-slate-300 space-y-1 min-w-0">
                            <div>
                              <span className="font-semibold text-white">{accInfo.label} ({accuracyTier}): </span>
                              <span className="text-slate-400">{accInfo.explanation}</span>
                            </div>
                            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-500">
                              {finding.detectionMethod && <span>Method: {finding.detectionMethod}</span>}
                              {finding.observedAt && <span>Observed: {new Date(finding.observedAt).toLocaleString()}</span>}
                              {finding.reference && (
                                <a
                                  href={finding.reference}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="inline-flex items-center gap-1 text-sky-400 hover:underline"
                                >
                                  Advisory Reference
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              )}
                            </div>
                          </div>
                          {onUpdateFindingStatus && (
                            <div className="flex items-center gap-2 shrink-0">
                              <label className="text-[11px] text-slate-400 whitespace-nowrap">
                                Finding Status:
                              </label>
                              <select
                                value={statusInfo.value}
                                onChange={(e) =>
                                  onUpdateFindingStatus(
                                    scan.id,
                                    finding.id,
                                    e.target.value as V2FindingStatus
                                  )
                                }
                                className="min-h-[36px] px-2.5 py-1 bg-slate-900 border border-slate-700 rounded-md text-xs text-white focus:outline-none focus:border-sky-500"
                              >
                                <option value="unresolved">Unresolved</option>
                                <option value="resolved">Resolved</option>
                                <option value="accepted_risk">Accepted Risk</option>
                              </select>
                            </div>
                          )}
                        </div>

                        {/* Plain English Explanation + Why It Matters */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-1">
                            <div className="text-sky-400 font-semibold">What Happened (Plain English)</div>
                            <p className="text-slate-200 leading-relaxed break-words">{plainText}</p>
                            {plainText !== finding.description && (
                              <p className="text-slate-400 leading-relaxed pt-1 break-words">{finding.description}</p>
                            )}
                          </div>
                          <div className="space-y-1">
                            <div className="text-amber-400 font-semibold">Why It Matters</div>
                            <p className="text-slate-200 leading-relaxed break-words">{finding.impact}</p>
                          </div>
                        </div>

                        {/* Supporting Evidence */}
                        {(finding.evidence.snippet ||
                          finding.evidence.header ||
                          finding.evidence.detail ||
                          finding.evidence.file ||
                          finding.evidence.url) && (
                          <div className="space-y-1.5">
                            <div className="text-slate-400 font-semibold">Affected Resource & Evidence</div>
                            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-[11px] text-slate-300 space-y-1 overflow-x-auto">
                              <div className="break-all">
                                <span className="text-slate-500">Resource: </span>
                                <span className="text-white">{affectedLocation}</span>
                              </div>
                              {(finding.evidence.snippet || finding.evidence.header || finding.evidence.detail) && (
                                <pre className="whitespace-pre-wrap break-all text-slate-300 pt-1">
                                  {finding.evidence.snippet || finding.evidence.header || finding.evidence.detail}
                                </pre>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Safe Verification & Remediation */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                            <div className="text-slate-300 font-semibold">How to Verify Safely (Non-Destructive)</div>
                            <p className="text-slate-400 leading-relaxed break-words">{verifySteps}</p>
                          </div>

                          <div className="p-3.5 bg-slate-950 border border-emerald-500/20 rounded-lg space-y-1">
                            <div className="text-emerald-400 font-semibold flex items-center gap-1.5">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              How to Fix
                            </div>
                            <p className="text-slate-200 leading-relaxed break-words">{finding.remediation}</p>
                          </div>
                        </div>

                        <div className="pt-1 flex flex-wrap items-center gap-3">
                          <button
                            type="button"
                            onClick={() => handleExplainFinding(finding)}
                            disabled={aiLoadingId === finding.id}
                            className="min-h-[40px] inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                          >
                            {aiLoadingId === finding.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                            )}
                            Generate Deep Fix Guide
                          </button>
                        </div>

                        {aiError[finding.id] && (
                          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 shrink-0" />
                            <span className="break-words">{aiError[finding.id]}</span>
                          </div>
                        )}

                        {aiExplanations[finding.id] && (
                          <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                            <div className="text-[11px] font-mono uppercase text-amber-300 font-semibold">
                              AI Recommendation — Verify Against Observed Evidence Before Applying
                            </div>
                            <div className="text-slate-200 whitespace-pre-wrap break-words leading-relaxed font-sans text-xs">
                              {aiExplanations[finding.id]}
                            </div>
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
      )}

      {/* TAB 2: ASSETS / FILES */}
      {activeTab === 'assets' && (
        <div className="space-y-6">
          {scan.urlDetails && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-white">
                    <Lock className="w-4 h-4 text-sky-400" />
                    TLS Certificate & Transport
                  </div>
                  {scan.urlDetails.tls ? (
                    <dl className="grid grid-cols-2 gap-y-2 text-xs">
                      <dt className="text-slate-400">Validation</dt>
                      <dd className={scan.urlDetails.tls.valid ? 'text-emerald-400 font-medium' : 'text-rose-400 font-medium'}>
                        {scan.urlDetails.tls.valid ? 'Valid Chain' : scan.urlDetails.tls.error || 'Invalid'}
                      </dd>
                      <dt className="text-slate-400">Protocol</dt>
                      <dd className="text-slate-200 font-mono">{scan.urlDetails.tls.protocol || 'Unknown'}</dd>
                      <dt className="text-slate-400">Issuer</dt>
                      <dd className="text-slate-200 truncate">{scan.urlDetails.tls.issuer || 'Unknown'}</dd>
                      <dt className="text-slate-400">Days Remaining</dt>
                      <dd className="text-slate-200 font-mono tabular-nums">
                        {scan.urlDetails.tls.daysRemaining ?? 'N/A'}
                      </dd>
                    </dl>
                  ) : (
                    <p className="text-xs text-amber-400">Target served over unencrypted HTTP; no TLS session inspected.</p>
                  )}
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-white">
                    <Globe className="w-4 h-4 text-sky-400" />
                    Crawl & Discovery Summary
                  </div>
                  <dl className="grid grid-cols-2 gap-y-2 text-xs">
                    <dt className="text-slate-400">Pages Crawled</dt>
                    <dd className="text-slate-200 font-mono tabular-nums">{scan.urlDetails.assets.pages.length}</dd>
                    <dt className="text-slate-400">Scripts / Styles</dt>
                    <dd className="text-slate-200 font-mono tabular-nums">
                      {scan.urlDetails.assets.scripts.length} JS / {scan.urlDetails.assets.stylesheets.length} CSS
                    </dd>
                    <dt className="text-slate-400">Documents / Images</dt>
                    <dd className="text-slate-200 font-mono tabular-nums">
                      {scan.urlDetails.assets.documents.length} docs / {scan.urlDetails.assets.images.length} imgs
                    </dd>
                    <dt className="text-slate-400">robots.txt / sitemap.xml</dt>
                    <dd className="text-slate-200 font-mono">
                      {scan.urlDetails.assets.robotsTxt.found ? 'Found' : 'Missing'} /{' '}
                      {scan.urlDetails.assets.sitemapXml.found
                        ? `${scan.urlDetails.assets.sitemapXml.urlCount} URLs`
                        : 'Missing'}
                    </dd>
                  </dl>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-800 text-sm font-semibold text-white">
                  Discovered Pages ({scan.urlDetails.assets.pages.length})
                </div>
                {/* Mobile Stacked Pages (< md) */}
                <div className="md:hidden divide-y divide-slate-800">
                  {scan.urlDetails.assets.pages.map((p) => (
                    <div key={p.url} className="p-4 space-y-1 text-xs">
                      <div className="font-mono text-slate-200 break-all">{p.url}</div>
                      <div className="text-slate-400 break-words">{p.title || '—'}</div>
                      <div className="flex items-center gap-3 font-mono tabular-nums text-[11px] text-slate-400">
                        <span className="text-slate-200">HTTP {p.statusCode}</span>
                        <span>·</span>
                        <span>{p.responseTimeMs}ms</span>
                      </div>
                    </div>
                  ))}
                </div>
                {/* Desktop Pages Table (>= md) */}
                <div className="hidden md:block overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="px-5 py-2.5 font-medium">URL</th>
                        <th className="px-4 py-2.5 font-medium">Title</th>
                        <th className="px-4 py-2.5 font-medium text-right">Status</th>
                        <th className="px-5 py-2.5 font-medium text-right">Latency</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {scan.urlDetails.assets.pages.map((p) => (
                        <tr key={p.url} className="hover:bg-slate-800/30">
                          <td className="px-5 py-2.5 font-mono text-slate-200 max-w-xs truncate">{p.url}</td>
                          <td className="px-4 py-2.5 text-slate-400 max-w-xs truncate">{p.title || '—'}</td>
                          <td className="px-4 py-2.5 font-mono tabular-nums text-right text-slate-200">{p.statusCode}</td>
                          <td className="px-5 py-2.5 font-mono tabular-nums text-right text-slate-400">{p.responseTimeMs}ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-white">
                  <Cookie className="w-4 h-4 text-sky-400" />
                  Cookie Security Flags ({scan.urlDetails.cookies.length})
                </div>
                {scan.urlDetails.cookies.length === 0 ? (
                  <p className="p-5 text-xs text-slate-400">No Set-Cookie headers were issued during the crawl.</p>
                ) : (
                  <>
                    {/* Mobile Stacked Cookies (< md) */}
                    <div className="md:hidden divide-y divide-slate-800">
                      {scan.urlDetails.cookies.map((c, idx) => (
                        <div key={`${c.name}-${idx}`} className="p-4 space-y-1.5 text-xs">
                          <div className="font-mono font-semibold text-slate-200 break-all">{c.name}</div>
                          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
                            <span className={c.httpOnly ? 'text-emerald-400' : 'text-amber-400'}>
                              HttpOnly: {c.httpOnly ? 'Yes' : 'No'}
                            </span>
                            <span className={c.secure ? 'text-emerald-400' : 'text-amber-400'}>
                              Secure: {c.secure ? 'Yes' : 'No'}
                            </span>
                            <span className="text-slate-300">SameSite: {c.sameSite || 'Unset'}</span>
                          </div>
                          <div className="text-[11px] text-slate-400 break-words">
                            {c.issues.length > 0 ? c.issues.join(', ') : 'Compliant'}
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Desktop Cookies Table (>= md) */}
                    <div className="hidden md:block overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="px-5 py-2.5 font-medium">Name</th>
                            <th className="px-4 py-2.5 font-medium">HttpOnly</th>
                            <th className="px-4 py-2.5 font-medium">Secure</th>
                            <th className="px-4 py-2.5 font-medium">SameSite</th>
                            <th className="px-5 py-2.5 font-medium">Issues</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {scan.urlDetails.cookies.map((c, idx) => (
                            <tr key={`${c.name}-${idx}`}>
                              <td className="px-5 py-2.5 font-mono text-slate-200">{c.name}</td>
                              <td className={`px-4 py-2.5 ${c.httpOnly ? 'text-emerald-400' : 'text-amber-400'}`}>
                                {c.httpOnly ? 'Yes' : 'No'}
                              </td>
                              <td className={`px-4 py-2.5 ${c.secure ? 'text-emerald-400' : 'text-amber-400'}`}>
                                {c.secure ? 'Yes' : 'No'}
                              </td>
                              <td className="px-4 py-2.5 font-mono text-slate-300">{c.sameSite || 'Unset'}</td>
                              <td className="px-5 py-2.5 text-slate-400">
                                {c.issues.length > 0 ? c.issues.join(', ') : 'Compliant'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </div>

              {(scan.urlDetails.assets.scripts.length > 0 || scan.urlDetails.assets.documents.length > 0) && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                    <div className="text-xs font-semibold text-white">JavaScript Assets ({scan.urlDetails.assets.scripts.length})</div>
                    <ul className="space-y-1 max-h-48 overflow-y-auto text-[11px] font-mono text-slate-400">
                      {scan.urlDetails.assets.scripts.slice(0, 30).map((s) => (
                        <li key={s} className="truncate">{s}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                    <div className="text-xs font-semibold text-white">Document Links ({scan.urlDetails.assets.documents.length})</div>
                    {scan.urlDetails.assets.documents.length === 0 ? (
                      <p className="text-xs text-slate-500">No public document files discovered.</p>
                    ) : (
                      <ul className="space-y-1 max-h-48 overflow-y-auto text-[11px] font-mono text-slate-400">
                        {scan.urlDetails.assets.documents.map((d) => (
                          <li key={d} className="truncate">{d}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}
            </>
          )}

          {scan.zipDetails && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-xs text-slate-400">Total Files</div>
                  <div className="text-lg font-semibold font-mono tabular-nums text-white mt-1">
                    {scan.zipDetails.totalFiles}
                  </div>
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-xs text-slate-400">Files Analyzed</div>
                  <div className="text-lg font-semibold font-mono tabular-nums text-white mt-1">
                    {scan.zipDetails.analyzedFiles}
                  </div>
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-xs text-slate-400">Uncompressed Size</div>
                  <div className="text-lg font-semibold font-mono tabular-nums text-white mt-1">
                    {(scan.zipDetails.uncompressedBytes / 1024).toFixed(1)} KB
                  </div>
                </div>
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                  <div className="text-xs text-slate-400">Manifests Found</div>
                  <div className="text-lg font-semibold font-mono tabular-nums text-white mt-1">
                    {scan.zipDetails.manifests.length}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-white">
                    <FileCode2 className="w-4 h-4 text-sky-400" />
                    Dependency Manifests
                  </div>
                  {scan.zipDetails.manifests.length === 0 ? (
                    <p className="text-xs text-slate-400">No dependency manifests detected in archive.</p>
                  ) : (
                    <div className="space-y-3">
                      {scan.zipDetails.manifests.map((m) => (
                        <div key={m.file} className="pb-3 border-b border-slate-800 last:border-b-0 last:pb-0">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono text-white">{m.file}</span>
                            <span className="text-slate-400 font-mono">{m.ecosystem} · {m.dependencyCount} deps</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="text-sm font-semibold text-white">Archive File Sample</div>
                  <ul className="space-y-1 max-h-56 overflow-y-auto text-[11px] font-mono text-slate-400">
                    {scan.zipDetails.fileTreeSample.map((f) => (
                      <li key={f} className="truncate">{f}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {scan.agentDetails && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-white mb-4">Authorized Agent Runtime Details</h3>
              <dl className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                <div>
                  <dt className="text-slate-400">Agent Name</dt>
                  <dd className="text-white font-medium mt-0.5">{scan.agentDetails.agentName}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Hostname</dt>
                  <dd className="text-white font-mono mt-0.5">{scan.agentDetails.hostname}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Environment</dt>
                  <dd className="text-white mt-0.5">{scan.agentDetails.environment}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">OS Platform</dt>
                  <dd className="text-white font-mono mt-0.5">{scan.agentDetails.osPlatform}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Runtime</dt>
                  <dd className="text-white font-mono mt-0.5">{scan.agentDetails.runtimeVersion}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Paths Inspected</dt>
                  <dd className="text-white font-mono tabular-nums mt-0.5">{scan.agentDetails.checkedPaths}</dd>
                </div>
              </dl>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: TECHNOLOGIES */}
      {activeTab === 'tech' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-white">
            <Layers className="w-4 h-4 text-sky-400" />
            Fingerprinted Technologies ({scan.technologies.length})
          </div>
          {scan.technologies.length === 0 ? (
            <p className="p-6 text-xs text-slate-400">No technology signatures were definitively detected.</p>
          ) : (
            <>
              {/* Mobile Stacked Tech Cards (< md) */}
              <div className="md:hidden divide-y divide-slate-800">
                {scan.technologies.map((tech) => (
                  <div key={tech.name} className="p-4 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-white">{tech.name}</span>
                      <span className="font-mono text-slate-300">{tech.version || '—'}</span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px] text-slate-400 capitalize">
                      <span>{tech.category}</span>
                      <span>·</span>
                      <span>Confidence: {tech.confidence}</span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-400 break-all">{tech.evidence}</div>
                  </div>
                ))}
              </div>

              {/* Desktop Tech Table (>= md) */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-5 py-2.5 font-medium">Technology</th>
                      <th className="px-4 py-2.5 font-medium">Category</th>
                      <th className="px-4 py-2.5 font-medium">Version</th>
                      <th className="px-4 py-2.5 font-medium">Confidence</th>
                      <th className="px-5 py-2.5 font-medium">Evidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {scan.technologies.map((tech) => (
                      <tr key={tech.name}>
                        <td className="px-5 py-3 font-medium text-white">{tech.name}</td>
                        <td className="px-4 py-3 text-slate-400 capitalize">{tech.category}</td>
                        <td className="px-4 py-3 font-mono text-slate-300">{tech.version || '—'}</td>
                        <td className="px-4 py-3 text-slate-300 capitalize">{tech.confidence}</td>
                        <td className="px-5 py-3 font-mono text-slate-400 truncate max-w-sm">{tech.evidence}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};
