import React, { useState } from 'react';
import { ScanResult, MonitoredSite } from '../types/scanner';
import { useAuth } from '../context/AuthContext';
import { generateSecurityPdfReport } from '../lib/pdf-report';
import {
  Shield,
  Activity,
  Globe,
  Search,
  ExternalLink,
  Download,
  Trash2,
  Scale,
  RotateCw,
  Plus,
  AlertCircle,
  Loader2
} from 'lucide-react';

interface DashboardProps {
  scans: ScanResult[];
  monitoredSites: MonitoredSite[];
  onSelectScan: (scan: ScanResult) => void;
  onDeleteScan: (scanId: string) => void;
  onLaunchScan: (targetUrl: string) => Promise<void>;
  onOpenCompare: (scanA?: ScanResult, scanB?: ScanResult) => void;
  onNavigateToSites: () => void;
  scanning: boolean;
}

export const Dashboard: React.FC<DashboardProps> = ({
  scans,
  monitoredSites,
  onSelectScan,
  onDeleteScan,
  onLaunchScan,
  onOpenCompare,
  onNavigateToSites,
  scanning
}) => {
  const { currentUser } = useAuth();
  const [quickUrl, setQuickUrl] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [gradeFilter, setGradeFilter] = useState<string>('all');
  const [exportingId, setExportingId] = useState<string | null>(null);

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim() || scanning) return;
    onLaunchScan(quickUrl.trim());
    setQuickUrl('');
  };

  const handleDownloadPdf = (scan: ScanResult) => {
    setExportingId(scan.id);
    try {
      const doc = generateSecurityPdfReport(scan);
      doc.save(`WP-Sentinel-${scan.hostname}-${new Date(scan.scanTimestamp).toISOString().split('T')[0]}.pdf`);
    } catch (err) {
      console.error('PDF generation error:', err);
    } finally {
      setExportingId(null);
    }
  };

  // Metrics (derived strictly from persisted scans)
  const totalScans = scans.length;
  const secureScans = scans.filter((s) => s.score >= 80).length;
  const warningScans = scans.filter((s) => s.score >= 50 && s.score < 80).length;
  const criticalScans = scans.filter((s) => s.score < 50).length;
  const avgScore =
    totalScans > 0 ? Math.round(scans.reduce((acc, s) => acc + s.score, 0) / totalScans) : 0;
  const totalVulns = scans.reduce((acc, s) => acc + s.findings.length, 0);
  const criticalVulns = scans.reduce(
    (acc, s) => acc + s.findings.filter((f) => f.severity === 'critical').length,
    0
  );
  const highVulns = scans.reduce(
    (acc, s) => acc + s.findings.filter((f) => f.severity === 'high').length,
    0
  );
  const latestScan = scans[0] || null;

  const filteredScans = scans.filter((s) => {
    const matchesSearch =
      s.hostname.toLowerCase().includes(searchFilter.toLowerCase()) ||
      s.targetUrl.toLowerCase().includes(searchFilter.toLowerCase());
    const matchesGrade = gradeFilter === 'all' || s.grade === gradeFilter;
    return matchesSearch && matchesGrade;
  });

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      
      {/* Dashboard Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-2">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Security Auditor Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            {currentUser
              ? `Signed in as ${currentUser.displayName || currentUser.email} — showing your private WordPress security audits.`
              : 'Guest mode (browser-only history). Sign in to sync scans and monitored domains.'}
          </p>
        </div>

        {/* Quick Launch Bar */}
        <form onSubmit={handleQuickScan} className="flex flex-col sm:flex-row gap-2 w-full lg:w-auto">
          <input
            type="text"
            value={quickUrl}
            onChange={(e) => setQuickUrl(e.target.value)}
            placeholder="Quick audit URL (e.g. https://site.com)..."
            aria-label="Quick audit URL"
            disabled={scanning}
            className="w-full sm:w-72 min-h-[44px] px-3.5 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={scanning || !quickUrl.trim()}
            className="min-h-[44px] px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-xl transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0"
          >
            {scanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
            Scan Target
          </button>
        </form>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Average Score */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 block">
              Fleet Average Score
            </span>
            <div className="text-2xl sm:text-3xl font-black font-mono tabular-nums text-white mt-1">
              {totalScans > 0 ? `${avgScore} / 100` : '—'}
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {avgScore >= 80 ? 'Good posture' : totalScans > 0 ? 'Needs remediation' : 'No scans yet'}
            </p>
          </div>
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-xl shrink-0">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        {/* Total Audits */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 block">
              Total Audits Completed
            </span>
            <div className="text-2xl sm:text-3xl font-black font-mono tabular-nums text-white mt-1">{totalScans}</div>
            <p className="text-[11px] font-mono tabular-nums mt-0.5 flex flex-wrap items-center gap-2">
              <span className="text-emerald-400">{secureScans} Secure</span>
              <span className="text-amber-400">{warningScans} Warn</span>
              <span className="text-rose-400">{criticalScans} Crit</span>
            </p>
          </div>
          <div className="p-3 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-xl shrink-0">
            <Shield className="w-5 h-5" />
          </div>
        </div>

        {/* Monitored Sites */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 block">
              Monitored Domains
            </span>
            <div className="text-2xl sm:text-3xl font-black font-mono tabular-nums text-white mt-1">
              {monitoredSites.length}
            </div>
            <button
              type="button"
              onClick={onNavigateToSites}
              className="text-[11px] text-cyan-400 hover:underline mt-0.5 block py-0.5"
            >
              Manage websites →
            </button>
          </div>
          <div className="p-3 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded-xl shrink-0">
            <Globe className="w-5 h-5" />
          </div>
        </div>

        {/* Identified Vulnerabilities */}
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-xs font-mono text-slate-400 block">
              Discovered Findings
            </span>
            <div className="text-2xl sm:text-3xl font-black font-mono tabular-nums text-rose-400 mt-1">{totalVulns}</div>
            <p className="text-[11px] text-rose-300 font-mono tabular-nums mt-0.5">
              {criticalVulns} Critical · {highVulns} High
            </p>
          </div>
          <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl shrink-0">
            <AlertCircle className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Latest Scan Status Summary */}
      {latestScan && (
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1 min-w-0">
            <span className="text-[11px] font-mono text-slate-400">
              Latest Scan Status
            </span>
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="text-base font-bold text-white break-all">{latestScan.hostname}</span>
              <span
                className={`px-2 py-0.5 text-[11px] font-mono tabular-nums font-bold rounded ${
                  latestScan.score >= 80
                    ? 'bg-emerald-500/15 text-emerald-400'
                    : latestScan.score >= 50
                      ? 'bg-amber-500/15 text-amber-400'
                      : 'bg-rose-500/15 text-rose-400'
                }`}
              >
                {latestScan.score}/100 ({latestScan.grade})
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono tabular-nums">
              {latestScan.findings.length} findings · {new Date(latestScan.scanTimestamp).toLocaleString()}
              {latestScan.coverage ? ` · ${latestScan.coverage.executedChecks}/${latestScan.coverage.totalChecks} checks` : ''}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => onSelectScan(latestScan)}
              className="min-h-[44px] sm:min-h-0 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg transition-colors whitespace-nowrap"
            >
              View Full Report
            </button>
            <button
              type="button"
              onClick={() => handleDownloadPdf(latestScan)}
              disabled={exportingId === latestScan.id}
              className="min-h-[44px] sm:min-h-0 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors inline-flex items-center gap-1.5 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              PDF
            </button>
          </div>
        </div>
      )}

      {/* Monitored Sites Quick Strip */}
      {monitoredSites.length > 0 && (
        <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-mono font-bold tracking-wider text-slate-300 flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Active Monitored Websites ({monitoredSites.length})
            </h3>
            <button
              type="button"
              onClick={onNavigateToSites}
              className="text-xs text-cyan-400 hover:underline py-1"
            >
              View all &amp; verification settings
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
            {monitoredSites.map((site) => (
              <div
                key={site.id}
                className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between gap-2"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-white text-xs truncate">{site.hostname}</span>
                    {site.verified && (
                      <span className="text-[10px] text-emerald-400 font-mono shrink-0">
                        · Verified
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono tabular-nums mt-0.5">
                    Score: {site.lastScore !== undefined ? `${site.lastScore}/100` : 'Not scanned'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onLaunchScan(site.url)}
                  disabled={scanning}
                  className="min-w-[40px] min-h-[40px] p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors text-xs flex items-center justify-center shrink-0"
                  title="Run Audit Now"
                  aria-label={`Run audit on ${site.hostname}`}
                >
                  <RotateCw className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan History Container */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden space-y-4 p-4 sm:p-6">
        {/* Filters & Search */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              Audit History
              <span className="text-xs font-mono tabular-nums text-slate-400">
                ({filteredScans.length})
              </span>
            </h2>
            <p className="text-xs text-slate-400">Complete historical security audits and exportable PDF records</p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            {/* Search input */}
            <div className="relative flex-1 sm:flex-initial">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Filter by hostname..."
                aria-label="Filter audit history by hostname"
                className="w-full sm:w-48 min-h-[40px] pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Grade filter */}
            <select
              value={gradeFilter}
              onChange={(e) => setGradeFilter(e.target.value)}
              aria-label="Filter by grade"
              className="w-full sm:w-auto min-h-[40px] px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Grades</option>
              <option value="A+">Grade A+</option>
              <option value="A">Grade A</option>
              <option value="B">Grade B</option>
              <option value="C">Grade C</option>
              <option value="D">Grade D</option>
              <option value="F">Grade F</option>
            </select>
          </div>
        </div>

        {/* Scans List (Mobile Cards + Desktop Table) */}
        {filteredScans.length === 0 ? (
          <div className="py-12 text-center space-y-3">
            <Shield className="w-10 h-10 text-slate-600 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">No security audit records found</p>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Execute your first passive WordPress audit using the quick scan launcher above.
            </p>
          </div>
        ) : (
          <>
            {/* Mobile Cards (< md) */}
            <div className="md:hidden space-y-3">
              {filteredScans.map((scan) => {
                const criticals = scan.findings.filter((f) => f.severity === 'critical').length;
                const highs = scan.findings.filter((f) => f.severity === 'high').length;
                const scoreCol =
                  scan.score >= 80 ? 'text-emerald-400' : scan.score >= 60 ? 'text-amber-400' : 'text-rose-400';

                return (
                  <div
                    key={scan.id}
                    className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <button
                        type="button"
                        onClick={() => onSelectScan(scan)}
                        className="text-left min-w-0 flex-1"
                      >
                        <div className="font-bold text-sm text-white break-all">{scan.hostname}</div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">{scan.targetUrl}</div>
                      </button>
                      <div className="text-right font-mono tabular-nums shrink-0">
                        <div className={`text-base font-black ${scoreCol}`}>{scan.score}/100</div>
                        <div className="text-[11px] text-slate-400">Grade {scan.grade}</div>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400 tabular-nums">
                      <span>{scan.wpVersion ? `WP v${scan.wpVersion}` : scan.isWordPress ? 'WordPress' : 'Generic'}</span>
                      <span>·</span>
                      <span>
                        {criticals > 0 ? `${criticals} Crit · ` : ''}
                        {highs > 0 ? `${highs} High · ` : ''}
                        {scan.findings.length} total
                      </span>
                      <span>·</span>
                      <span>{new Date(scan.scanTimestamp).toLocaleDateString()}</span>
                    </div>

                    <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
                      <button
                        type="button"
                        onClick={() => onSelectScan(scan)}
                        className="flex-1 min-h-[40px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded-lg"
                      >
                        Open Report
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDownloadPdf(scan)}
                        disabled={exportingId === scan.id}
                        className="min-h-[40px] min-w-[40px] px-2.5 bg-slate-900 border border-slate-800 text-slate-300 rounded-lg flex items-center justify-center"
                        aria-label={`Download PDF report for ${scan.hostname}`}
                      >
                        {exportingId === scan.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                      </button>
                      <button
                        type="button"
                        onClick={() => onOpenCompare(scan)}
                        className="min-h-[40px] min-w-[40px] px-2.5 bg-slate-900 border border-slate-800 text-slate-300 rounded-lg flex items-center justify-center"
                        aria-label={`Compare ${scan.hostname}`}
                      >
                        <Scale className="w-4 h-4" />
                      </button>
                      <button
                        type="button"
                        onClick={() => onDeleteScan(scan.id)}
                        className="min-h-[40px] min-w-[40px] px-2.5 bg-slate-900 border border-slate-800 text-rose-400 rounded-lg flex items-center justify-center"
                        aria-label={`Delete scan for ${scan.hostname}`}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Desktop Table (>= md) */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-mono text-[11px] border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Target Website</th>
                    <th className="py-3 px-4">Score &amp; Grade</th>
                    <th className="py-3 px-4">Stack</th>
                    <th className="py-3 px-4">Findings Breakdown</th>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {filteredScans.map((scan) => {
                    const criticals = scan.findings.filter((f) => f.severity === 'critical').length;
                    const highs = scan.findings.filter((f) => f.severity === 'high').length;
                    const scoreCol =
                      scan.score >= 80 ? 'text-emerald-400' : scan.score >= 60 ? 'text-amber-400' : 'text-rose-400';

                    return (
                      <tr
                        key={scan.id}
                        className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                        onClick={() => onSelectScan(scan)}
                      >
                        <td className="py-3.5 px-4">
                          <div className="font-bold text-white group-hover:text-cyan-300 transition-colors">
                            {scan.hostname}
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono truncate max-w-xs">
                            {scan.targetUrl}
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono tabular-nums">
                          <div className="flex items-center gap-2">
                            <span className={`text-base font-black ${scoreCol}`}>{scan.score}</span>
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-200">
                              {scan.grade}
                            </span>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-300">
                          {scan.wpVersion ? `v${scan.wpVersion}` : scan.isWordPress ? 'WordPress' : 'Generic'}
                        </td>

                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-1.5 font-mono tabular-nums text-[11px]">
                            {criticals > 0 && (
                              <span className="px-1.5 py-0.5 bg-rose-500/20 text-rose-300 rounded">
                                {criticals} Crit
                              </span>
                            )}
                            {highs > 0 && (
                              <span className="px-1.5 py-0.5 bg-orange-500/20 text-orange-300 rounded">
                                {highs} High
                              </span>
                            )}
                            <span className="text-slate-400">
                              {scan.findings.length} total
                            </span>
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono tabular-nums text-slate-400 text-[11px] whitespace-nowrap">
                          {new Date(scan.scanTimestamp).toLocaleDateString()} {new Date(scan.scanTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </td>

                        <td
                          className="py-3.5 px-4 text-right space-x-1 whitespace-nowrap"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <button
                            type="button"
                            onClick={() => handleDownloadPdf(scan)}
                            disabled={exportingId === scan.id}
                            className="p-2 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition-colors"
                            title="Download PDF Report"
                          >
                            {exportingId === scan.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Download className="w-3.5 h-3.5" />
                            )}
                          </button>

                          <button
                            type="button"
                            onClick={() => onOpenCompare(scan)}
                            className="p-2 text-slate-400 hover:text-blue-300 hover:bg-slate-800 rounded transition-colors"
                            title="Compare with another scan"
                          >
                            <Scale className="w-3.5 h-3.5" />
                          </button>

                          <button
                            type="button"
                            onClick={() => onDeleteScan(scan.id)}
                            className="p-2 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                            title="Delete Scan Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
