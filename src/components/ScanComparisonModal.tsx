import React, { useState } from 'react';
import { ScanResult } from '../types/scanner';
import {
  Scale,
  X,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Lock,
  Minus
} from 'lucide-react';

interface ScanComparisonModalProps {
  isOpen: boolean;
  onClose: () => void;
  scans: ScanResult[];
  initialScanA?: ScanResult;
  initialScanB?: ScanResult;
}

export const ScanComparisonModal: React.FC<ScanComparisonModalProps> = ({
  isOpen,
  onClose,
  scans,
  initialScanA,
  initialScanB
}) => {
  const [scanAId, setScanAId] = useState<string>(initialScanA?.id || scans[1]?.id || scans[0]?.id || '');
  const [scanBId, setScanBId] = useState<string>(initialScanB?.id || scans[0]?.id || '');

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const scanA = scans.find((s) => s.id === scanAId);
  const scanB = scans.find((s) => s.id === scanBId);

  if (!scanA || !scanB) {
    return (
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
        role="dialog"
        aria-modal="true"
        aria-label="Scan Comparison"
      >
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full text-center space-y-4">
          <Scale className="w-10 h-10 text-cyan-400 mx-auto" />
          <h3 className="text-base font-bold text-white">Insufficient Scans to Compare</h3>
          <p className="text-xs text-slate-400">
            You need at least two scans in your history to generate a side-by-side regression and remediation comparison.
          </p>
          <button
            type="button"
            onClick={onClose}
            className="min-h-[44px] px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  // Calculate score difference
  const scoreDiff = scanB.score - scanA.score;

  // Identify resolved findings (in A, but not in B)
  const resolvedFindings = scanA.findings.filter(
    (fa) => !scanB.findings.some((fb) => fb.id === fa.id || fb.title === fa.title)
  );

  // Identify new regressions (in B, but not in A)
  const newFindings = scanB.findings.filter(
    (fb) => !scanA.findings.some((fa) => fa.id === fb.id || fa.title === fb.title)
  );

  // Unresolved findings (still in B)
  const persistentFindings = scanB.findings.filter((fb) =>
    scanA.findings.some((fa) => fa.id === fb.id || fa.title === fb.title)
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-labelledby="v1-compare-title"
    >
      <div className="relative w-full max-w-4xl max-h-[90dvh] bg-slate-900 border border-slate-800 rounded-2xl sm:rounded-3xl shadow-2xl p-4 sm:p-6 md:p-8 flex flex-col overflow-hidden">
        
        {/* Header */}
        <div className="flex items-start sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2.5 bg-blue-500/10 border border-blue-500/30 text-blue-400 rounded-xl shrink-0">
              <Scale className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h2 id="v1-compare-title" className="text-base sm:text-xl font-bold text-white">Scan Differential & Regression Analysis</h2>
              <p className="text-xs text-slate-400">Compare security posture drift across historical audits</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close comparison modal"
            className="min-h-[44px] min-w-[44px] flex items-center justify-center text-slate-400 hover:text-white rounded-lg transition-colors shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scan Selectors Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 py-4 border-b border-slate-800">
          <div>
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1 font-semibold">
              Baseline Audit (Scan A)
            </label>
            <select
              value={scanAId}
              onChange={(e) => setScanAId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.hostname} — Score {s.score} ({new Date(s.scanTimestamp).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-mono uppercase text-slate-400 mb-1 font-semibold">
              Comparison Audit (Scan B)
            </label>
            <select
              value={scanBId}
              onChange={(e) => setScanBId(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.hostname} — Score {s.score} ({new Date(s.scanTimestamp).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Content Body (Scrollable) */}
        <div className="flex-1 overflow-y-auto py-6 space-y-6 pr-1 text-xs">
          
          {/* Posture Score Delta Box */}
          <div className="p-5 bg-slate-950 border border-slate-800 rounded-2xl flex flex-col sm:flex-row items-center justify-between gap-6 text-center sm:text-left">
            <div>
              <span className="text-[11px] font-mono uppercase text-slate-400 tracking-wider">
                Overall Score Evolution
              </span>
              <div className="flex items-center gap-4 mt-2">
                <div>
                  <div className="text-2xl font-black font-mono text-slate-300">{scanA.score}</div>
                  <span className="text-[10px] text-slate-500 font-mono">Scan A (Grade {scanA.grade})</span>
                </div>
                <ArrowRight className="w-5 h-5 text-slate-600" />
                <div>
                  <div className="text-2xl font-black font-mono text-cyan-400">{scanB.score}</div>
                  <span className="text-[10px] text-slate-500 font-mono">Scan B (Grade {scanB.grade})</span>
                </div>
              </div>
            </div>

            {/* Score Delta Badge */}
            <div
              className={`px-4 py-3 rounded-2xl flex items-center gap-2 font-mono font-bold text-sm ${
                scoreDiff > 0
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : scoreDiff < 0
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'bg-slate-800 text-slate-300'
              }`}
            >
              {scoreDiff > 0 ? (
                <>
                  <TrendingUp className="w-5 h-5 text-emerald-400" />
                  +{scoreDiff} pts Hardened
                </>
              ) : scoreDiff < 0 ? (
                <>
                  <TrendingDown className="w-5 h-5 text-rose-400" />
                  {scoreDiff} pts Degradation
                </>
              ) : (
                <>
                  <Minus className="w-5 h-5 text-slate-400" />
                  No Score Change
                </>
              )}
            </div>
          </div>

          {/* Categorical Delta Comparison Grid */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase text-slate-400 font-bold tracking-wider">
              Categorical Sub-score Drift
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {[
                { label: 'SSL/TLS', a: scanA.categories.ssl_tls.score, b: scanB.categories.ssl_tls.score },
                { label: 'Headers', a: scanA.categories.security_headers.score, b: scanB.categories.security_headers.score },
                { label: 'Core Hardening', a: scanA.categories.core_configuration.score, b: scanB.categories.core_configuration.score },
                { label: 'Sensitive Files', a: scanA.categories.sensitive_files.score, b: scanB.categories.sensitive_files.score },
                { label: 'Plugins & Themes', a: scanA.categories.plugins_themes.score, b: scanB.categories.plugins_themes.score }
              ].map((c) => {
                const diff = c.b - c.a;
                return (
                  <div key={c.label} className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-center">
                    <span className="text-[10px] text-slate-400 uppercase block truncate">{c.label}</span>
                    <div className="text-sm font-bold text-white mt-1">
                      {c.a}% → {c.b}%
                    </div>
                    <span
                      className={`text-[10px] font-semibold block mt-0.5 ${
                        diff > 0 ? 'text-emerald-400' : diff < 0 ? 'text-rose-400' : 'text-slate-500'
                      }`}
                    >
                      {diff > 0 ? `+${diff}%` : diff < 0 ? `${diff}%` : 'Stable'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Resolved Vulnerabilities (Fixed) */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase text-emerald-400 font-bold tracking-wider flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              Remediated Vulnerabilities ({resolvedFindings.length})
            </h3>
            {resolvedFindings.length === 0 ? (
              <p className="text-[11px] text-slate-500 italic p-3 bg-slate-950/50 rounded-xl border border-slate-800/80">
                No resolved findings between these two scans.
              </p>
            ) : (
              <div className="space-y-2">
                {resolvedFindings.map((f) => (
                  <div
                    key={f.id}
                    className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-emerald-300"
                  >
                    <div className="min-w-0">
                      <span className="font-semibold break-words">{f.title}</span>
                      <p className="text-[11px] text-emerald-400/80 break-words">{f.description}</p>
                    </div>
                    <span className="px-2 py-0.5 text-[10px] font-mono bg-emerald-500/20 rounded text-emerald-200 w-fit shrink-0 tabular-nums">
                      +{f.scoreDeduction} pts recovered
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* New Regressions (Introduced) */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono uppercase text-rose-400 font-bold tracking-wider flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" />
              New Security Regressions ({newFindings.length})
            </h3>
            {newFindings.length === 0 ? (
              <p className="text-[11px] text-slate-500 italic p-3 bg-slate-950/50 rounded-xl border border-slate-800/80">
                Zero new regressions detected in comparison scan. Great work!
              </p>
            ) : (
              <div className="space-y-2">
                {newFindings.map((f) => (
                  <div
                    key={f.id}
                    className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-rose-300"
                  >
                    <div className="min-w-0">
                      <span className="font-semibold break-words">{f.title}</span>
                      <p className="text-[11px] text-rose-400/80 break-words">{f.description}</p>
                    </div>
                    <span className="px-2 py-0.5 text-[10px] font-mono bg-rose-500/20 rounded text-rose-200 w-fit shrink-0 tabular-nums">
                      -{f.scoreDeduction} pts
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-slate-800 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="min-h-[44px] px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold transition-colors"
          >
            Close Comparison
          </button>
        </div>

      </div>
    </div>
  );
};
