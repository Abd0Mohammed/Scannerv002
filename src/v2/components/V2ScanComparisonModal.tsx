import React, { useState, useMemo, useEffect } from 'react';
import { X, ArrowUpRight, ArrowDownRight, Minus, CheckCircle2, AlertCircle, ShieldAlert } from 'lucide-react';
import { V2ScanResult } from '../types/v2';

interface V2ScanComparisonModalProps {
  isOpen: boolean;
  onClose: () => void;
  scans: V2ScanResult[];
  initialBaseId?: string;
  initialCompareId?: string;
}

export const V2ScanComparisonModal: React.FC<V2ScanComparisonModalProps> = ({
  isOpen,
  onClose,
  scans,
  initialBaseId,
  initialCompareId
}) => {
  const [baseId, setBaseId] = useState<string>(initialBaseId || '');
  const [compareId, setCompareId] = useState<string>(initialCompareId || '');

  useEffect(() => {
    if (!isOpen) return;
    if (initialCompareId) {
      setCompareId(initialCompareId);
      const other = scans.find((s) => s.id !== initialCompareId);
      setBaseId(initialBaseId || other?.id || '');
    } else if (scans.length >= 2) {
      setCompareId(scans[0].id);
      setBaseId(scans[1].id);
    } else if (scans.length === 1) {
      setCompareId(scans[0].id);
      setBaseId(scans[0].id);
    }
  }, [isOpen, scans, initialBaseId, initialCompareId]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const baseScan = useMemo(() => scans.find((s) => s.id === baseId), [scans, baseId]);
  const targetScan = useMemo(() => scans.find((s) => s.id === compareId), [scans, compareId]);

  const diff = useMemo(() => {
    if (!baseScan || !targetScan) return null;
    const keyOf = (f: { title: string; evidence: { file?: string; line?: number; url?: string; package?: string } }) =>
      `${f.title}::${f.evidence.file || f.evidence.url || f.evidence.package || ''}`;

    const baseMap = new Map(baseScan.findings.map((f) => [keyOf(f), f]));
    const targetMap = new Map(targetScan.findings.map((f) => [keyOf(f), f]));

    const resolved = baseScan.findings.filter((f) => !targetMap.has(keyOf(f)));
    const introduced = targetScan.findings.filter((f) => !baseMap.has(keyOf(f)));
    const persistent = targetScan.findings.filter((f) => baseMap.has(keyOf(f)));

    return {
      scoreDelta: targetScan.score - baseScan.score,
      resolved,
      introduced,
      persistent
    };
  }, [baseScan, targetScan]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/80 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="v2-compare-title"
    >
      <div className="relative w-full max-w-3xl max-h-[90dvh] overflow-y-auto bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-4 sm:p-6 space-y-6">
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="min-w-0">
            <h2 id="v2-compare-title" className="text-base sm:text-lg font-semibold text-white">Scan-to-Scan Posture Comparison</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Compare an earlier baseline audit against a newer scan to verify fixes and detect regressions.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="min-h-[44px] min-w-[44px] flex items-center justify-center text-slate-400 hover:text-white transition-colors rounded-lg shrink-0"
            aria-label="Close comparison"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {scans.length < 2 ? (
          <div className="p-8 text-center bg-slate-950 border border-slate-800 rounded-xl space-y-2">
            <p className="text-sm font-medium text-white">At least 2 scans are required for comparison</p>
            <p className="text-xs text-slate-400">
              Run another URL, ZIP, or Agent audit to track security improvements over time.
            </p>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Baseline Scan (Before)</label>
                <select
                  value={baseId}
                  onChange={(e) => setBaseId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} — {s.score}/100 ({new Date(s.createdAt).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-slate-300">Comparison Scan (After)</label>
                <select
                  value={compareId}
                  onChange={(e) => setCompareId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} — {s.score}/100 ({new Date(s.createdAt).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {diff && baseScan && targetScan && (
              <div className="space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
                    <div className="text-xs text-slate-400">Score Change</div>
                    <div
                      className={`text-xl font-bold font-mono tabular-nums mt-1 flex items-center gap-1 ${
                        diff.scoreDelta > 0
                          ? 'text-emerald-400'
                          : diff.scoreDelta < 0
                            ? 'text-rose-400'
                            : 'text-slate-300'
                      }`}
                    >
                      {diff.scoreDelta > 0 ? (
                        <ArrowUpRight className="w-4 h-4" />
                      ) : diff.scoreDelta < 0 ? (
                        <ArrowDownRight className="w-4 h-4" />
                      ) : (
                        <Minus className="w-4 h-4" />
                      )}
                      {diff.scoreDelta > 0 ? `+${diff.scoreDelta}` : diff.scoreDelta} pts
                    </div>
                  </div>
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
                    <div className="text-xs text-slate-400">Resolved Findings</div>
                    <div className="text-xl font-bold font-mono tabular-nums text-emerald-400 mt-1">
                      {diff.resolved.length}
                    </div>
                  </div>
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
                    <div className="text-xs text-slate-400">New Findings</div>
                    <div className="text-xl font-bold font-mono tabular-nums text-rose-400 mt-1">
                      {diff.introduced.length}
                    </div>
                  </div>
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
                    <div className="text-xs text-slate-400">Unchanged</div>
                    <div className="text-xl font-bold font-mono tabular-nums text-slate-200 mt-1">
                      {diff.persistent.length}
                    </div>
                  </div>
                </div>

                {diff.resolved.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" />
                      No Longer Detected ({diff.resolved.length})
                    </div>
                    <ul className="bg-slate-950 border border-slate-800 rounded-xl divide-y divide-slate-800/80 text-xs">
                      {diff.resolved.map((f) => (
                        <li key={f.id} className="px-4 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1 sm:gap-2">
                          <span className="text-slate-200 break-words">{f.title}</span>
                          <span className="font-mono uppercase text-[11px] text-slate-400 shrink-0">{f.severity}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {diff.introduced.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-rose-400 flex items-center gap-1.5">
                      <ShieldAlert className="w-4 h-4" />
                      Newly Appeared ({diff.introduced.length})
                    </div>
                    <ul className="bg-slate-950 border border-slate-800 rounded-xl divide-y divide-slate-800/80 text-xs">
                      {diff.introduced.map((f) => (
                        <li key={f.id} className="px-4 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1 sm:gap-2">
                          <span className="text-slate-200 break-words">{f.title}</span>
                          <span className="font-mono uppercase text-[11px] text-rose-400 shrink-0">{f.severity}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {diff.resolved.length === 0 && diff.introduced.length === 0 && (
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-300 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-sky-400 shrink-0" />
                    <span>Both scans contain the same set of findings ({diff.persistent.length} persistent).</span>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
