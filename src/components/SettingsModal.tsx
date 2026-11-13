import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { X, Key, CheckCircle2, AlertTriangle, Shield, Loader2, LogOut, User } from 'lucide-react';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({ isOpen, onClose }) => {
  const { currentUser, userProfile, updateWpScanKey, updateProfilePreferences, logout } = useAuth();
  const [apiKey, setApiKey] = useState(userProfile?.wpscanApiKey || '');
  const [displayName, setDisplayName] = useState(userProfile?.displayName || currentUser?.displayName || '');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; message: string; plan?: string } | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  React.useEffect(() => {
    setApiKey(userProfile?.wpscanApiKey || '');
    setDisplayName(userProfile?.displayName || currentUser?.displayName || '');
    setSaveError(null);
    setSaveSuccess(false);
  }, [userProfile?.wpscanApiKey, userProfile?.displayName, currentUser?.displayName, isOpen]);

  React.useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !saving) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, saving, onClose]);

  if (!isOpen) return null;

  const handleTestKey = async () => {
    if (!apiKey.trim()) {
      setTestResult({ valid: false, message: 'Please enter a WPScan API key to test.' });
      return;
    }

    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/wpscan/test-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: apiKey.trim() })
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Connection failed';
      setTestResult({ valid: false, message: msg });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    if (!currentUser) {
      setSaveError('Please sign in first to save your account preferences and WPScan token.');
      return;
    }
    setSaving(true);
    setSaveSuccess(false);
    try {
      await updateWpScanKey(apiKey.trim());
      if (displayName.trim() && displayName.trim() !== userProfile?.displayName) {
        await updateProfilePreferences({ displayName: displayName.trim() });
      }
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save settings:', err);
      setSaveError(err instanceof Error ? err.message : 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  };

  const createdAtDisplay =
    userProfile?.createdAt || currentUser?.metadata?.creationTime
      ? new Date(userProfile?.createdAt || currentUser!.metadata!.creationTime!).toLocaleDateString()
      : '—';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/80 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-modal-title"
    >
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-5 sm:p-6 md:p-7 max-h-[90dvh] overflow-y-auto">
        <button
          type="button"
          onClick={onClose}
          className="absolute top-3.5 right-3.5 min-h-[44px] min-w-[44px] flex items-center justify-center text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 rounded-lg transition-colors"
          aria-label="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-5 pr-10">
          <div className="p-2.5 bg-sky-500/10 border border-sky-500/30 rounded-xl text-sky-400 shrink-0">
            <Shield className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <h2 id="settings-modal-title" className="text-base sm:text-lg font-bold text-white">Account & Scanner Settings</h2>
            <p className="text-xs text-slate-400">Profile details, isolation status, and WPScan configuration</p>
          </div>
        </div>

        <form onSubmit={handleSave} className="space-y-5">
          {/* User Account Info */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-sky-400" />
                {currentUser ? 'Registered User Account' : 'Guest Session'}
              </span>
              <span className={`font-medium ${currentUser ? 'text-emerald-400' : 'text-amber-400'}`}>
                {currentUser ? 'Authenticated' : 'Browser-Only'}
              </span>
            </div>

            {currentUser ? (
              <>
                <div className="space-y-1">
                  <label className="block text-[11px] text-slate-400">Display Name</label>
                  <input
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Your name or organization"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
                  />
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 text-slate-400 pt-1">
                  <span className="shrink-0">Email</span>
                  <span className="text-slate-200 font-mono break-all sm:text-right">{currentUser.email}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 text-slate-400">
                  <span className="shrink-0">Firebase UID</span>
                  <span className="text-slate-300 font-mono text-[11px] break-all sm:text-right">{currentUser.uid}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 text-slate-400">
                  <span className="shrink-0">Account Created</span>
                  <span className="text-slate-300 font-mono tabular-nums sm:text-right">{createdAtDisplay}</span>
                </div>
              </>
            ) : (
              <p className="text-slate-400 leading-relaxed">
                You are browsing as a guest. Scans are saved only in this browser. Sign in to sync scans, monitored sites, and V2 reports privately to your account.
              </p>
            )}
          </div>

          {/* WPScan API Integration */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <label className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <Key className="w-4 h-4 text-amber-400" />
                WPScan API Token (V1 Optional)
              </label>
              <a
                href="https://wpscan.com/api"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] text-sky-400 hover:underline"
              >
                Get free token →
              </a>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              WP Sentinel V1 includes a built-in curated CVE catalog. Adding your personal WPScan token enables live lookups against the WPScan API. Tokens are never displayed in plaintext after saving.
            </p>
            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Enter WPScan API token..."
                className="flex-1 min-h-[44px] px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono placeholder-slate-600 focus:outline-none focus:border-sky-500"
              />
              <button
                type="button"
                onClick={handleTestKey}
                disabled={testing || !apiKey}
                className="min-h-[44px] px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 shrink-0"
              >
                {testing && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Test Token
              </button>
            </div>

            {testResult && (
              <div
                className={`p-3 rounded-lg border text-xs flex items-start gap-2.5 ${
                  testResult.valid
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                }`}
              >
                {testResult.valid ? (
                  <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
                )}
                <div>
                  <p className="font-semibold">{testResult.valid ? 'Token Validated' : 'Validation Failed'}</p>
                  <p>{testResult.message}</p>
                  {testResult.plan && (
                    <p className="mt-1 text-[11px] text-emerald-400">Plan: {testResult.plan}</p>
                  )}
                </div>
              </div>
            )}
          </div>

          {saveError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{saveError}</span>
            </div>
          )}

          {saveSuccess && (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              Settings saved to your profile.
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
            <div>
              {currentUser && (
                <button
                  type="button"
                  onClick={() => {
                    logout();
                    onClose();
                  }}
                  className="min-h-[44px] inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  Sign Out
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2 ml-auto">
              <button
                type="button"
                onClick={onClose}
                className="min-h-[44px] px-4 py-2 text-xs font-medium text-slate-300 hover:text-white transition-colors rounded-lg"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="min-h-[44px] flex items-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold rounded-lg text-xs transition-colors disabled:opacity-50"
              >
                {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Save Settings
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
