import React, { useState } from 'react';
import { MonitoredSite } from '../types/scanner';
import { useAuth } from '../context/AuthContext';
import {
  Globe,
  Plus,
  ShieldCheck,
  RotateCw,
  Trash2,
  Copy,
  Check,
  CheckCircle2,
  AlertCircle,
  Loader2,
  FileCode,
  ExternalLink
} from 'lucide-react';

interface SitesManagementProps {
  sites: MonitoredSite[];
  onAddSite: (url: string) => Promise<void>;
  onVerifySite: (siteId: string, url: string, token: string) => Promise<{ verified: boolean; message: string }>;
  onDeleteSite: (siteId: string) => Promise<void>;
  onRunAudit: (url: string) => Promise<void>;
  scanning: boolean;
}

export const SitesManagement: React.FC<SitesManagementProps> = ({
  sites,
  onAddSite,
  onVerifySite,
  onDeleteSite,
  onRunAudit,
  scanning
}) => {
  const { currentUser } = useAuth();
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [adding, setAdding] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationFeedback, setVerificationFeedback] = useState<{ id: string; success: boolean; message: string } | null>(null);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const [activeSiteForGuide, setActiveSiteForGuide] = useState<MonitoredSite | null>(null);

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSiteUrl.trim() || adding) return;

    setAdding(true);
    try {
      await onAddSite(newSiteUrl.trim());
      setNewSiteUrl('');
    } catch (err) {
      console.error('Error adding site:', err);
    } finally {
      setAdding(false);
    }
  };

  const handleTriggerVerification = async (site: MonitoredSite) => {
    setVerifyingId(site.id);
    setVerificationFeedback(null);
    try {
      const result = await onVerifySite(site.id, site.url, site.verificationToken);
      setVerificationFeedback({
        id: site.id,
        success: result.verified,
        message: result.message
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification failed';
      setVerificationFeedback({
        id: site.id,
        success: false,
        message: msg
      });
    } finally {
      setVerifyingId(null);
    }
  };

  const handleCopy = (token: string) => {
    navigator.clipboard.writeText(token);
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2500);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            Monitored WordPress Fleet
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Track authorized websites, verify domain ownership, and monitor continuous security compliance.
          </p>
        </div>

        {/* Add Website Form */}
        <form onSubmit={handleAddSubmit} className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
          <input
            type="text"
            value={newSiteUrl}
            onChange={(e) => setNewSiteUrl(e.target.value)}
            placeholder="https://example.com"
            disabled={adding}
            aria-label="Website URL to add"
            className="w-full sm:w-72 min-h-[44px] px-3.5 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={adding || !newSiteUrl.trim()}
            className="min-h-[44px] px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-sm flex items-center justify-center gap-1.5 whitespace-nowrap"
          >
            {adding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            Add Site
          </button>
        </form>
      </div>

      {/* Verification Feedback Banner */}
      {verificationFeedback && (
        <div
          className={`p-4 rounded-xl border text-xs flex items-start gap-3 animate-in fade-in ${
            verificationFeedback.success
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
          }`}
        >
          {verificationFeedback.success ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <AlertCircle className="w-5 h-5 text-amber-400 shrink-0" />
          )}
          <div>
            <p className="font-semibold">{verificationFeedback.success ? 'Verification Successful' : 'Verification Incomplete'}</p>
            <p className="mt-0.5">{verificationFeedback.message}</p>
          </div>
        </div>
      )}

      {/* Sites Grid */}
      {sites.length === 0 ? (
        <div className="py-16 text-center bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-4">
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-2xl w-fit mx-auto text-slate-500">
            <Globe className="w-10 h-10" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">No Monitored Websites Added Yet</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto mt-1">
              Add your WordPress production and staging domains to conduct scheduled audits and verify site ownership.
            </p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {sites.map((site) => {
            const isVerifying = verifyingId === site.id;

            return (
              <div
                key={site.id}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4 flex flex-col justify-between"
              >
                <div>
                  {/* Top Row: Hostname and Status */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-base font-bold text-white tracking-tight break-words">
                          {site.hostname}
                        </h3>
                        {site.verified ? (
                          <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded flex items-center gap-1 shrink-0">
                            <ShieldCheck className="w-3 h-3" />
                            Ownership Verified
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded flex items-center gap-1 shrink-0">
                            Unverified
                          </span>
                        )}
                      </div>
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-slate-400 hover:text-cyan-400 font-mono inline-flex items-center gap-1 mt-1 transition-colors break-all"
                      >
                        {site.url}
                        <ExternalLink className="w-3 h-3 shrink-0" />
                      </a>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        type="button"
                        onClick={() => onDeleteSite(site.id)}
                        className="min-h-[40px] min-w-[40px] flex items-center justify-center text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                        title="Remove site"
                        aria-label={`Remove ${site.hostname}`}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Security Stats */}
                  <div className="mt-4 p-3 bg-slate-950 border border-slate-800 rounded-xl grid grid-cols-2 gap-2 text-xs font-mono tabular-nums">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Latest Score</span>
                      <span className="text-sm font-bold text-white">
                        {site.lastScore !== undefined ? `${site.lastScore} / 100` : 'Not scanned'}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Letter Grade</span>
                      <span className="text-sm font-bold text-cyan-400">
                        {site.lastGrade || '—'}
                      </span>
                    </div>
                  </div>

                  {/* Verification Token Info */}
                  {!site.verified && (
                    <div className="mt-4 p-3.5 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-slate-400">
                        <span className="font-semibold text-slate-200">Ownership Token:</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(`<meta name="wp-sentinel-verification" content="${site.verificationToken}">`)}
                          className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 font-mono min-h-[32px]"
                        >
                          {copiedToken ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          Copy HTML Meta Tag
                        </button>
                      </div>

                      <div className="p-2 bg-slate-900 border border-slate-800 rounded font-mono text-[11px] text-slate-300 break-all select-all">
                        {`<meta name="wp-sentinel-verification" content="${site.verificationToken}">`}
                      </div>

                      <p className="text-[11px] text-slate-500 leading-normal">
                        Add this tag to your site's &lt;head&gt; (via header.php or theme settings) or create a DNS TXT record containing this token.
                      </p>
                    </div>
                  )}
                </div>

                {/* Card Actions */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-800/80">
                  {!site.verified ? (
                    <button
                      type="button"
                      onClick={() => handleTriggerVerification(site)}
                      disabled={isVerifying}
                      className="min-h-[40px] px-3.5 py-1.5 bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-slate-200 rounded-xl transition-colors flex items-center gap-1.5 disabled:opacity-50"
                    >
                      {isVerifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />}
                      Verify Ownership
                    </button>
                  ) : (
                    <span className="text-[11px] text-emerald-400 font-mono flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" />
                      Authorized Target
                    </span>
                  )}

                  <button
                    type="button"
                    onClick={() => onRunAudit(site.url)}
                    disabled={scanning}
                    className="min-h-[40px] px-4 py-1.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded-xl transition-all shadow-sm flex items-center gap-1.5 ml-auto"
                  >
                    <RotateCw className="w-3.5 h-3.5" />
                    Run Audit
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
