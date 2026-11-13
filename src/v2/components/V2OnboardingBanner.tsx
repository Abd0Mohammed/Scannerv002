import React from 'react';
import { Globe, FileArchive, Server, ShieldCheck, X } from 'lucide-react';

interface V2OnboardingBannerProps {
  onStartUrlScan: () => void;
  onStartZipScan: () => void;
  onStartAgentSetup: () => void;
  onDismiss: () => void;
}

export const V2OnboardingBanner: React.FC<V2OnboardingBannerProps> = ({
  onStartUrlScan,
  onStartZipScan,
  onStartAgentSetup,
  onDismiss
}) => {
  return (
    <section className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-white">Welcome to Site Sentinel — Quick Start Guide</h2>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">
            Site Sentinel checks websites, source code archives, and servers for common security gaps without making destructive changes. Choose the scan method that fits what you want to check:
          </p>
        </div>
        <button
          onClick={onDismiss}
          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs text-slate-400 hover:text-white rounded-md hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
        >
          <X className="w-3.5 h-3.5" />
          Skip guide
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col justify-between gap-3">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Globe className="w-4 h-4 text-sky-400" />
              1. URL Crawler
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Checks your live public website for HTTPS/TLS issues, missing security headers, exposed config files, and cookie weaknesses.
            </p>
          </div>
          <button
            onClick={onStartUrlScan}
            className="w-full py-2 px-3 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
          >
            Scan a Website URL
          </button>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col justify-between gap-3">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <FileArchive className="w-4 h-4 text-sky-400" />
              2. ZIP Code Analysis
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Safely inspects a zipped codebase in memory for accidentally committed secrets, vulnerable dependencies, and risky code patterns.
            </p>
          </div>
          <button
            onClick={onStartZipScan}
            className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs rounded-lg transition-colors"
          >
            Upload a ZIP Archive
          </button>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col justify-between gap-3">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-white">
              <Server className="w-4 h-4 text-sky-400" />
              3. Read-Only Server Agent
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Runs locally on servers you manage to verify file permissions and environment flags without granting remote command access.
            </p>
          </div>
          <button
            onClick={onStartAgentSetup}
            className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs rounded-lg transition-colors"
          >
            Set Up Server Agent
          </button>
        </div>
      </div>

      <div className="flex items-start gap-2.5 pt-2 border-t border-slate-800 text-xs text-slate-400">
        <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <span>
          <strong className="text-slate-200">Authorization Rule:</strong> Only scan websites, archives, or servers that you own or have written permission to test. Every scan requires a confirmation checkbox and is logged in your audit trail.
        </span>
      </div>
    </section>
  );
};
