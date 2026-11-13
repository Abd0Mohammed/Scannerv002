import React, { useState } from 'react';
import {
  Shield,
  Search,
  Lock,
  Layers,
  FileCode,
  FileText,
  Sparkles,
  ArrowRight,
  Activity,
  AlertCircle,
  Database,
  Loader2
} from 'lucide-react';

interface LandingPageProps {
  onStartScan: (targetUrl: string) => Promise<void>;
  scanning: boolean;
  scanError: string | null;
  onExploreDashboard: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onStartScan,
  scanning,
  scanError,
  onExploreDashboard
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [activeTab, setActiveTab] = useState<'passive' | 'intelligence' | 'ssrf' | 'scoring'>('passive');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim() || scanning) return;
    onStartScan(urlInput.trim());
  };

  const sampleTargets = [
    'https://wordpress.org',
    'https://wpmudev.com',
    'https://yoast.com'
  ];

  return (
    <div className="space-y-16 md:space-y-24 py-4 md:py-10">
      {/* Hero Section */}
      <section className="relative max-w-5xl mx-auto text-center px-2 sm:px-4">
        {/* Kicker */}
        <p className="text-xs font-mono text-cyan-400 tracking-wide mb-4">
          Passive WordPress Security Intelligence Engine
        </p>

        <h1 className="text-3xl sm:text-5xl lg:text-6xl font-extrabold text-white tracking-tight leading-[1.15]">
          Mission-Critical Security Auditing for{' '}
          <span className="text-cyan-400">
            WordPress Infrastructure
          </span>
        </h1>

        <p className="mt-5 text-sm sm:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed">
          Safely audit WordPress sites against 30+ passive vulnerability vectors, HTTP security headers, sensitive file exposures, and WPScan CVE intelligence—with AI-assisted remediation recommendations.
        </p>

        {/* Real URL Submission Scanner Box */}
        <div className="mt-8 sm:mt-10 max-w-2xl mx-auto">
          <form
            onSubmit={handleSubmit}
            className="p-2 bg-slate-900 border border-slate-800 rounded-xl shadow-lg flex flex-col sm:flex-row items-stretch sm:items-center gap-2"
          >
            <div className="relative flex-1 w-full flex items-center">
              <Search className="absolute left-3.5 w-4 h-4 text-slate-400" />
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter WordPress URL (e.g., https://example.com)..."
                disabled={scanning}
                aria-label="Target WordPress URL"
                className="w-full min-h-[44px] pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={scanning || !urlInput.trim()}
              className="w-full sm:w-auto min-h-[44px] px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold rounded-lg text-sm transition-colors flex items-center justify-center gap-2 whitespace-nowrap shrink-0"
            >
              {scanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                  Auditing Target...
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  Launch Security Scan
                </>
              )}
            </button>
          </form>

          {/* Quick Target Suggestions */}
          <div className="mt-3 flex flex-wrap items-center justify-center gap-x-3 gap-y-1.5 text-xs text-slate-400">
            <span>Quick audit test targets:</span>
            {sampleTargets.map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setUrlInput(st)}
                className="font-mono text-cyan-400 hover:underline hover:text-cyan-300 transition-colors py-1"
              >
                {st.replace('https://', '')}
              </button>
            ))}
          </div>

          <p className="mt-2 text-[11px] text-slate-400 leading-relaxed">
            Passive read-only HTTP &amp; TLS inspection only. Scan only websites you own or have permission to review. Need non-WordPress URL crawling, ZIP code analysis, or server agents? Use <strong className="text-slate-200">Site Sentinel V2</strong> above.
          </p>

          {/* Scan Error Alert */}
          {scanError && (
            <div className="mt-4 p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start gap-3 text-left text-xs text-rose-300">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
              <div className="space-y-1 min-w-0">
                <p className="font-semibold text-rose-200">Scan Execution Error</p>
                <p className="break-words">{scanError}</p>
                <p className="text-rose-200/80">
                  Tip: Verify the URL uses a valid public domain (private/localhost IPs are blocked for safety) and is reachable over HTTP/HTTPS.
                </p>
              </div>
            </div>
          )}

          {/* Scanning Progress Overlay */}
          {scanning && (
            <div className="mt-6 p-5 bg-slate-900 border border-cyan-500/30 rounded-xl text-left space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-cyan-400">
                <span className="flex items-center gap-2">
                  <Activity className="w-4 h-4 animate-spin" />
                  Executing Multi-Vector Passive Security Audit...
                </span>
                <span>Active</span>
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-cyan-400 h-full w-2/3"></div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 text-[11px] text-slate-300 font-mono">
                <div>SSRF &amp; DNS Validated</div>
                <div>SSL/TLS Protocol Audit</div>
                <div>Headers &amp; Clickjacking</div>
                <div>WPScan Threat Intel</div>
              </div>
            </div>
          )}
        </div>

        {/* Capabilities Strip */}
        <div className="mt-10 sm:mt-12 grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 text-center">
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
            <div className="text-base sm:text-lg font-bold font-mono text-cyan-400">100% Passive</div>
            <p className="text-xs text-slate-400 mt-1">Non-intrusive &amp; safe for production</p>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
            <div className="text-base sm:text-lg font-bold font-mono text-sky-400">Evidence-First</div>
            <p className="text-xs text-slate-400 mt-1">Verified responses &amp; 5-tier accuracy</p>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
            <div className="text-base sm:text-lg font-bold font-mono text-indigo-400">SSRF Hardened</div>
            <p className="text-xs text-slate-400 mt-1">Private IPs &amp; metadata blocked</p>
          </div>
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
            <div className="text-base sm:text-lg font-bold font-mono text-emerald-400">SentinAI</div>
            <p className="text-xs text-slate-400 mt-1">Server config recommendations</p>
          </div>
        </div>
      </section>

      {/* Interactive Architecture & Engine Pillars */}
      <section className="max-w-6xl mx-auto px-2 sm:px-4">
        <div className="text-center max-w-2xl mx-auto mb-8 sm:mb-10">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white">
            Enterprise Architecture &amp; Security Engine
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-2">
            Built from first principles following OWASP, NIST guidelines, and defense-in-depth security engineering.
          </p>
        </div>

        {/* Responsive Tab Switcher */}
        <div className="flex justify-center mb-6 sm:mb-8">
          <div className="w-full sm:w-auto p-1 bg-slate-900 border border-slate-800 rounded-xl grid grid-cols-2 sm:inline-flex gap-1 text-xs">
            <button
              type="button"
              onClick={() => setActiveTab('passive')}
              className={`min-h-[40px] px-3 sm:px-4 py-2 rounded-lg font-semibold transition-colors whitespace-nowrap ${
                activeTab === 'passive' ? 'bg-cyan-500 text-slate-950' : 'text-slate-300 hover:text-white'
              }`}
            >
              Passive Checks (30+)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('intelligence')}
              className={`min-h-[40px] px-3 sm:px-4 py-2 rounded-lg font-semibold transition-colors whitespace-nowrap ${
                activeTab === 'intelligence' ? 'bg-cyan-500 text-slate-950' : 'text-slate-300 hover:text-white'
              }`}
            >
              WPScan Intelligence
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('ssrf')}
              className={`min-h-[40px] px-3 sm:px-4 py-2 rounded-lg font-semibold transition-colors whitespace-nowrap ${
                activeTab === 'ssrf' ? 'bg-cyan-500 text-slate-950' : 'text-slate-300 hover:text-white'
              }`}
            >
              SSRF Defense
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('scoring')}
              className={`min-h-[40px] px-3 sm:px-4 py-2 rounded-lg font-semibold transition-colors whitespace-nowrap ${
                activeTab === 'scoring' ? 'bg-cyan-500 text-slate-950' : 'text-slate-300 hover:text-white'
              }`}
            >
              Deterministic Scoring
            </button>
          </div>
        </div>

        {/* Tab Content Display */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xl">
          {activeTab === 'passive' && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="space-y-3">
                <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded-xl w-fit">
                  <Layers className="w-5 h-5" />
                </div>
                <h3 className="text-base font-bold text-white">HTTP Security Headers</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options (Clickjacking defense), X-Content-Type-Options: nosniff, Referrer-Policy, and technology fingerprint leak suppression.
                </p>
              </div>

              <div className="space-y-3">
                <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-xl w-fit">
                  <FileCode className="w-5 h-5" />
                </div>
                <h3 className="text-base font-bold text-white">Core Hardening & Exposures</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Active XML-RPC detection (brute force and DDoS vector), REST API username enumeration (/wp-json/wp/v2/users), author ID redirection (?author=1), and uploads directory browsing.
                </p>
              </div>

              <div className="space-y-3">
                <div className="p-2.5 bg-purple-500/10 border border-purple-500/20 text-purple-400 rounded-xl w-fit">
                  <Lock className="w-5 h-5" />
                </div>
                <h3 className="text-base font-bold text-white">Sensitive File Hunter</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Passive non-destructive checks for wp-config.php.bak, wp-config.old, .env, .git/HEAD repository leaks, database dump archives (backup.sql), and exposed PHP debug.log files.
                </p>
              </div>
            </div>
          )}

          {activeTab === 'intelligence' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              <div className="space-y-4">
                <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-xl w-fit">
                  <Database className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-bold text-white">Dual-Tier Threat Intelligence Engine</h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  WP Sentinel merges our curated local WordPress vulnerability intelligence catalog with official WPScan API query capabilities.
                </p>
                <ul className="space-y-2 text-xs text-slate-300">
                  <li>
                    <strong>Zero Missing Keys Failure:</strong> Automatic fallback to curated CVE catalog with NIST/WPScan CVE records.
                  </li>
                  <li>
                    <strong>Component Signature Parsing:</strong> Extracts plugin slugs and theme versions from HTML script links and styles.
                  </li>
                  <li>
                    <strong>Custom Key Support:</strong> Plug in your personal WPScan token in settings for live quota execution.
                  </li>
                </ul>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-300 space-y-2 overflow-x-auto">
                <div className="text-cyan-400">Live WPScan Correlation Sample:</div>
                <div className="p-2.5 bg-slate-900 rounded border border-slate-800 text-[11px] space-y-1">
                  <div>[CVE-2024-28000] LiteSpeed Cache &lt; 6.4.0 (CVSS 9.8 Critical)</div>
                  <div>[CVE-2024-2123] Elementor &lt; 3.20.0 (CVSS 7.1 High Stored XSS)</div>
                  <div>[CVE-2020-35489] Contact Form 7 &lt; 5.3.2 (CVSS 9.8 File Upload RCE)</div>
                </div>
                <div className="text-emerald-400 text-[11px]">Mapped automatically with version-verified advisories</div>
              </div>
            </div>
          )}

          {activeTab === 'ssrf' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              <div className="space-y-4">
                <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl w-fit">
                  <Shield className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-bold text-white">Full-Spectrum SSRF Prevention</h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Every user-supplied URL undergoes DNS pre-flight verification and IP classification before any connection is initiated:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-slate-300">
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    Loopback (127.0.0.0/8, ::1)
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    Private RFC1918 (10.x, 172.16.x, 192.168.x)
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    Cloud Metadata (169.254.169.254)
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    Redirect Validation at Every Hop
                  </div>
                </div>
              </div>

              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-[11px] text-cyan-300 overflow-x-auto">
                <p className="text-slate-400 mb-1">Node.js SSRF Pre-flight Validation</p>
                <p>const addresses = await dns.lookup(hostname);</p>
                <p>if (isPrivateOrReservedIp(addresses[0].address)) &#123;</p>
                <p className="text-rose-400 pl-4">throw new Error('Access to private/reserved IP blocked');</p>
                <p>&#125;</p>
                <p className="text-emerald-400 mt-2">Max payload: 2MB | Timeout: 8s | Ports: 80, 443 only</p>
              </div>
            </div>
          )}

          {activeTab === 'scoring' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
              <div className="space-y-4">
                <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl w-fit">
                  <Activity className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-bold text-white">Transparent, Deterministic Scoring</h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Scores are computed from a 100-point base using accuracy-weighted deductions, deduplication, and explicit coverage checks:
                </p>
                <div className="space-y-1.5 text-xs font-mono tabular-nums">
                  <div className="flex justify-between gap-2 p-2 bg-rose-500/10 border border-rose-500/20 text-rose-300 rounded">
                    <span>Critical Finding (CVSS 9.0 - 10.0)</span>
                    <strong className="text-rose-400 shrink-0">-25 pts</strong>
                  </div>
                  <div className="flex justify-between gap-2 p-2 bg-orange-500/10 border border-orange-500/20 text-orange-300 rounded">
                    <span>High Severity Finding (CVSS 7.0 - 8.9)</span>
                    <strong className="text-orange-400 shrink-0">-15 pts</strong>
                  </div>
                  <div className="flex justify-between gap-2 p-2 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded">
                    <span>Medium Severity Finding (CVSS 4.0 - 6.9)</span>
                    <strong className="text-amber-400 shrink-0">-8 pts</strong>
                  </div>
                  <div className="flex justify-between gap-2 p-2 bg-blue-500/10 border border-blue-500/20 text-blue-300 rounded">
                    <span>Low Severity Hygiene (CVSS 0.1 - 3.9)</span>
                    <strong className="text-blue-400 shrink-0">-3 pts</strong>
                  </div>
                </div>
              </div>

              <div className="p-5 sm:p-6 bg-slate-950 border border-slate-800 rounded-xl text-center space-y-3">
                <span className="text-xs uppercase font-mono text-slate-400 tracking-wider">
                  Letter Grade Scale
                </span>
                <div className="grid grid-cols-3 gap-2 font-mono text-xs tabular-nums">
                  <div className="p-2 bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30">
                    <span className="text-base font-black">A+ / A</span>
                    <p className="text-[10px] text-slate-300">90 - 100 pts</p>
                  </div>
                  <div className="p-2 bg-blue-500/20 text-blue-300 rounded border border-blue-500/30">
                    <span className="text-base font-black">B</span>
                    <p className="text-[10px] text-slate-300">80 - 89 pts</p>
                  </div>
                  <div className="p-2 bg-amber-500/20 text-amber-300 rounded border border-amber-500/30">
                    <span className="text-base font-black">C</span>
                    <p className="text-[10px] text-slate-300">70 - 79 pts</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2 font-mono text-xs tabular-nums">
                  <div className="p-2 bg-orange-500/20 text-orange-300 rounded border border-orange-500/30">
                    <span className="text-base font-black">D</span>
                    <p className="text-[10px] text-slate-300">60 - 69 pts</p>
                  </div>
                  <div className="p-2 bg-rose-500/20 text-rose-300 rounded border border-rose-500/30">
                    <span className="text-base font-black">F</span>
                    <p className="text-[10px] text-slate-300">&lt; 60 pts</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Feature Grid */}
      <section className="max-w-6xl mx-auto px-2 sm:px-4">
        <div className="text-center max-w-xl mx-auto mb-10">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white">Full-Stack Capability Matrix</h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-2">
            Everything your SecOps and DevOps teams need to audit and protect WordPress fleets.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
            <div className="p-2.5 bg-cyan-500/10 text-cyan-400 rounded-lg w-fit">
              <Sparkles className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white">SentinAI Advisor</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Generate server-specific configuration recommendations (.htaccess, Nginx, wp-config.php) grounded strictly in observed scan evidence.
            </p>
          </div>

          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
            <div className="p-2.5 bg-blue-500/10 text-blue-400 rounded-lg w-fit">
              <FileText className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white">Executive PDF Reports</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Export client-ready security audit reports with categorical scores, accuracy tiers, coverage metrics, and remediation steps.
            </p>
          </div>

          <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-3">
            <div className="p-2.5 bg-emerald-500/10 text-emerald-400 rounded-lg w-fit">
              <Activity className="w-5 h-5" />
            </div>
            <h3 className="text-base font-bold text-white">Scan Comparison Engine</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Diff previous audits to verify that vulnerabilities were actually patched and confirm that security configuration has not degraded.
            </p>
          </div>
        </div>
      </section>

      {/* Footer Call to Action */}
      <section className="max-w-4xl mx-auto px-2 sm:px-4 text-center">
        <div className="p-6 sm:p-10 bg-slate-900 border border-slate-800 rounded-2xl space-y-5">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white">
            Ready to secure your WordPress websites?
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 max-w-lg mx-auto">
            Run your first passive audit now or sign in to track continuous site monitoring in your personal dashboard.
          </p>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }}
              className="min-h-[44px] px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-xs transition-colors"
            >
              Scan a Website Now
            </button>
            <button
              type="button"
              onClick={onExploreDashboard}
              className="min-h-[44px] px-6 py-3 bg-slate-800 hover:bg-slate-700 text-white font-semibold rounded-xl text-xs transition-colors flex items-center justify-center gap-1.5"
            >
              Open Auditor Dashboard
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </section>

    </div>
  );
};
