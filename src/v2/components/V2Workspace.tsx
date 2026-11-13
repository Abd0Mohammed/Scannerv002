import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  LayoutDashboard,
  Globe,
  FileArchive,
  Server,
  History,
  Settings,
  Shield,
  ArrowRight,
  Loader2,
  AlertTriangle,
  Trash2,
  Download,
  Upload,
  CheckCircle2,
  FileText,
  Scale,
  Search,
  LogOut,
  UserCheck,
  UserX,
  HelpCircle,
  X,
  Menu
} from 'lucide-react';
import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  onSnapshot
} from 'firebase/firestore';
import { useAuth } from '../../context/AuthContext';
import { db, handleFirestoreError, OperationType } from '../../lib/firebase';
import { MonitoredSite } from '../../types/scanner';
import {
  V2AgentRecord,
  V2AuditLog,
  V2FindingStatus,
  V2ScanJob,
  V2ScanResult
} from '../types/v2';
import { V2ScanResults } from './V2ScanResults';
import { V2AgentPanel } from './V2AgentPanel';
import { V2OnboardingBanner } from './V2OnboardingBanner';
import { V2ScanComparisonModal } from './V2ScanComparisonModal';
import { exportV2PdfReport } from '../lib/v2-pdf-report';

type V2Tab = 'dashboard' | 'url-scan' | 'zip-scan' | 'agents' | 'history' | 'settings' | 'result';

interface V2WorkspaceProps {
  onSwitchToV1: () => void;
  onOpenAuth: (mode?: 'signin' | 'signup') => void;
}

function stripUndefined<T>(obj: T): T {
  if (Array.isArray(obj)) {
    return obj.map((item) => stripUndefined(item)) as unknown as T;
  }
  if (obj !== null && typeof obj === 'object') {
    const clean: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (v !== undefined) {
        clean[k] = stripUndefined(v);
      }
    }
    return clean as T;
  }
  return obj;
}

function getScanErrorHint(errorMessage: string): string {
  const lower = errorMessage.toLowerCase();
  if (lower.includes('private') || lower.includes('reserved') || lower.includes('metadata') || lower.includes('ssrf')) {
    return 'Tip: Internal, localhost, and private network addresses are blocked for security. Enter a publicly reachable domain (https://...).';
  }
  if (lower.includes('timeout') || lower.includes('abort') || lower.includes('econn')) {
    return 'Tip: The target site took too long to respond or blocked automated requests. Verify the domain is online and reachable via HTTPS.';
  }
  if (lower.includes('attest') || lower.includes('authoriz')) {
    return 'Tip: Check the authorization box below before launching a scan.';
  }
  if (lower.includes('zip') || lower.includes('archive') || lower.includes('traversal')) {
    return 'Tip: Upload a standard .zip archive under 15 MB containing source files without symlinks or "../" path entries.';
  }
  return 'Tip: Double-check the URL format (including https://) and ensure the server allows standard HTTP/HTTPS requests.';
}

export const V2Workspace: React.FC<V2WorkspaceProps> = ({ onSwitchToV1, onOpenAuth }) => {
  const {
    currentUser,
    userProfile,
    logout,
    updateProfilePreferences,
    sessionNotice,
    clearSessionNotice
  } = useAuth();

  const [activeTab, setActiveTab] = useState<V2Tab>('dashboard');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [scans, setScans] = useState<V2ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<V2ScanResult | null>(null);
  const [auditLogs, setAuditLogs] = useState<V2AuditLog[]>([]);
  const [agents, setAgents] = useState<V2AgentRecord[]>([]);
  const [monitoredSites, setMonitoredSites] = useState<MonitoredSite[]>([]);
  const [geminiReady, setGeminiReady] = useState<boolean | null>(null);

  useEffect(() => {
    if (!mobileMenuOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileMenuOpen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [mobileMenuOpen]);

  // Onboarding state (persisted in userProfile for signed-in users, or localStorage for guests)
  const [guestOnboardingDismissed, setGuestOnboardingDismissed] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('sitesentinel_v2_onboarding_done') === '1';
    }
    return false;
  });
  const [forceShowGuide, setForceShowGuide] = useState(false);

  // Comparison modal state
  const [compareOpen, setCompareOpen] = useState(false);
  const [compareTargetScanId, setCompareTargetScanId] = useState<string | undefined>(undefined);

  // Account Profile form state
  const [profileNameInput, setProfileNameInput] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [profileSavedMsg, setProfileSavedMsg] = useState<string | null>(null);

  // URL Scan Form State
  const [targetUrl, setTargetUrl] = useState('');
  const [crawlScope, setCrawlScope] = useState<'same-origin' | 'include-subdomains'>('same-origin');
  const [maxPages, setMaxPages] = useState(10);
  const [maxDepth, setMaxDepth] = useState(2);
  const [urlAuthorized, setUrlAuthorized] = useState(false);
  const [urlScanning, setUrlScanning] = useState(false);
  const [urlJob, setUrlJob] = useState<V2ScanJob | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  // ZIP Upload Form State
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [zipAuthorized, setZipAuthorized] = useState(false);
  const [zipUploading, setZipUploading] = useState(false);
  const [zipError, setZipError] = useState<string | null>(null);

  // History Filters
  const [modeFilter, setModeFilter] = useState<'all' | 'url' | 'zip' | 'agent'>('all');
  const [historySearch, setHistorySearch] = useState('');
  const [healthFilter, setHealthFilter] = useState<'all' | 'secure' | 'warning' | 'critical'>('all');

  useEffect(() => {
    setProfileNameInput(userProfile?.displayName || currentUser?.displayName || '');
  }, [userProfile?.displayName, currentUser?.displayName]);

  // Check V2 backend health
  useEffect(() => {
    fetch('/api/v2/health')
      .then((r) => r.json())
      .then((d) => setGeminiReady(Boolean(d.geminiConfigured)))
      .catch(() => setGeminiReady(false));
  }, []);

  // Load Audit Logs & Agents scoped strictly to current user (or anonymous when signed out)
  const refreshAuditAndAgents = useCallback(() => {
    const uidParam = currentUser?.uid ? `?userId=${encodeURIComponent(currentUser.uid)}` : '';
    fetch(`/api/v2/audit-logs${uidParam}`)
      .then((r) => r.json())
      .then((d) => setAuditLogs(d.logs || []))
      .catch(() => {});

    fetch(`/api/v2/agent/list${uidParam}`)
      .then((r) => r.json())
      .then((d) => setAgents(d.agents || []))
      .catch(() => {});
  }, [currentUser?.uid]);

  useEffect(() => {
    refreshAuditAndAgents();
  }, [refreshAuditAndAgents, activeTab]);

  // Load V2 Scans & read-only V1 monitored sites summary (strictly per user)
  useEffect(() => {
    if (!currentUser) {
      setMonitoredSites([]);
      setSelectedScan(null);
      const cached = localStorage.getItem('sitesentinel_v2_guest_scans');
      if (cached) {
        try {
          setScans(JSON.parse(cached));
        } catch {
          setScans([]);
        }
      } else {
        setScans([]);
      }
      return;
    }

    const colPath = `users/${currentUser.uid}/v2_scans`;
    const colRef = collection(db, 'users', currentUser.uid, 'v2_scans');
    const unsubScans = onSnapshot(
      colRef,
      (snapshot) => {
        const list: V2ScanResult[] = [];
        snapshot.forEach((d) => list.push(d.data() as V2ScanResult));
        list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        setScans(list);
      },
      (err) => {
        handleFirestoreError(err, OperationType.LIST, colPath);
      }
    );

    // Read-only overview of user's monitored sites from V1 collection (does not mutate V1 data)
    const sitesPath = `users/${currentUser.uid}/sites`;
    const sitesRef = collection(db, 'users', currentUser.uid, 'sites');
    const unsubSites = onSnapshot(
      sitesRef,
      (snapshot) => {
        const list: MonitoredSite[] = [];
        snapshot.forEach((d) => list.push(d.data() as MonitoredSite));
        setMonitoredSites(list);
      },
      (err) => {
        handleFirestoreError(err, OperationType.LIST, sitesPath);
      }
    );

    return () => {
      unsubScans();
      unsubSites();
    };
  }, [currentUser]);

  const persistV2Scan = useCallback(
    async (result: V2ScanResult) => {
      if (currentUser) {
        const normalized: V2ScanResult = stripUndefined({
          ...result,
          userId: currentUser.uid,
          version: 'v2'
        });
        try {
          await setDoc(doc(db, 'users', currentUser.uid, 'v2_scans', normalized.id), normalized);
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, `users/${currentUser.uid}/v2_scans/${normalized.id}`);
        }
      } else {
        setScans((prev) => {
          const updated = [result, ...prev.filter((s) => s.id !== result.id)].slice(0, 20);
          localStorage.setItem('sitesentinel_v2_guest_scans', JSON.stringify(updated));
          return updated;
        });
      }
    },
    [currentUser]
  );

  const handleUpdateFindingStatus = useCallback(
    async (scanId: string, findingId: string, status: V2FindingStatus) => {
      const targetScan = scans.find((s) => s.id === scanId) || selectedScan;
      if (!targetScan) return;

      const updatedScan: V2ScanResult = {
        ...targetScan,
        findings: targetScan.findings.map((f) => (f.id === findingId ? { ...f, status } : f))
      };

      setSelectedScan((prev) => (prev?.id === scanId ? updatedScan : prev));

      if (currentUser) {
        try {
          await setDoc(
            doc(db, 'users', currentUser.uid, 'v2_scans', scanId),
            stripUndefined({ ...updatedScan, userId: currentUser.uid, version: 'v2' }),
            { merge: true }
          );
        } catch (err) {
          handleFirestoreError(err, OperationType.UPDATE, `users/${currentUser.uid}/v2_scans/${scanId}`);
        }
      } else {
        setScans((prev) => {
          const updated = prev.map((s) => (s.id === scanId ? updatedScan : s));
          localStorage.setItem('sitesentinel_v2_guest_scans', JSON.stringify(updated));
          return updated;
        });
      }
    },
    [scans, selectedScan, currentUser]
  );

  const syncAgentToFirestore = useCallback(
    async (agent: V2AgentRecord) => {
      if (!currentUser) return;
      try {
        await setDoc(
          doc(db, 'users', currentUser.uid, 'v2_agents', agent.id),
          stripUndefined({ ...agent, userId: currentUser.uid }),
          { merge: true }
        );
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, `users/${currentUser.uid}/v2_agents/${agent.id}`);
      }
    },
    [currentUser]
  );

  const handleDeleteScan = async (scanId: string) => {
    if (currentUser) {
      try {
        await deleteDoc(doc(db, 'users', currentUser.uid, 'v2_scans', scanId));
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, `users/${currentUser.uid}/v2_scans/${scanId}`);
      }
    } else {
      setScans((prev) => {
        const updated = prev.filter((s) => s.id !== scanId);
        localStorage.setItem('sitesentinel_v2_guest_scans', JSON.stringify(updated));
        return updated;
      });
    }
    if (selectedScan?.id === scanId) {
      setSelectedScan(null);
      setActiveTab('history');
    }
  };

  const handleDismissOnboarding = async () => {
    setForceShowGuide(false);
    if (currentUser) {
      await updateProfilePreferences({ onboardingCompleted: true }).catch(() => {});
    } else {
      setGuestOnboardingDismissed(true);
      localStorage.setItem('sitesentinel_v2_onboarding_done', '1');
    }
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentUser || !profileNameInput.trim() || savingProfile) return;
    setSavingProfile(true);
    setProfileSavedMsg(null);
    try {
      await updateProfilePreferences({ displayName: profileNameInput.trim() });
      setProfileSavedMsg('Account display name updated.');
    } finally {
      setSavingProfile(false);
    }
  };

  // Start Universal URL Scan (Async Job with Live Polling)
  const handleStartUrlScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (urlScanning) return;
    setUrlError(null);
    setUrlJob(null);

    if (!targetUrl.trim()) {
      setUrlError('Enter a target URL (e.g., https://example.com).');
      return;
    }
    if (!urlAuthorized) {
      setUrlError('You must attest that you own or have explicit authorization to audit this target.');
      return;
    }

    setUrlScanning(true);
    try {
      const startRes = await fetch('/api/v2/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          maxPages,
          maxDepth,
          scope: crawlScope,
          authorizedAttestation: true,
          userId: currentUser?.uid || 'anonymous',
          async: true
        })
      });

      const startData = await startRes.json();
      if (!startRes.ok) {
        throw new Error(startData.error || 'Failed to queue URL scan.');
      }

      const jobId = startData.jobId as string;
      let finished = false;
      while (!finished) {
        await new Promise((r) => setTimeout(r, 600));
        const jobRes = await fetch(`/api/v2/scan/jobs/${encodeURIComponent(jobId)}`);
        const jobData = (await jobRes.json()) as V2ScanJob;
        setUrlJob(jobData);

        if (jobData.status === 'completed' && jobData.result) {
          finished = true;
          await persistV2Scan(jobData.result);
          refreshAuditAndAgents();
          setSelectedScan(jobData.result);
          setActiveTab('result');
        } else if (jobData.status === 'failed') {
          finished = true;
          throw new Error(jobData.error || 'Universal scan failed.');
        }
      }
    } catch (err: unknown) {
      setUrlError(err instanceof Error ? err.message : 'Scan execution error.');
      refreshAuditAndAgents();
    } finally {
      setUrlScanning(false);
    }
  };

  // Upload & Analyze ZIP Archive
  const handleStartZipScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (zipUploading) return;
    setZipError(null);
    if (!zipFile) {
      setZipError('Select a .zip source archive first.');
      return;
    }
    if (!zipAuthorized) {
      setZipError('Confirm authorization before analyzing archive contents.');
      return;
    }

    setZipUploading(true);
    try {
      const formData = new FormData();
      formData.append('archive', zipFile);
      formData.append('authorizedAttestation', 'true');
      formData.append('userId', currentUser?.uid || 'anonymous');

      const res = await fetch('/api/v2/scan/zip', {
        method: 'POST',
        body: formData
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'ZIP analysis failed.');
      }

      const result = data as V2ScanResult;
      await persistV2Scan(result);
      refreshAuditAndAgents();
      setSelectedScan(result);
      setActiveTab('result');
      setZipFile(null);
    } catch (err: unknown) {
      setZipError(err instanceof Error ? err.message : 'Failed to analyze archive.');
      refreshAuditAndAgents();
    } finally {
      setZipUploading(false);
    }
  };

  // Real persisted metrics calculation
  const metrics = useMemo(() => {
    const totalScans = scans.length;
    const secureScans = scans.filter((s) => s.score >= 80).length;
    const warningScans = scans.filter((s) => s.score >= 50 && s.score < 80).length;
    const criticalScans = scans.filter((s) => s.score < 50).length;
    const avgScore =
      totalScans > 0 ? Math.round(scans.reduce((acc, s) => acc + s.score, 0) / totalScans) : null;

    let criticalFindings = 0;
    let highFindings = 0;
    let mediumFindings = 0;
    let lowFindings = 0;
    for (const s of scans) {
      criticalFindings += s.summary?.critical || 0;
      highFindings += s.summary?.high || 0;
      mediumFindings += s.summary?.medium || 0;
      lowFindings += s.summary?.low || 0;
    }

    const activeAgents = agents.filter((a) => a.status === 'active' || a.status === 'registered').length;
    const revokedAgents = agents.filter((a) => a.status === 'revoked').length;

    return {
      totalScans,
      secureScans,
      warningScans,
      criticalScans,
      avgScore,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      activeAgents,
      revokedAgents,
      latestScan: scans[0] || null
    };
  }, [scans, agents]);

  const showOnboarding =
    forceShowGuide ||
    (currentUser ? userProfile?.onboardingCompleted === false : !guestOnboardingDismissed);

  const navItems: Array<{ id: V2Tab; label: string; icon: React.ReactNode }> = [
    { id: 'dashboard', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'url-scan', label: 'URL Crawler', icon: <Globe className="w-4 h-4" /> },
    { id: 'zip-scan', label: 'ZIP Analyzer', icon: <FileArchive className="w-4 h-4" /> },
    { id: 'agents', label: 'Server Agents', icon: <Server className="w-4 h-4" /> },
    { id: 'history', label: 'History & Audit', icon: <History className="w-4 h-4" /> },
    { id: 'settings', label: 'Account & Settings', icon: <Settings className="w-4 h-4" /> }
  ];

  const filteredScans = scans.filter((s) => {
    if (modeFilter !== 'all' && s.mode !== modeFilter) return false;
    if (healthFilter === 'secure' && s.score < 80) return false;
    if (healthFilter === 'warning' && (s.score < 50 || s.score >= 80)) return false;
    if (healthFilter === 'critical' && s.score >= 50) return false;
    if (historySearch.trim()) {
      const q = historySearch.toLowerCase();
      return s.target.toLowerCase().includes(q) || s.grade.toLowerCase().includes(q);
    }
    return true;
  });

  const displayName = userProfile?.displayName || currentUser?.displayName || currentUser?.email?.split('@')[0];

  const selectTab = (tab: V2Tab) => {
    setActiveTab(tab);
    setMobileMenuOpen(false);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col overflow-x-hidden">
      {/* Top Workspace Header */}
      <header className="h-16 border-b border-slate-800 bg-slate-950 px-3 sm:px-6 flex items-center justify-between gap-2 sm:gap-4 sticky top-0 z-30">
        <div className="flex items-center gap-2 sm:gap-3 min-w-0">
          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            className="lg:hidden min-h-[44px] min-w-[44px] inline-flex items-center justify-center rounded-lg text-slate-300 hover:text-white hover:bg-slate-900 border border-slate-800 transition-colors shrink-0"
            aria-label={mobileMenuOpen ? 'Close workspace menu' : 'Open workspace menu'}
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
          <Shield className="w-5 h-5 text-sky-400 shrink-0" />
          <span className="text-sm sm:text-base font-bold tracking-tight text-white whitespace-nowrap truncate">
            Site Sentinel V2
          </span>
        </div>

        <nav className="hidden lg:flex items-center gap-6 text-xs font-medium text-slate-400">
          <button
            type="button"
            onClick={() => selectTab('url-scan')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            URL Scan
          </button>
          <button
            type="button"
            onClick={() => selectTab('zip-scan')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            ZIP Audit
          </button>
          <button
            type="button"
            onClick={() => selectTab('agents')}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Agents
          </button>
          <button
            type="button"
            onClick={onSwitchToV1}
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Switch to V1 (WordPress)
          </button>
        </nav>

        <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
          {currentUser ? (
            <div className="flex items-center gap-1.5 sm:gap-3">
              <button
                type="button"
                onClick={() => selectTab('settings')}
                className="min-h-[40px] flex items-center gap-2 px-2.5 sm:px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-200 transition-colors"
                title="View Registered Account Details"
              >
                <UserCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="font-medium truncate max-w-[84px] sm:max-w-[140px]">{displayName}</span>
                <span className="hidden md:inline text-slate-500 font-mono truncate max-w-[140px]">
                  · {currentUser.email}
                </span>
              </button>
              <button
                type="button"
                onClick={() => logout()}
                className="min-h-[40px] inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-rose-400 rounded-lg transition-colors whitespace-nowrap shrink-0"
                title="Sign Out"
                aria-label="Sign Out"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 sm:gap-2.5">
              <span className="hidden xl:inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded-lg text-[11px] text-amber-300">
                <UserX className="w-3.5 h-3.5" />
                Guest (Browser-Only)
              </span>
              <button
                type="button"
                onClick={() => onOpenAuth('signin')}
                className="min-h-[40px] px-2.5 sm:px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => onOpenAuth('signup')}
                className="min-h-[40px] px-2.5 sm:px-3.5 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shrink-0"
              >
                <span className="sm:hidden">Join</span>
                <span className="hidden sm:inline">Create Account</span>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Collapsible Mobile Workspace Drawer (< lg) */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-b border-slate-800 bg-slate-900/95 px-4 py-3 space-y-1.5 animate-in fade-in slide-in-from-top-2 duration-150">
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => selectTab(item.id)}
              className={`w-full min-h-[44px] flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                activeTab === item.id || (activeTab === 'result' && item.id === 'history')
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
          <div className="pt-2 mt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onSwitchToV1();
              }}
              className="w-full min-h-[44px] text-left px-3 py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-medium text-sky-400 transition-colors"
            >
              Switch to WP Sentinel V1 →
            </button>
          </div>
        </div>
      )}

      {/* Session Expiry / Disabled Notice */}
      {sessionNotice && (
        <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 sm:px-6 py-2.5 text-xs text-amber-200 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 min-w-0">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span className="break-words">{sessionNotice}</span>
          </div>
          <button
            type="button"
            onClick={clearSessionNotice}
            className="text-amber-300 hover:text-white p-1.5 min-h-[36px] min-w-[36px] flex items-center justify-center shrink-0"
            aria-label="Dismiss notice"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="flex-1 flex flex-col lg:flex-row max-w-[1440px] w-full mx-auto">
        {/* Desktop Left Sidebar */}
        <aside className="hidden lg:block w-60 border-r border-slate-800 p-4 shrink-0">
          <div className="flex flex-col gap-1">
            {navItems.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => selectTab(item.id)}
                className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === item.id || (activeTab === 'result' && item.id === 'history')
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </button>
            ))}
          </div>

          <div className="mt-8 pt-6 border-t border-slate-800 space-y-2 text-xs">
            <div className="text-slate-400 font-medium">WP Sentinel V1</div>
            <button
              type="button"
              onClick={onSwitchToV1}
              className="w-full text-left px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-300 transition-colors"
            >
              Open WP Sentinel V1 →
            </button>
          </div>
        </aside>

        {/* Main Viewport */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 min-w-0 space-y-6 sm:space-y-8">
          {/* OVERVIEW DASHBOARD */}
          {activeTab === 'dashboard' && (
            <div className="space-y-8">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h1 className="text-2xl font-bold text-white tracking-tight">
                    Security Posture Overview
                  </h1>
                  <p className="text-xs text-slate-400 mt-1">
                    {currentUser
                      ? `Signed in as ${displayName} (${currentUser.email}). Showing only your account’s persisted audits.`
                      : 'Guest mode: results are saved locally in this browser. Sign in to sync across devices.'}
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2.5">
                  {!showOnboarding && (
                    <button
                      onClick={() => setForceShowGuide(true)}
                      className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs rounded-lg transition-colors whitespace-nowrap"
                    >
                      <HelpCircle className="w-3.5 h-3.5 text-sky-400" />
                      Show Guide
                    </button>
                  )}
                  <button
                    onClick={() => setActiveTab('url-scan')}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
                  >
                    New URL Scan
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setActiveTab('zip-scan')}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white font-medium text-xs rounded-lg transition-colors whitespace-nowrap"
                  >
                    Upload ZIP
                  </button>
                </div>
              </div>

              {/* Skippable Onboarding Banner */}
              {showOnboarding && (
                <V2OnboardingBanner
                  onStartUrlScan={() => setActiveTab('url-scan')}
                  onStartZipScan={() => setActiveTab('zip-scan')}
                  onStartAgentSetup={() => setActiveTab('agents')}
                  onDismiss={handleDismissOnboarding}
                />
              )}

              {/* Primary KPI Strip */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                  <div className="text-xs text-slate-400">Total V2 Scans</div>
                  <div className="text-2xl font-bold font-mono tabular-nums text-white">
                    {metrics.totalScans}
                  </div>
                  <div className="flex items-center gap-3 text-[11px] font-mono tabular-nums">
                    <span className="text-emerald-400">{metrics.secureScans} Secure</span>
                    <span className="text-amber-400">{metrics.warningScans} Warn</span>
                    <span className="text-rose-400">{metrics.criticalScans} Crit</span>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                  <div className="text-xs text-slate-400">Average Score</div>
                  <div className="text-2xl font-bold font-mono tabular-nums text-white">
                    {metrics.avgScore !== null ? `${metrics.avgScore}/100` : '—'}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {metrics.avgScore === null
                      ? 'Run your first scan to calculate score'
                      : metrics.avgScore >= 80
                        ? 'Healthy overall security baseline'
                        : metrics.avgScore >= 50
                          ? 'Moderate risk — review warnings'
                          : 'High risk — critical fixes needed'}
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                  <div className="text-xs text-slate-400">Open Findings by Severity</div>
                  <div className="grid grid-cols-4 gap-1.5 pt-0.5 text-center font-mono tabular-nums">
                    <div>
                      <div className="text-base font-bold text-rose-400">{metrics.criticalFindings}</div>
                      <div className="text-[10px] text-slate-500">CRIT</div>
                    </div>
                    <div>
                      <div className="text-base font-bold text-orange-400">{metrics.highFindings}</div>
                      <div className="text-[10px] text-slate-500">HIGH</div>
                    </div>
                    <div>
                      <div className="text-base font-bold text-amber-400">{metrics.mediumFindings}</div>
                      <div className="text-[10px] text-slate-500">MED</div>
                    </div>
                    <div>
                      <div className="text-base font-bold text-sky-400">{metrics.lowFindings}</div>
                      <div className="text-[10px] text-slate-500">LOW</div>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
                  <div className="text-xs text-slate-400">Server Agents & Sites</div>
                  <div className="text-2xl font-bold font-mono tabular-nums text-white">
                    {metrics.activeAgents} Active
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                    {metrics.revokedAgents} revoked · {monitoredSites.length} monitored sites
                  </div>
                </div>
              </div>

              {/* Latest Scan Status Panel */}
              {metrics.latestScan && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1 min-w-0">
                    <div className="text-xs text-slate-400">Latest Scan Result</div>
                    <div className="text-base font-semibold text-white break-all">
                      {metrics.latestScan.target}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono tabular-nums">
                      <span className="uppercase text-slate-200">{metrics.latestScan.mode}</span>
                      <span>·</span>
                      <span
                        className={
                          metrics.latestScan.score >= 80
                            ? 'text-emerald-400 font-semibold'
                            : metrics.latestScan.score >= 50
                              ? 'text-amber-400 font-semibold'
                              : 'text-rose-400 font-semibold'
                        }
                      >
                        {metrics.latestScan.score}/100 ({metrics.latestScan.grade})
                      </span>
                      <span>·</span>
                      <span>{metrics.latestScan.findings.length} findings</span>
                      {metrics.latestScan.coverage && (
                        <>
                          <span>·</span>
                          <span className="text-sky-300">
                            {metrics.latestScan.coverage.executedChecks}/{metrics.latestScan.coverage.totalChecks} checks
                          </span>
                        </>
                      )}
                      <span>·</span>
                      <span>{new Date(metrics.latestScan.createdAt).toLocaleString()}</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedScan(metrics.latestScan);
                        setActiveTab('result');
                      }}
                      className="min-h-[40px] px-3.5 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
                    >
                      Inspect Findings
                    </button>
                    <button
                      type="button"
                      onClick={() => exportV2PdfReport(metrics.latestScan!)}
                      className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors whitespace-nowrap"
                    >
                      <Download className="w-3.5 h-3.5" />
                      PDF Report
                    </button>
                    {scans.length >= 2 && (
                      <button
                        type="button"
                        onClick={() => {
                          setCompareTargetScanId(metrics.latestScan!.id);
                          setCompareOpen(true);
                        }}
                        className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-medium text-xs rounded-lg transition-colors whitespace-nowrap"
                      >
                        <Scale className="w-3.5 h-3.5 text-sky-400" />
                        Compare
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* Monitored Sites Read-Only Summary (from V1 sites collection when signed in) */}
              {currentUser && monitoredSites.length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-white">
                      Your Monitored Websites ({monitoredSites.length})
                    </h2>
                    <button
                      onClick={onSwitchToV1}
                      className="text-xs text-sky-400 hover:text-sky-300"
                    >
                      Manage in WP Sentinel V1 →
                    </button>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {monitoredSites.slice(0, 6).map((site) => (
                      <div
                        key={site.id}
                        className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between gap-2 text-xs"
                      >
                        <div className="min-w-0">
                          <div className="font-medium text-white truncate">{site.hostname}</div>
                          <div className="text-[11px] text-slate-400 font-mono">
                            {site.lastScore !== undefined
                              ? `Latest: ${site.lastScore}/100 (${site.lastGrade || '—'})`
                              : 'Not scanned yet'}
                          </div>
                        </div>
                        <button
                          onClick={() => {
                            setTargetUrl(site.url);
                            setActiveTab('url-scan');
                          }}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] shrink-0"
                        >
                          V2 Scan
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Mode Launchers */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <button
                  onClick={() => setActiveTab('url-scan')}
                  className="text-left bg-slate-900 hover:bg-slate-800/80 border border-slate-800 rounded-xl p-5 transition-colors space-y-2"
                >
                  <Globe className="w-5 h-5 text-sky-400" />
                  <div className="text-sm font-semibold text-white">Universal URL Crawler</div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Inspect robots.txt, sitemaps, internal pages, JS/CSS/doc assets, TLS certs, cookies, and multi-stack exposures.
                  </p>
                </button>
                <button
                  onClick={() => setActiveTab('zip-scan')}
                  className="text-left bg-slate-900 hover:bg-slate-800/80 border border-slate-800 rounded-xl p-5 transition-colors space-y-2"
                >
                  <FileArchive className="w-5 h-5 text-sky-400" />
                  <div className="text-sm font-semibold text-white">ZIP Project Analyzer</div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Static SAST, secret redaction, and dependency CVE checks across npm, pip, composer, maven, Go, and .NET.
                  </p>
                </button>
                <button
                  onClick={() => setActiveTab('agents')}
                  className="text-left bg-slate-900 hover:bg-slate-800/80 border border-slate-800 rounded-xl p-5 transition-colors space-y-2"
                >
                  <Server className="w-5 h-5 text-sky-400" />
                  <div className="text-sm font-semibold text-white">Authorized Server Agent</div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Deploy revocable read-only agents for host config permissions and runtime posture verification.
                  </p>
                </button>
              </div>

              {/* Recent Scans Table */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-white">Recent V2 Assessments</h2>
                  {scans.length > 0 && (
                    <button
                      onClick={() => setActiveTab('history')}
                      className="text-xs text-sky-400 hover:text-sky-300"
                    >
                      View all →
                    </button>
                  )}
                </div>
                {scans.length === 0 ? (
                  <div className="p-8 text-center space-y-3">
                    <Shield className="w-8 h-8 text-slate-600 mx-auto" />
                    <p className="text-sm font-medium text-white">No V2 audits yet</p>
                    <p className="text-xs text-slate-400 max-w-md mx-auto">
                      Start by scanning a website you own, uploading a zipped codebase, or connecting a read-only server agent.
                    </p>
                    <div className="flex flex-wrap items-center justify-center gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => setActiveTab('url-scan')}
                        className="min-h-[44px] px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
                      >
                        Run First URL Scan
                      </button>
                      <button
                        type="button"
                        onClick={() => setActiveTab('zip-scan')}
                        className="min-h-[44px] px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs rounded-lg transition-colors"
                      >
                        Analyze a ZIP Archive
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    {/* Mobile Stacked Cards (< md) */}
                    <div className="md:hidden divide-y divide-slate-800">
                      {scans.slice(0, 8).map((s) => (
                        <button
                          key={s.id}
                          type="button"
                          onClick={() => {
                            setSelectedScan(s);
                            setActiveTab('result');
                          }}
                          className="w-full text-left p-4 hover:bg-slate-800/40 transition-colors space-y-2"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <span className="text-xs font-medium text-white break-all">{s.target}</span>
                            <span className="text-xs font-mono tabular-nums font-semibold text-sky-400 shrink-0">
                              {s.score}/100 ({s.grade})
                            </span>
                          </div>
                          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono tabular-nums text-slate-400">
                            <span className="uppercase text-slate-300">{s.mode}</span>
                            <span>·</span>
                            <span>{s.findings.length} findings</span>
                            <span>·</span>
                            <span>{new Date(s.createdAt).toLocaleDateString()}</span>
                          </div>
                        </button>
                      ))}
                    </div>

                    {/* Desktop Table (>= md) */}
                    <div className="hidden md:block overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="px-5 py-2.5 font-medium">Target</th>
                            <th className="px-4 py-2.5 font-medium">Mode</th>
                            <th className="px-4 py-2.5 font-medium text-right">Findings</th>
                            <th className="px-4 py-2.5 font-medium text-right">Score</th>
                            <th className="px-5 py-2.5 font-medium text-right">Date</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {scans.slice(0, 8).map((s) => (
                            <tr
                              key={s.id}
                              onClick={() => {
                                setSelectedScan(s);
                                setActiveTab('result');
                              }}
                              className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                            >
                              <td className="px-5 py-3 font-medium text-white max-w-xs truncate">{s.target}</td>
                              <td className="px-4 py-3 font-mono uppercase text-slate-400">{s.mode}</td>
                              <td className="px-4 py-3 font-mono tabular-nums text-right text-slate-300">
                                {s.findings.length}
                              </td>
                              <td className="px-4 py-3 font-mono tabular-nums text-right font-semibold text-sky-400">
                                {s.score}/100 ({s.grade})
                              </td>
                              <td className="px-5 py-3 font-mono tabular-nums text-right text-slate-400">
                                {new Date(s.createdAt).toLocaleDateString()}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {/* UNIVERSAL URL SCANNER */}
          {activeTab === 'url-scan' && (
            <div className="max-w-3xl space-y-6">
              <div>
                <h1 className="text-xl font-bold text-white">Universal URL Scanner & Crawler</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Safely crawls public web pages with SSRF IP pinning, TLS certificate validation, cookie flag checks, and multi-framework exposure checks.
                </p>
              </div>

              <form onSubmit={handleStartUrlScan} className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
                <div className="space-y-2">
                  <label className="block text-xs font-medium text-slate-200">Target Root URL</label>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://example.com"
                    disabled={urlScanning}
                    className="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white font-mono placeholder-slate-600 focus:outline-none focus:border-sky-500"
                  />
                  <p className="text-[11px] text-slate-400">
                    Public websites only. Loopback, private network, and cloud metadata IPs are automatically blocked.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-300">Crawl Scope</label>
                    <select
                      value={crawlScope}
                      onChange={(e) => setCrawlScope(e.target.value as 'same-origin' | 'include-subdomains')}
                      disabled={urlScanning}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
                    >
                      <option value="same-origin">Same Origin Only</option>
                      <option value="include-subdomains">Include Subdomains</option>
                    </select>
                    <p className="text-[11px] text-slate-500">Limits crawling strictly to domains you control.</p>
                  </div>
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-300">Max Pages (1–25)</label>
                    <input
                      type="number"
                      min={1}
                      max={25}
                      value={maxPages}
                      onChange={(e) => setMaxPages(Number(e.target.value))}
                      disabled={urlScanning}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono focus:outline-none focus:border-sky-500"
                    />
                    <p className="text-[11px] text-slate-500">Caps requests so small servers stay fast.</p>
                  </div>
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-slate-300">Max Crawl Depth (1–3)</label>
                    <input
                      type="number"
                      min={1}
                      max={3}
                      value={maxDepth}
                      onChange={(e) => setMaxDepth(Number(e.target.value))}
                      disabled={urlScanning}
                      className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono focus:outline-none focus:border-sky-500"
                    />
                    <p className="text-[11px] text-slate-500">Link levels followed from homepage.</p>
                  </div>
                </div>

                <label className="flex items-start gap-2.5 p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={urlAuthorized}
                    onChange={(e) => setUrlAuthorized(e.target.checked)}
                    disabled={urlScanning}
                    className="mt-0.5 rounded border-slate-700 bg-slate-950 text-sky-500"
                  />
                  <span>
                    <strong className="text-white block mb-0.5">Authorization Required</strong>
                    I confirm that I own this target or have explicit permission to run passive crawling and security checks. This attestation is recorded in the audit log.
                  </span>
                </label>

                {urlError && (
                  <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 space-y-1">
                    <div className="flex items-center gap-2 font-medium">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>{urlError}</span>
                    </div>
                    <p className="text-rose-200/80 pl-6">{getScanErrorHint(urlError)}</p>
                  </div>
                )}

                {urlScanning && urlJob && (
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-sky-400 font-medium">{urlJob.stage}</span>
                      <span className="font-mono tabular-nums text-slate-300">
                        {urlJob.progress}% · {urlJob.pagesCrawled} pages
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-sky-500 transition-all duration-300"
                        style={{ width: `${urlJob.progress}%` }}
                      />
                    </div>
                  </div>
                )}

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={urlScanning}
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors disabled:opacity-50"
                  >
                    {urlScanning && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    {urlScanning ? 'Crawling & Auditing...' : 'Start Universal Scan'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* ZIP PROJECT ANALYZER */}
          {activeTab === 'zip-scan' && (
            <div className="max-w-3xl space-y-6">
              <div>
                <h1 className="text-xl font-bold text-white">Hardened ZIP Project Analyzer</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Inspects zipped source code strictly in memory without executing scripts or installing packages. Protects against ZIP bombs, path traversal, and symlinks.
                </p>
              </div>

              <form onSubmit={handleStartZipScan} className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
                <div className="border border-dashed border-slate-700 rounded-xl p-8 text-center space-y-3 bg-slate-950/60">
                  <Upload className="w-7 h-7 text-sky-400 mx-auto" />
                  <div className="text-xs text-slate-300">
                    {zipFile ? (
                      <span className="font-mono text-white">
                        {zipFile.name} ({(zipFile.size / 1024).toFixed(1)} KB)
                      </span>
                    ) : (
                      'Choose a .zip project archive (max 15 MB compressed / 60 MB extracted)'
                    )}
                  </div>
                  <label className="inline-block px-4 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium text-white rounded-lg cursor-pointer transition-colors">
                    Select ZIP Archive
                    <input
                      type="file"
                      accept=".zip,application/zip"
                      onChange={(e) => setZipFile(e.target.files?.[0] || null)}
                      disabled={zipUploading}
                      className="hidden"
                    />
                  </label>
                </div>

                <label className="flex items-start gap-2.5 p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={zipAuthorized}
                    onChange={(e) => setZipAuthorized(e.target.checked)}
                    disabled={zipUploading}
                    className="mt-0.5 rounded border-slate-700 bg-slate-950 text-sky-500"
                  />
                  <span>
                    <strong className="text-white block mb-0.5">Authorization Required</strong>
                    I confirm I am authorized to upload and statically inspect this source archive. Detected secret values are automatically masked in reports.
                  </span>
                </label>

                {zipError && (
                  <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-300 space-y-1">
                    <div className="flex items-center gap-2 font-medium">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>{zipError}</span>
                    </div>
                    <p className="text-rose-200/80 pl-6">{getScanErrorHint(zipError)}</p>
                  </div>
                )}

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={zipUploading || !zipFile}
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors disabled:opacity-50"
                  >
                    {zipUploading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    {zipUploading ? 'Analyzing Archive...' : 'Analyze ZIP Archive'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* SERVER AGENTS */}
          {activeTab === 'agents' && (
            <V2AgentPanel
              userId={currentUser?.uid}
              onSelectReport={(rep) => {
                setSelectedScan(rep);
                setActiveTab('result');
              }}
              onSyncAgentToFirestore={syncAgentToFirestore}
              onSyncReportToFirestore={persistV2Scan}
              onAgentsChanged={setAgents}
            />
          )}

          {/* HISTORY & AUDIT LOGS */}
          {activeTab === 'history' && (
            <div className="space-y-8">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <h1 className="text-xl font-bold text-white">Scan History & Audit Trail</h1>
                  <p className="text-xs text-slate-400 mt-1">
                    Filter past URL crawls, ZIP static analyses, agent reports, and compare changes over time.
                  </p>
                </div>

                <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2 w-full lg:w-auto">
                  {scans.length >= 2 && (
                    <button
                      type="button"
                      onClick={() => {
                        setCompareTargetScanId(scans[0]?.id);
                        setCompareOpen(true);
                      }}
                      className="min-h-[40px] inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
                    >
                      <Scale className="w-3.5 h-3.5" />
                      Compare Scans
                    </button>
                  )}

                  <div className="relative w-full sm:w-44">
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={historySearch}
                      onChange={(e) => setHistorySearch(e.target.value)}
                      placeholder="Search target..."
                      aria-label="Search scan history"
                      className="w-full min-h-[40px] pl-8 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <select
                    value={healthFilter}
                    onChange={(e) => setHealthFilter(e.target.value as 'all' | 'secure' | 'warning' | 'critical')}
                    aria-label="Filter by score health"
                    className="w-full sm:w-auto min-h-[40px] px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                  >
                    <option value="all">All Scores</option>
                    <option value="secure">Secure (80+)</option>
                    <option value="warning">Warning (50–79)</option>
                    <option value="critical">Critical (&lt;50)</option>
                  </select>

                  <div className="grid grid-cols-4 sm:flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg w-full sm:w-fit">
                    {(['all', 'url', 'zip', 'agent'] as const).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setModeFilter(m)}
                        className={`min-h-[34px] px-2.5 sm:px-3 py-1 text-xs font-medium rounded-md uppercase transition-colors ${
                          modeFilter === m ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                {filteredScans.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-400">
                    No scans recorded under these filters.
                  </div>
                ) : (
                  <>
                    {/* Mobile Stacked History Cards (< md) */}
                    <div className="md:hidden divide-y divide-slate-800">
                      {filteredScans.map((s) => (
                        <div key={s.id} className="p-4 space-y-3">
                          <div className="flex items-start justify-between gap-3">
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedScan(s);
                                setActiveTab('result');
                              }}
                              className="text-left text-xs font-semibold text-white hover:text-sky-400 break-all"
                            >
                              {s.target}
                            </button>
                            <span className="text-xs font-mono tabular-nums text-sky-400 font-semibold shrink-0">
                              {s.score}/100 ({s.grade})
                            </span>
                          </div>
                          <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono tabular-nums text-slate-400">
                            <span className="uppercase text-slate-300">{s.mode}</span>
                            <span>·</span>
                            <span>{s.findings.length} findings</span>
                            <span>·</span>
                            <span>{new Date(s.createdAt).toLocaleString()}</span>
                          </div>
                          <div className="flex flex-wrap items-center gap-2 pt-1">
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedScan(s);
                                setActiveTab('result');
                              }}
                              className="min-h-[36px] px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-md"
                            >
                              Open
                            </button>
                            {scans.length >= 2 && (
                              <button
                                type="button"
                                onClick={() => {
                                  setCompareTargetScanId(s.id);
                                  setCompareOpen(true);
                                }}
                                className="min-h-[36px] px-3 py-1.5 bg-slate-800/70 hover:bg-slate-700 text-slate-300 hover:text-sky-400 text-xs rounded-md inline-flex items-center gap-1"
                              >
                                <Scale className="w-3.5 h-3.5" />
                                Compare
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => exportV2PdfReport(s)}
                              className="min-h-[36px] px-3 py-1.5 bg-slate-800/70 hover:bg-slate-700 text-slate-300 hover:text-white text-xs rounded-md inline-flex items-center gap-1"
                            >
                              <Download className="w-3.5 h-3.5" />
                              PDF
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteScan(s.id)}
                              className="min-h-[36px] px-2.5 py-1.5 text-rose-400 hover:bg-rose-500/10 rounded-md inline-flex items-center gap-1 text-xs ml-auto"
                              aria-label={`Delete scan ${s.target}`}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Desktop History Table (>= md) */}
                    <div className="hidden md:block overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="px-5 py-2.5 font-medium">Target</th>
                            <th className="px-4 py-2.5 font-medium">Mode</th>
                            <th className="px-4 py-2.5 font-medium text-right">Findings</th>
                            <th className="px-4 py-2.5 font-medium text-right">Score</th>
                            <th className="px-4 py-2.5 font-medium text-right">Date</th>
                            <th className="px-5 py-2.5 font-medium text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {filteredScans.map((s) => (
                            <tr key={s.id} className="hover:bg-slate-800/30">
                              <td
                                onClick={() => {
                                  setSelectedScan(s);
                                  setActiveTab('result');
                                }}
                                className="px-5 py-3 font-medium text-white max-w-xs truncate cursor-pointer hover:text-sky-400"
                              >
                                {s.target}
                              </td>
                              <td className="px-4 py-3 font-mono uppercase text-slate-400">{s.mode}</td>
                              <td className="px-4 py-3 font-mono tabular-nums text-right text-slate-300">
                                {s.findings.length}
                              </td>
                              <td className="px-4 py-3 font-mono tabular-nums text-right text-sky-400 font-semibold">
                                {s.score}/100 ({s.grade})
                              </td>
                              <td className="px-4 py-3 font-mono tabular-nums text-right text-slate-400">
                                {new Date(s.createdAt).toLocaleString()}
                              </td>
                              <td className="px-5 py-3 text-right space-x-2 whitespace-nowrap">
                                <button
                                  type="button"
                                  onClick={() => {
                                    setSelectedScan(s);
                                    setActiveTab('result');
                                  }}
                                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md"
                                >
                                  Open
                                </button>
                                {scans.length >= 2 && (
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setCompareTargetScanId(s.id);
                                      setCompareOpen(true);
                                    }}
                                    className="p-1.5 text-slate-400 hover:text-sky-400 inline-flex"
                                    title="Compare Scan"
                                  >
                                    <Scale className="w-3.5 h-3.5" />
                                  </button>
                                )}
                                <button
                                  type="button"
                                  onClick={() => exportV2PdfReport(s)}
                                  className="p-1.5 text-slate-400 hover:text-white inline-flex"
                                  title="Export PDF"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteScan(s.id)}
                                  className="p-1.5 text-slate-400 hover:text-rose-400 inline-flex"
                                  title="Delete Scan"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </div>

              {/* Security Audit Trail */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-white">
                  <FileText className="w-4 h-4 text-sky-400" />
                  Server Security Audit Log ({auditLogs.length})
                </div>
                {auditLogs.length === 0 ? (
                  <p className="p-6 text-xs text-slate-400">No audit events logged under this account yet.</p>
                ) : (
                  <>
                    {/* Mobile Stacked Audit Cards (< md) */}
                    <div className="md:hidden divide-y divide-slate-800">
                      {auditLogs.slice(0, 25).map((log) => (
                        <div key={log.id} className="p-4 space-y-1.5 text-xs">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-slate-200 break-all">{log.action}</span>
                            <span
                              className={`font-medium capitalize shrink-0 ${
                                log.status === 'blocked'
                                  ? 'text-rose-400'
                                  : log.status === 'completed'
                                    ? 'text-emerald-400'
                                    : 'text-amber-400'
                              }`}
                            >
                              {log.status}
                            </span>
                          </div>
                          <div className="text-slate-300 font-mono text-[11px] break-all">{log.target}</div>
                          <div className="flex items-center justify-between gap-2 text-[11px] text-slate-400">
                            <span className="break-words">{log.detail}</span>
                            <span className="font-mono tabular-nums shrink-0 text-slate-500">
                              {new Date(log.createdAt).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Desktop Audit Table (>= md) */}
                    <div className="hidden md:block overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="px-5 py-2.5 font-medium">Action</th>
                            <th className="px-4 py-2.5 font-medium">Target</th>
                            <th className="px-4 py-2.5 font-medium">Status</th>
                            <th className="px-4 py-2.5 font-medium">Detail</th>
                            <th className="px-5 py-2.5 font-medium text-right">Timestamp</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {auditLogs.slice(0, 25).map((log) => (
                            <tr key={log.id}>
                              <td className="px-5 py-2.5 font-mono text-slate-200">{log.action}</td>
                              <td className="px-4 py-2.5 text-slate-300 max-w-[180px] truncate">{log.target}</td>
                              <td
                                className={`px-4 py-2.5 font-medium capitalize ${
                                  log.status === 'blocked'
                                    ? 'text-rose-400'
                                    : log.status === 'completed'
                                      ? 'text-emerald-400'
                                      : 'text-amber-400'
                                }`}
                              >
                                {log.status}
                              </td>
                              <td className="px-4 py-2.5 text-slate-400 max-w-xs truncate">{log.detail}</td>
                              <td className="px-5 py-2.5 font-mono tabular-nums text-right text-slate-500">
                                {new Date(log.createdAt).toLocaleTimeString()}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {/* SELECTED SCAN RESULT */}
          {activeTab === 'result' && selectedScan && (
            <V2ScanResults
              scan={selectedScan}
              onBack={() => setActiveTab('history')}
              onUpdateFindingStatus={handleUpdateFindingStatus}
              onOpenCompare={(scan) => {
                setCompareTargetScanId(scan.id);
                setCompareOpen(true);
              }}
            />
          )}

          {/* ACCOUNT & SETTINGS */}
          {activeTab === 'settings' && (
            <div className="max-w-3xl space-y-6">
              <div>
                <h1 className="text-xl font-bold text-white">Account & Security Settings</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Manage your registered account details, onboarding guide, and V2 runtime boundaries.
                </p>
              </div>

              {/* Account Status & Profile */}
              {currentUser ? (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-10 h-10 rounded-xl bg-sky-500/20 border border-sky-500/30 flex items-center justify-center text-sky-400 font-bold shrink-0">
                        {(displayName || 'U')[0].toUpperCase()}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-white flex flex-wrap items-center gap-2">
                          <span className="break-words">{displayName}</span>
                          <span className="text-[11px] font-medium text-emerald-400">· Registered Account</span>
                        </div>
                        <div className="text-xs text-slate-400 font-mono break-all">{currentUser.email}</div>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => logout()}
                      className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs font-medium rounded-lg transition-colors self-start sm:self-auto shrink-0"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      Sign Out
                    </button>
                  </div>

                  <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                    <div className="min-w-0">
                      <dt className="text-slate-400">Firebase UID</dt>
                      <dd className="text-slate-200 font-mono mt-0.5 break-all" title={currentUser.uid}>
                        {currentUser.uid}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-400">Sign-In Method</dt>
                      <dd className="text-slate-200 mt-0.5 capitalize">
                        {userProfile?.authProvider === 'google.com' ? 'Google OAuth' : 'Email & Password'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-400">Member Since</dt>
                      <dd className="text-slate-200 font-mono mt-0.5">
                        {userProfile?.createdAt
                          ? new Date(userProfile.createdAt).toLocaleDateString()
                          : currentUser.metadata?.creationTime
                            ? new Date(currentUser.metadata.creationTime).toLocaleDateString()
                            : 'Active'}
                      </dd>
                    </div>
                  </dl>

                  <form onSubmit={handleSaveProfile} className="pt-4 border-t border-slate-800 space-y-3">
                    <label className="block text-xs font-medium text-slate-300">Display Name</label>
                    <div className="flex flex-col sm:flex-row gap-3">
                      <input
                        type="text"
                        value={profileNameInput}
                        onChange={(e) => setProfileNameInput(e.target.value)}
                        placeholder="Your name"
                        className="flex-1 px-3.5 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-sky-500"
                      />
                      <button
                        type="submit"
                        disabled={savingProfile || !profileNameInput.trim()}
                        className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap"
                      >
                        {savingProfile ? 'Saving...' : 'Save Name'}
                      </button>
                    </div>
                    {profileSavedMsg && (
                      <p className="text-xs text-emerald-400">{profileSavedMsg}</p>
                    )}
                  </form>

                  <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div className="text-slate-400">
                      <strong className="text-slate-200">Data Isolation:</strong> Your V2 scans, agents, and audit logs are stored separately from your WP Sentinel V1 records under your private Firebase UID.
                    </div>
                    <button
                      onClick={() => {
                        setForceShowGuide(true);
                        setActiveTab('dashboard');
                      }}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg whitespace-nowrap shrink-0"
                    >
                      Re-open Quick Start Guide
                    </button>
                  </div>
                </div>
              ) : (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-sm font-semibold text-white">Currently in Guest Mode (Unauthenticated)</div>
                    <p className="text-xs text-slate-400 max-w-xl">
                      Guest scans are stored temporarily in your browser only and are never shared with registered accounts. Sign in or create an account to save reports to Firestore across devices.
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => onOpenAuth('signin')}
                      className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded-lg"
                    >
                      Sign In
                    </button>
                    <button
                      onClick={() => onOpenAuth('signup')}
                      className="px-3.5 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 text-xs font-semibold rounded-lg"
                    >
                      Create Account
                    </button>
                  </div>
                </div>
              )}

              {/* Runtime Security Guarantees */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl divide-y divide-slate-800 text-xs">
                <div className="p-5 flex items-center justify-between gap-4">
                  <div>
                    <div className="font-semibold text-white">SSRF & DNS Rebinding Guard</div>
                    <div className="text-slate-400 mt-0.5">
                      Blocks RFC 1918, loopback, link-local, and cloud metadata IPs; pins sockets to validated DNS records.
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium shrink-0">
                    <CheckCircle2 className="w-4 h-4" />
                    Enforced
                  </span>
                </div>
                <div className="p-5 flex items-center justify-between gap-4">
                  <div>
                    <div className="font-semibold text-white">ZIP Sandbox & Archive Caps</div>
                    <div className="text-slate-400 mt-0.5">
                      15 MB compressed / 60 MB decompressed / 50:1 max ratio / 2,000 files; rejects path traversal and symlinks; zero code execution.
                    </div>
                  </div>
                  <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium shrink-0">
                    <CheckCircle2 className="w-4 h-4" />
                    Enforced
                  </span>
                </div>
                <div className="p-5 flex items-center justify-between gap-4">
                  <div>
                    <div className="font-semibold text-white">Gemini AI Remediation Layer</div>
                    <div className="text-slate-400 mt-0.5">
                      Optional server-side explanation service (GEMINI_API_KEY). Core scanning & scoring operate deterministically without it.
                    </div>
                  </div>
                  <span className={`font-medium shrink-0 ${geminiReady ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {geminiReady === null ? 'Checking...' : geminiReady ? 'Configured' : 'Key Not Set'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* V2 Scan-to-Scan Comparison Modal */}
      <V2ScanComparisonModal
        isOpen={compareOpen}
        onClose={() => setCompareOpen(false)}
        scans={scans}
        initialCompareId={compareTargetScanId}
      />
    </div>
  );
};
