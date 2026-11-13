import React, { useState, useEffect } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { Dashboard } from './components/Dashboard';
import { ScanResultsView } from './components/ScanResultsView';
import { SitesManagement } from './components/SitesManagement';
import { ScanComparisonModal } from './components/ScanComparisonModal';
import { AuthModal } from './components/AuthModal';
import { SettingsModal } from './components/SettingsModal';
import { V2Workspace } from './v2/components/V2Workspace';
import { ScanResult, MonitoredSite } from './types/scanner';
import { db, handleFirestoreError, OperationType } from './lib/firebase';
import {
  collection,
  doc,
  setDoc,
  deleteDoc,
  onSnapshot
} from 'firebase/firestore';

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

function MainApp() {
  const { currentUser, userProfile, sessionNotice, clearSessionNotice } = useAuth();

  const [platformVersion, setPlatformVersion] = useState<'v1' | 'v2'>(() => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      if (params.get('v') === '2' || window.location.hash === '#v2') return 'v2';
    }
    return 'v1';
  });

  const switchPlatformVersion = (ver: 'v1' | 'v2') => {
    setPlatformVersion(ver);
    if (typeof window !== 'undefined') {
      const url = new URL(window.location.href);
      url.searchParams.set('v', ver === 'v2' ? '2' : '1');
      window.history.replaceState({}, '', url.toString());
    }
  };

  const [currentView, setCurrentView] = useState<'scanner' | 'dashboard' | 'sites' | 'compare'>('scanner');
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [monitoredSites, setMonitoredSites] = useState<MonitoredSite[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Modals
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState<'signin' | 'signup'>('signin');
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);
  const [comparisonModalOpen, setComparisonModalOpen] = useState(false);
  const [compareScanA, setCompareScanA] = useState<ScanResult | undefined>(undefined);
  const [compareScanB, setCompareScanB] = useState<ScanResult | undefined>(undefined);

  // Sync Scans and Sites from Firestore when user is logged in
  useEffect(() => {
    setCurrentScan(null);
    if (!currentUser) {
      setMonitoredSites([]);
      // In guest mode, load any local cached scans
      const local = localStorage.getItem('wpsentinel_guest_scans');
      if (local) {
        try {
          setScans(JSON.parse(local));
        } catch {
          // Ignore
        }
      } else {
        setScans([]);
      }
      return;
    }

    // 1. Scans Listener
    const scansPath = `users/${currentUser.uid}/scans`;
    const scansColRef = collection(db, 'users', currentUser.uid, 'scans');
    const unsubScans = onSnapshot(
      scansColRef,
      (snapshot) => {
        const loaded: ScanResult[] = [];
        snapshot.forEach((d) => {
          loaded.push(d.data() as ScanResult);
        });
        // Sort descending by timestamp
        loaded.sort((a, b) => new Date(b.scanTimestamp).getTime() - new Date(a.scanTimestamp).getTime());
        setScans(loaded);
      },
      (error) => {
        handleFirestoreError(error, OperationType.LIST, scansPath);
      }
    );

    // 2. Monitored Sites Listener
    const sitesPath = `users/${currentUser.uid}/sites`;
    const sitesColRef = collection(db, 'users', currentUser.uid, 'sites');
    const unsubSites = onSnapshot(
      sitesColRef,
      (snapshot) => {
        const loadedSites: MonitoredSite[] = [];
        snapshot.forEach((d) => {
          loadedSites.push(d.data() as MonitoredSite);
        });
        setMonitoredSites(loadedSites);
      },
      (error) => {
        handleFirestoreError(error, OperationType.LIST, sitesPath);
      }
    );

    return () => {
      unsubScans();
      unsubSites();
    };
  }, [currentUser]);

  // Execute Real WordPress Scan
  const handleStartScan = async (targetUrl: string) => {
    setScanning(true);
    setScanError(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl,
          userId: currentUser?.uid || 'anonymous',
          wpscanApiKey: userProfile?.wpscanApiKey
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Security scan failed.');
      }

      const scanResult = data as ScanResult;
      setCurrentScan(scanResult);
      setCurrentView('scanner');

      // Save to Firestore if authenticated
      if (currentUser) {
        const scanDocRef = doc(db, 'users', currentUser.uid, 'scans', scanResult.id);
        const firestoreScan = stripUndefined({
          ...scanResult,
          userId: currentUser.uid,
          createdAt: scanResult.createdAt || scanResult.scanTimestamp
        });
        try {
          await setDoc(scanDocRef, firestoreScan);
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, `users/${currentUser.uid}/scans/${scanResult.id}`);
        }
      } else {
        // Save to guest storage
        setScans((prev) => {
          const updated = [scanResult, ...prev.filter((s) => s.id !== scanResult.id)];
          localStorage.setItem('wpsentinel_guest_scans', JSON.stringify(updated.slice(0, 10)));
          return updated;
        });
      }

      // If domain is in monitored sites, update its last score
      const matchingSite = monitoredSites.find((s) => s.hostname === scanResult.hostname);
      if (matchingSite && currentUser) {
        try {
          await setDoc(
            doc(db, 'users', currentUser.uid, 'sites', matchingSite.id),
            stripUndefined({
              ...matchingSite,
              lastScore: scanResult.score,
              lastGrade: scanResult.grade,
              lastScannedAt: scanResult.scanTimestamp,
              scanCount: (matchingSite.scanCount || 0) + 1
            }),
            { merge: true }
          );
        } catch (err) {
          handleFirestoreError(err, OperationType.UPDATE, `users/${currentUser.uid}/sites/${matchingSite.id}`);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to complete security scan.';
      setScanError(msg);
    } finally {
      setScanning(false);
    }
  };

  // Delete Scan from Firestore or local state
  const handleDeleteScan = async (scanId: string) => {
    if (currentUser) {
      try {
        await deleteDoc(doc(db, 'users', currentUser.uid, 'scans', scanId));
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, `users/${currentUser.uid}/scans/${scanId}`);
      }
    } else {
      setScans((prev) => {
        const updated = prev.filter((s) => s.id !== scanId);
        localStorage.setItem('wpsentinel_guest_scans', JSON.stringify(updated));
        return updated;
      });
    }

    if (currentScan?.id === scanId) {
      setCurrentScan(null);
    }
  };

  // Add Monitored Site
  const handleAddSite = async (rawUrl: string) => {
    if (!currentUser) {
      setAuthModalMode('signin');
      setAuthModalOpen(true);
      return;
    }

    let url = rawUrl.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
    }
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const siteId = `site_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const verificationToken = `wpsentinel-verification-${Math.random().toString(36).substring(2, 12)}`;

    const newSite: MonitoredSite = {
      id: siteId,
      userId: currentUser.uid,
      url: `${parsed.protocol}//${parsed.host}`,
      hostname,
      verified: false,
      verificationToken,
      scanCount: 0,
      createdAt: new Date().toISOString()
    };

    try {
      await setDoc(doc(db, 'users', currentUser.uid, 'sites', siteId), newSite);
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, `users/${currentUser.uid}/sites/${siteId}`);
    }
  };

  // Verify Site Ownership
  const handleVerifySite = async (siteId: string, url: string, token: string) => {
    const res = await fetch('/api/verify-site', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: url, token })
    });
    const data = await res.json();

    if (data.verified && currentUser) {
      await setDoc(
        doc(db, 'users', currentUser.uid, 'sites', siteId),
        { verified: true },
        { merge: true }
      );
    }

    return data;
  };

  // Delete Monitored Site
  const handleDeleteSite = async (siteId: string) => {
    if (!currentUser) return;
    try {
      await deleteDoc(doc(db, 'users', currentUser.uid, 'sites', siteId));
    } catch (err) {
      handleFirestoreError(err, OperationType.DELETE, `users/${currentUser.uid}/sites/${siteId}`);
    }
  };

  const handleOpenCompare = (scanA?: ScanResult, scanB?: ScanResult) => {
    setCompareScanA(scanA);
    setCompareScanB(scanB);
    setComparisonModalOpen(true);
  };

  if (platformVersion === 'v2') {
    return (
      <>
        <V2Workspace
          onSwitchToV1={() => switchPlatformVersion('v1')}
          onOpenAuth={(mode = 'signin') => {
            setAuthModalMode(mode);
            setAuthModalOpen(true);
          }}
        />
        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          initialMode={authModalMode}
        />
      </>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans overflow-x-hidden">
      {/* Version Switcher Bar */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-4 sm:px-6 lg:px-8 py-2">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 text-slate-400">
            <span className="hidden sm:inline">Platform Edition:</span>
            <span className="font-semibold text-white">WP Sentinel V1</span>
            <span className="text-slate-500 hidden md:inline">· WordPress Auditor</span>
          </div>
          <button
            type="button"
            onClick={() => switchPlatformVersion('v2')}
            className="text-sky-400 hover:text-sky-300 font-medium transition-colors py-1 min-h-[36px] sm:min-h-0 flex items-center"
          >
            <span className="sm:hidden">Switch to V2 →</span>
            <span className="hidden sm:inline">Switch to Site Sentinel V2 (URL · ZIP · Agent) →</span>
          </button>
        </div>
      </div>

      {/* Top Navbar */}
      <Navbar
        currentView={currentView}
        setCurrentView={(view) => {
          setCurrentView(view);
          if (view === 'compare') {
            handleOpenCompare();
          }
        }}
        onOpenAuth={(mode = 'signin') => {
          setAuthModalMode(mode);
          setAuthModalOpen(true);
        }}
        onOpenSettings={() => setSettingsModalOpen(true)}
        onNewScan={() => {
          setCurrentScan(null);
          setCurrentView('scanner');
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
      />

      {/* Session Notice Banner */}
      {sessionNotice && (
        <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 sm:px-6 lg:px-8 py-2.5 text-xs text-amber-200">
          <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span>{sessionNotice}</span>
            </div>
            <button
              onClick={clearSessionNotice}
              className="text-amber-300 hover:text-white p-1"
              aria-label="Dismiss session notice"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* VIEW 1: Scanner (Landing or Results) */}
        {currentView === 'scanner' && (
          <>
            {currentScan ? (
              <div className="space-y-6">
                <button
                  onClick={() => setCurrentScan(null)}
                  className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
                >
                  ← Back to Audit Launcher
                </button>
                <ScanResultsView
                  scan={currentScan}
                  onRescan={(url) => handleStartScan(url)}
                  onSaveToSites={(scan) => handleAddSite(scan.targetUrl)}
                  onCompareWith={(scan) => handleOpenCompare(undefined, scan)}
                />
              </div>
            ) : (
              <LandingPage
                onStartScan={handleStartScan}
                scanning={scanning}
                scanError={scanError}
                onExploreDashboard={() => setCurrentView('dashboard')}
              />
            )}
          </>
        )}

        {/* VIEW 2: Dashboard */}
        {currentView === 'dashboard' && (
          <Dashboard
            scans={scans}
            monitoredSites={monitoredSites}
            onSelectScan={(scan) => {
              setCurrentScan(scan);
              setCurrentView('scanner');
            }}
            onDeleteScan={handleDeleteScan}
            onLaunchScan={handleStartScan}
            onOpenCompare={(scanA, scanB) => handleOpenCompare(scanA, scanB)}
            onNavigateToSites={() => setCurrentView('sites')}
            scanning={scanning}
          />
        )}

        {/* VIEW 3: Monitored Sites Fleet */}
        {currentView === 'sites' && (
          <SitesManagement
            sites={monitoredSites}
            onAddSite={handleAddSite}
            onVerifySite={handleVerifySite}
            onDeleteSite={handleDeleteSite}
            onRunAudit={handleStartScan}
            scanning={scanning}
          />
        )}

        {/* VIEW 4: Compare fallback container */}
        {currentView === 'compare' && (
          <Dashboard
            scans={scans}
            monitoredSites={monitoredSites}
            onSelectScan={(scan) => {
              setCurrentScan(scan);
              setCurrentView('scanner');
            }}
            onDeleteScan={handleDeleteScan}
            onLaunchScan={handleStartScan}
            onOpenCompare={(scanA, scanB) => handleOpenCompare(scanA, scanB)}
            onNavigateToSites={() => setCurrentView('sites')}
            scanning={scanning}
          />
        )}
      </main>

      {/* Modals */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        initialMode={authModalMode}
      />

      <SettingsModal
        isOpen={settingsModalOpen}
        onClose={() => setSettingsModalOpen(false)}
      />

      <ScanComparisonModal
        isOpen={comparisonModalOpen}
        onClose={() => setComparisonModalOpen(false)}
        scans={scans}
        initialScanA={compareScanA}
        initialScanB={compareScanB}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-slate-300 font-mono tracking-wider">WP SENTINEL</span>
            <span>—</span>
            <span>Passive Cybersecurity Intelligence & Vulnerability Auditor</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span>SSRF Filter Active</span>
            <span>•</span>
            <span>Zero-Disruption Passive Auditing</span>
            <span>•</span>
            <span>NIST & WPScan Sync</span>
          </div>
        </div>
      </footer>

    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
