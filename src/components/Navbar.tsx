import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  LayoutDashboard,
  Globe,
  Scale,
  Settings,
  LogOut,
  User,
  Menu,
  X,
  Plus
} from 'lucide-react';

interface NavbarProps {
  currentView: 'scanner' | 'dashboard' | 'sites' | 'compare';
  setCurrentView: (view: 'scanner' | 'dashboard' | 'sites' | 'compare') => void;
  onOpenAuth: (mode?: 'signin' | 'signup') => void;
  onOpenSettings: () => void;
  onNewScan: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentView,
  setCurrentView,
  onOpenAuth,
  onOpenSettings,
  onNewScan
}) => {
  const { currentUser, logout } = useAuth();
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setUserDropdownOpen(false);
        setMobileMenuOpen(false);
      }
    };
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setUserDropdownOpen(false);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const navigateMobile = (view: 'scanner' | 'dashboard' | 'sites' | 'compare') => {
    setCurrentView(view);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand Zone */}
        <div className="flex items-center gap-6 min-w-0">
          <button
            type="button"
            onClick={() => navigateMobile('scanner')}
            className="flex items-center gap-2.5 text-left group shrink-0 min-h-[44px]"
          >
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg group-hover:border-cyan-400 transition-colors">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <span className="font-extrabold text-base tracking-tight text-white group-hover:text-cyan-300 transition-colors whitespace-nowrap">
              WP SENTINEL
            </span>
          </button>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1" aria-label="Primary V1 navigation">
            <button
              type="button"
              onClick={() => setCurrentView('scanner')}
              className={`px-3.5 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                currentView === 'scanner'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900'
              }`}
            >
              Auditor
            </button>
            <button
              type="button"
              onClick={() => setCurrentView('dashboard')}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                currentView === 'dashboard'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              Dashboard
            </button>
            <button
              type="button"
              onClick={() => setCurrentView('sites')}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                currentView === 'sites'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              Sites
            </button>
            <button
              type="button"
              onClick={() => setCurrentView('compare')}
              className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                currentView === 'compare'
                  ? 'bg-slate-800 text-white font-semibold'
                  : 'text-slate-300 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Scale className="w-3.5 h-3.5" />
              Compare
            </button>
          </nav>
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onNewScan}
            className="hidden sm:inline-flex items-center gap-1.5 px-3.5 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            Quick Audit
          </button>

          {/* Desktop Auth Controls */}
          {currentUser ? (
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setUserDropdownOpen((prev) => !prev)}
                aria-expanded={userDropdownOpen}
                aria-haspopup="menu"
                className="flex items-center gap-2 px-2.5 py-1.5 min-h-[40px] bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs text-slate-200 transition-colors"
              >
                <div className="w-6 h-6 rounded-md bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-[11px] font-bold text-cyan-300 shrink-0">
                  {currentUser.email ? currentUser.email[0].toUpperCase() : 'U'}
                </div>
                <span className="max-w-[120px] truncate text-slate-200 font-medium hidden sm:inline">
                  {currentUser.displayName || currentUser.email?.split('@')[0]}
                </span>
              </button>

              {userDropdownOpen && (
                <div
                  role="menu"
                  className="absolute right-0 mt-2 w-60 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl py-1.5 text-xs z-50"
                >
                  <div className="px-3.5 py-2.5 border-b border-slate-800">
                    <p className="text-[11px] font-mono text-emerald-400 mb-0.5">
                      Registered Account
                    </p>
                    <p className="font-semibold text-white truncate">{currentUser.displayName || 'Auditor'}</p>
                    <p className="text-[11px] text-slate-400 truncate font-mono">{currentUser.email}</p>
                  </div>

                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setUserDropdownOpen(false);
                      onOpenSettings();
                    }}
                    className="w-full flex items-center gap-2.5 px-3.5 py-2.5 min-h-[44px] text-slate-200 hover:text-white hover:bg-slate-800 transition-colors text-left"
                  >
                    <Settings className="w-4 h-4 text-slate-400" />
                    Account &amp; API Settings
                  </button>

                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setUserDropdownOpen(false);
                      logout();
                    }}
                    className="w-full flex items-center gap-2.5 px-3.5 py-2.5 min-h-[44px] text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 transition-colors text-left border-t border-slate-800"
                  >
                    <LogOut className="w-4 h-4" />
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="hidden sm:flex items-center gap-2">
              <span className="hidden lg:inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded-lg text-[11px] text-amber-300 font-mono">
                <User className="w-3 h-3" />
                Guest Session
              </span>
              <button
                type="button"
                onClick={() => onOpenAuth('signin')}
                className="px-3 py-2 text-xs font-medium text-slate-200 hover:text-white transition-colors whitespace-nowrap"
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => onOpenAuth('signup')}
                className="px-3.5 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap"
              >
                Get Started
              </button>
            </div>
          )}

          {/* Mobile Hamburger Trigger */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            aria-expanded={mobileMenuOpen}
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="md:hidden inline-flex items-center justify-center w-11 h-11 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 hover:text-white"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Collapsible Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-slate-800 bg-slate-950 px-4 py-3 space-y-2">
          <nav className="grid grid-cols-2 gap-2" aria-label="Mobile V1 navigation">
            <button
              type="button"
              onClick={() => navigateMobile('scanner')}
              className={`min-h-[44px] px-3 py-2 rounded-lg text-xs font-medium text-left ${
                currentView === 'scanner'
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'bg-slate-900 text-slate-300'
              }`}
            >
              Auditor
            </button>
            <button
              type="button"
              onClick={() => navigateMobile('dashboard')}
              className={`min-h-[44px] px-3 py-2 rounded-lg text-xs font-medium text-left flex items-center gap-2 ${
                currentView === 'dashboard'
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'bg-slate-900 text-slate-300'
              }`}
            >
              <LayoutDashboard className="w-4 h-4 shrink-0" />
              Dashboard
            </button>
            <button
              type="button"
              onClick={() => navigateMobile('sites')}
              className={`min-h-[44px] px-3 py-2 rounded-lg text-xs font-medium text-left flex items-center gap-2 ${
                currentView === 'sites'
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'bg-slate-900 text-slate-300'
              }`}
            >
              <Globe className="w-4 h-4 shrink-0" />
              Monitored Sites
            </button>
            <button
              type="button"
              onClick={() => navigateMobile('compare')}
              className={`min-h-[44px] px-3 py-2 rounded-lg text-xs font-medium text-left flex items-center gap-2 ${
                currentView === 'compare'
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'bg-slate-900 text-slate-300'
              }`}
            >
              <Scale className="w-4 h-4 shrink-0" />
              Compare Scans
            </button>
          </nav>

          <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onNewScan();
              }}
              className="flex-1 min-h-[44px] px-3 py-2 bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-semibold rounded-lg flex items-center justify-center gap-1.5"
            >
              <Plus className="w-4 h-4" />
              Quick Audit
            </button>
            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                onOpenSettings();
              }}
              className="min-h-[44px] px-3 py-2 bg-slate-900 border border-slate-800 text-slate-200 text-xs font-medium rounded-lg flex items-center gap-1.5"
            >
              <Settings className="w-4 h-4" />
              Settings
            </button>
            {!currentUser && (
              <>
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenAuth('signin');
                  }}
                  className="min-h-[44px] px-3 py-2 bg-slate-900 border border-slate-800 text-slate-200 text-xs font-medium rounded-lg"
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenAuth('signup');
                  }}
                  className="min-h-[44px] px-3 py-2 bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg"
                >
                  Get Started
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
};

