import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  User,
  onAuthStateChanged,
  signInWithPopup,
  GoogleAuthProvider,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  updateProfile,
  signOut
} from 'firebase/auth';
import { doc, getDoc, setDoc, updateDoc } from 'firebase/firestore';
import { auth, db, handleFirestoreError, OperationType, testFirestoreConnection } from '../lib/firebase';
import { UserProfile } from '../types/scanner';

interface AuthContextType {
  currentUser: User | null;
  userProfile: UserProfile | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInWithEmail: (email: string, pass: string) => Promise<void>;
  signUpWithEmail: (email: string, pass: string, name?: string) => Promise<void>;
  logout: () => Promise<void>;
  updateWpScanKey: (key: string) => Promise<void>;
  updateProfilePreferences: (patch: { displayName?: string; onboardingCompleted?: boolean }) => Promise<void>;
  error: string | null;
  sessionNotice: string | null;
  clearError: () => void;
  clearSessionNotice: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function formatFirebaseAuthError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: string })?.code || '';

  if (code === 'auth/invalid-credential' || code === 'auth/wrong-password' || code === 'auth/user-not-found') {
    return 'Invalid email or password. Please check your credentials and try again.';
  }
  if (code === 'auth/email-already-in-use') {
    return 'An account with this email address already exists. Sign in instead or use Google authentication.';
  }
  if (code === 'auth/weak-password') {
    return 'Password is too weak. Please choose a stronger password with at least 6 characters.';
  }
  if (code === 'auth/invalid-email') {
    return 'Please enter a valid email address.';
  }
  if (code === 'auth/user-disabled') {
    return 'This account has been disabled. Contact support or sign in with a different account.';
  }
  if (code === 'auth/user-token-expired' || code === 'auth/requires-recent-login') {
    return 'Your authentication session expired. Please sign in again.';
  }
  if (code === 'auth/too-many-requests') {
    return 'Too many failed attempts. Please wait a few moments before trying again.';
  }
  if (code === 'auth/network-request-failed') {
    return 'Network connection error while contacting authentication servers. Check your internet connection.';
  }
  if (code === 'auth/popup-closed-by-user') {
    return 'Sign-in window was closed before completing authentication.';
  }
  if (code === 'auth/popup-blocked') {
    return 'Sign-in popup was blocked by your browser. Allow popups for this site or sign in with email.';
  }
  if (code === 'auth/unauthorized-domain') {
    return 'This domain is not authorized for Google Sign-In in the Firebase project configuration.';
  }
  return raw || 'Authentication failed. Please try again.';
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  useEffect(() => {
    testFirestoreConnection();

    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      if (user) {
        try {
          // Verify account is still active and valid on Firebase Auth
          await user.reload();
          await user.getIdToken(false);
        } catch (tokenErr: unknown) {
          const code = (tokenErr as { code?: string })?.code || '';
          if (
            code === 'auth/user-disabled' ||
            code === 'auth/user-not-found' ||
            code === 'auth/user-token-expired' ||
            code === 'auth/invalid-user-token'
          ) {
            setSessionNotice(formatFirebaseAuthError(tokenErr));
            await signOut(auth).catch(() => {});
            setCurrentUser(null);
            setUserProfile(null);
            setLoading(false);
            return;
          }
        }

        setCurrentUser(user);
        try {
          const userDocRef = doc(db, 'users', user.uid);
          const snap = await getDoc(userDocRef);
          const providerId = user.providerData?.[0]?.providerId || 'password';
          if (snap.exists()) {
            const existing = snap.data() as UserProfile;
            setUserProfile({
              ...existing,
              displayName: existing.displayName || user.displayName || user.email?.split('@')[0] || 'Security Auditor',
              authProvider: existing.authProvider || providerId
            });
          } else {
            const newProfile: UserProfile = {
              userId: user.uid,
              email: user.email || '',
              displayName: user.displayName || user.email?.split('@')[0] || 'Security Auditor',
              onboardingCompleted: false,
              authProvider: providerId,
              createdAt: user.metadata?.creationTime
                ? new Date(user.metadata.creationTime).toISOString()
                : new Date().toISOString()
            };
            await setDoc(userDocRef, newProfile);
            setUserProfile(newProfile);
          }
        } catch (err) {
          console.error('Error fetching/creating user profile:', err);
        }
      } else {
        setCurrentUser(null);
        setUserProfile(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    setError(null);
    setSessionNotice(null);
    try {
      const provider = new GoogleAuthProvider();
      provider.setCustomParameters({ prompt: 'select_account' });
      const result = await signInWithPopup(auth, provider);
      const user = result.user;

      const userDocRef = doc(db, 'users', user.uid);
      const snap = await getDoc(userDocRef);
      if (!snap.exists()) {
        const newProfile: UserProfile = {
          userId: user.uid,
          email: user.email || '',
          displayName: user.displayName || user.email?.split('@')[0] || 'Security Auditor',
          onboardingCompleted: false,
          authProvider: 'google.com',
          createdAt: user.metadata?.creationTime
            ? new Date(user.metadata.creationTime).toISOString()
            : new Date().toISOString()
        };
        await setDoc(userDocRef, newProfile);
        setUserProfile(newProfile);
      }
    } catch (err: unknown) {
      const msg = formatFirebaseAuthError(err);
      setError(msg);
      throw new Error(msg);
    }
  };

  const signInWithEmail = async (email: string, pass: string) => {
    setError(null);
    setSessionNotice(null);
    try {
      await signInWithEmailAndPassword(auth, email.trim(), pass);
    } catch (err: unknown) {
      const msg = formatFirebaseAuthError(err);
      setError(msg);
      throw new Error(msg);
    }
  };

  const signUpWithEmail = async (email: string, pass: string, name?: string) => {
    setError(null);
    setSessionNotice(null);
    try {
      const cleanEmail = email.trim();
      const cleanName = name?.trim();
      const cred = await createUserWithEmailAndPassword(auth, cleanEmail, pass);
      if (cleanName) {
        await updateProfile(cred.user, { displayName: cleanName });
      }
      const newProfile: UserProfile = {
        userId: cred.user.uid,
        email: cleanEmail,
        displayName: cleanName || cleanEmail.split('@')[0],
        onboardingCompleted: false,
        authProvider: 'password',
        createdAt: new Date().toISOString()
      };
      await setDoc(doc(db, 'users', cred.user.uid), newProfile);
      setUserProfile(newProfile);
    } catch (err: unknown) {
      const msg = formatFirebaseAuthError(err);
      setError(msg);
      throw new Error(msg);
    }
  };

  const logout = async () => {
    setError(null);
    setSessionNotice(null);
    try {
      await signOut(auth);
      setCurrentUser(null);
      setUserProfile(null);
    } catch (err: unknown) {
      const msg = formatFirebaseAuthError(err);
      setError(msg);
    }
  };

  const updateWpScanKey = async (key: string) => {
    if (!currentUser) return;
    try {
      await updateDoc(doc(db, 'users', currentUser.uid), {
        wpscanApiKey: key
      });
      setUserProfile((prev) => (prev ? { ...prev, wpscanApiKey: key } : null));
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `users/${currentUser.uid}`);
    }
  };

  const updateProfilePreferences = async (patch: { displayName?: string; onboardingCompleted?: boolean }) => {
    if (!currentUser) return;
    try {
      const updates: Record<string, unknown> = {};
      if (patch.displayName !== undefined) {
        const trimmed = patch.displayName.trim().slice(0, 128);
        updates.displayName = trimmed;
        await updateProfile(currentUser, { displayName: trimmed }).catch(() => {});
      }
      if (patch.onboardingCompleted !== undefined) {
        updates.onboardingCompleted = patch.onboardingCompleted;
      }
      if (Object.keys(updates).length > 0) {
        await updateDoc(doc(db, 'users', currentUser.uid), updates);
        setUserProfile((prev) => (prev ? { ...prev, ...updates } : null));
      }
    } catch (err) {
      handleFirestoreError(err, OperationType.UPDATE, `users/${currentUser.uid}`);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        userProfile,
        loading,
        signInWithGoogle,
        signInWithEmail,
        signUpWithEmail,
        logout,
        updateWpScanKey,
        updateProfilePreferences,
        error,
        sessionNotice,
        clearError: () => setError(null),
        clearSessionNotice: () => setSessionNotice(null)
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
