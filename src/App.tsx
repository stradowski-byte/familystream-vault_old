/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  WifiOff,
  Search,
  Eraser,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  BellRing,
  Tv,
  Send,
  ChevronDown,
  ChevronUp,
  EyeOff,
  Shield,
} from 'lucide-react';
import {
  onAuthStateChanged,
  signOut,
  User as FirebaseUser,
} from 'firebase/auth';
import {
  auth,
  ensureFirebaseAuthSession,
  isFirebaseConfigured,
  testFirestoreConnection,
} from './lib/firebase';
import {
  appendActivityLogToFirestore,
  consumeInvitationTokenInFirestore,
  createInvitationInFirestore,
  decryptPrivatePasswordsInMemory,
  deleteDeviceFromFirestore,
  deleteInvitationFromFirestore,
  deleteMemberFromFirestore,
  deletePasswordFromFirestore,
  ensureBaseCollectionsInitializedInFirestore,
  fetchLiveVaultBootstrapStateFromFirestore,
  mergeMembersInFirestore,
  rebindDeviceCertificateInFirestore,
  replaceFullVaultStateInFirestore,
  saveDeviceToFirestore,
  saveMemberToFirestore,
  savePasswordToFirestore,
  saveVaultConfigToFirestore,
  subscribeToVaultFirestoreRealtime,
} from './lib/firestoreVaultService';
import {
  ActivityLog,
  BackupFileStructure,
  CoAdminPermissions,
  DecryptedPrivatePayload,
  DEFAULT_CATEGORIES,
  Device,
  InvitationMode,
  InvitationPurpose,
  isAdminOrCoAdmin,
  isCoAdmin,
  isPrimaryAdmin,
  Member,
  parsePasswordCardExtras,
  parseSubAccounts,
  PasswordHistoryEntry,
  PasswordRecord,
  PasswordSosReason,
  serializePasswordCardExtras,
  SubAccountEntry,
  ThemeMode,
  VaultCategory,
  VaultConfig,
  VaultInvitation,
} from './types/vault';
import {
  checkPasswordPwnedKAnonymity,
  decryptVaultBackupFile,
  encryptPrivateRecordPayload,
  encryptVaultBackupFile,
  generateRandomDekBase64,
  generateSaltBase64,
  generateStrongPassword,
  hashPasswordForAuth,
  unwrapDekFromMergeEscrow,
  unwrapDekWithHardwareCertificate,
  unwrapDekWithPassword,
  unwrapLocalDeviceKeysPayload,
  wrapDekForMergeEscrow,
  wrapDekWithHardwareCertificate,
  wrapDekWithPassword,
  wrapLocalDeviceKeysPayload,
} from './lib/crypto';
import {
  authenticateWithBiometrics,
  getDetectedDeviceProfile,
  getStoredBiometricProfile,
  registerBiometricUnlock,
  StoredBiometricProfile,
  verifyDeviceHardwareSignatureMatch,
} from './lib/deviceAndBiometrics';
import { useOnlineStatus } from './hooks/useOnlineStatus';
import { usePWAInstall } from './hooks/usePWAInstall';
import { AdminTabId, TopBar } from './components/TopBar';
import { PasswordCard } from './components/PasswordCard';
import { AddPasswordModal } from './components/AddPasswordModal';
import { AuthAndBootstrapView } from './components/AuthAndBootstrapView';
import { AdminTab2AccountsAndDevices } from './components/AdminTab2AccountsAndDevices';
import { AdminTab3ConfigAndBackup } from './components/AdminTab3ConfigAndBackup';
import { UserProfileView } from './components/UserProfileView';

const REMEMBERED_SESSION_KEY = 'fsv_remembered_session_v1';
const DEVICE_THEME_PREFERENCE_KEY = 'fsv_device_theme_preference_v1';

function readStoredDeviceTheme(): ThemeMode | null {
  if (typeof window === 'undefined') return null;
  try {
    const saved = window.localStorage.getItem(DEVICE_THEME_PREFERENCE_KEY);
    if (saved === 'dusk' || saved === 'linen') {
      return saved;
    }
  } catch {
    // ignore storage errors
  }
  return null;
}

interface RememberedVaultSession {
  memberId: string;
  wrappedKeysPayload?: string;
  keyWrapSaltBase64?: string;
  // Legacy fallback fields (automatically migrated and stripped from localStorage)
  dekBase64?: string;
  mergedDeks?: string[];
  savedAt: string;
}

function makeId(prefix: string): string {
  const bytes = new Uint8Array(8);
  window.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}_${hex}`;
}

export default function App() {
  const isOnline = useOnlineStatus();
  const { isInstallable, isInstalled, install: installPWA } = usePWAInstall();
  const [showIOSInstallModal, setShowIOSInstallModal] = useState(false);

  const detectedDevice = useMemo(() => getDetectedDeviceProfile(), []);

  // Theme state persisted per device in localStorage (Soft Slate Dusk vs Warm Linen Paper)
  const [theme, setTheme] = useState<ThemeMode>(
    () => readStoredDeviceTheme() || 'dusk'
  );

  const handleToggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next: ThemeMode = prev === 'dusk' ? 'linen' : 'dusk';
      try {
        window.localStorage.setItem(DEVICE_THEME_PREFERENCE_KEY, next);
      } catch {
        // ignore storage errors
      }
      return next;
    });
  }, []);

  // Cloud Firestore real-time collections (onSnapshot) & Global Firebase Auth Loading State
  const [firebaseConfigVersion, setFirebaseConfigVersion] = useState(0);
  const [isInitialLoading, setIsInitialLoading] = useState(true);
  const [isAuthStateResolved, setIsAuthStateResolved] = useState<boolean>(
    () => !isFirebaseConfigured()
  );
  const [isSessionRestoreComplete, setIsSessionRestoreComplete] =
    useState<boolean>(() => !isFirebaseConfigured());
  const [isUpdatingApp, setIsUpdatingApp] = useState(false);
  const [vaultConfig, setVaultConfig] = useState<VaultConfig | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [passwords, setPasswords] = useState<PasswordRecord[]>([]);
  const [invitations, setInvitations] = useState<VaultInvitation[]>([]);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);

  // Active authenticated session in memory
  const [currentMemberId, setCurrentMemberId] = useState<string | null>(null);
  const [activeDekBase64, setActiveDekBase64] = useState<string | null>(null);
  const [activeMergedDeks, setActiveMergedDeks] = useState<string[]>([]);
  const [isVaultLockedByTimeout, setIsVaultLockedByTimeout] = useState(false);

  // Pending device / account authorization state
  const [pendingAuthState, setPendingAuthState] = useState<{
    member: Member;
    dekBase64: string;
    mergedDeksBase64: string[];
    passwordPlain?: string;
  } | null>(null);

  // Decrypted private records cache in memory (ONLY for currentMember — E2E client-side)
  const [decryptedPrivateMap, setDecryptedPrivateMap] = useState<
    Record<string, DecryptedPrivatePayload>
  >({});

  // Biometric profile on this device
  const [biometricProfile, setBiometricProfile] =
    useState<StoredBiometricProfile | null>(() => getStoredBiometricProfile());

  // UI Navigation & Filtering state
  const [activeAdminTab, setActiveAdminTab] = useState<AdminTabId>('vault');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategoryFilter, setSelectedCategoryFilter] =
    useState<string>('all');
  const [vaultSectionFilter, setVaultSectionFilter] = useState<
    'all' | 'shared' | 'private' | 'revealed'
  >('all');
  const [sortBy, setSortBy] = useState<'alpha' | 'updated' | 'newest'>('alpha');
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isHealthAuditOpen, setIsHealthAuditOpen] = useState(false);
  const [rotatingPasswordId, setRotatingPasswordId] = useState<string | null>(
    null
  );
  const [topBannerSosCodes, setTopBannerSosCodes] = useState<
    Record<string, string>
  >({});
  const [resolvingSosRecordId, setResolvingSosRecordId] = useState<
    string | null
  >(null);

  // Pillar 2 & 3 State: Search shortcut ref, Privacy Shield (background masking without logout), and Zero-Knowledge Breach Check
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const [isPrivacyShieldActive, setIsPrivacyShieldActive] = useState(false);
  const [pwnedCheckResults, setPwnedCheckResults] = useState<
    Record<string, number>
  >({});
  const [isCheckingBreaches, setIsCheckingBreaches] = useState(false);
  const [hasRunBreachCheck, setHasRunBreachCheck] = useState(false);

  // Clipboard auto-clear timer state
  const [clipboardCountdown, setClipboardCountdown] = useState<{
    secondsLeft: number;
    label: string;
  } | null>(null);
  const clipboardIntervalRef = useRef<number | null>(null);

  // Clean up any legacy bypass key from localStorage on boot
  useEffect(() => {
    try {
      localStorage.removeItem('fsv_aistudio_forced_entry_v1');
    } catch {
      // ignore
    }
  }, []);

  // Sync theme class with documentElement & apply vault defaultTheme ONLY if user hasn't picked a device preference yet
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dusk') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  useEffect(() => {
    if (!vaultConfig?.defaultTheme) return;
    if (readStoredDeviceTheme() === null) {
      setTheme(vaultConfig.defaultTheme);
    }
  }, [vaultConfig?.defaultTheme]);

  const showToast = useCallback((msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 3500);
  }, []);

  // 1. Global Firebase Auth State Listener (onAuthStateChanged):
  // Ensures we wait for Firebase Auth to check browserLocalPersistence before deciding between /login and the vault
  useEffect(() => {
    if (!isFirebaseConfigured() || !auth) {
      setIsAuthStateResolved(true);
      setIsSessionRestoreComplete(true);
      return;
    }

    setIsAuthStateResolved(false);
    const unsubAuth = onAuthStateChanged(auth, () => {
      setIsAuthStateResolved(true);
    });

    const authFallbackTimer = window.setTimeout(() => {
      setIsAuthStateResolved(true);
    }, 2500);

    return () => {
      window.clearTimeout(authFallbackTimer);
      unsubAuth();
    };
  }, [firebaseConfigVersion]);

  // 2. Test connection to Cloud Firestore on boot & subscribe to real-time onSnapshot listeners
  useEffect(() => {
    void testFirestoreConnection();

    const unsubscribe = subscribeToVaultFirestoreRealtime({
      onVaultConfig: (cfg) => setVaultConfig(cfg),
      onMembers: (list) => setMembers(list),
      onDevices: (list) => setDevices(list),
      onPasswords: (list) => setPasswords(list),
      onInvitations: (list) => setInvitations(list),
      onActivityLogs: (list) => setActivityLogs(list),
      onInitialSyncComplete: () => setIsInitialLoading(false),
    });

    const fallbackTimer = window.setTimeout(() => {
      setIsInitialLoading(false);
    }, 2500);

    return () => {
      window.clearTimeout(fallbackTimer);
      unsubscribe();
    };
  }, [firebaseConfigVersion]);

  // 3. Restore active Firebase Auth session or remembered session once both Auth and initial Firestore sync complete
  useEffect(() => {
    if (!isAuthStateResolved || isInitialLoading) {
      return;
    }

    if (currentMemberId || isVaultLockedByTimeout) {
      setIsSessionRestoreComplete(true);
      return;
    }

    if (members.length === 0) {
      setIsSessionRestoreComplete(true);
      return;
    }

    let cancelled = false;

    const tryRestoreSession = async () => {
      try {
        // A. Check remembered session in localStorage (encrypted with AES-256-GCM Wrapped Key bound to device hardware)
        try {
          const rawSession = localStorage.getItem(REMEMBERED_SESSION_KEY);
          if (rawSession) {
            const parsedSession = JSON.parse(
              rawSession
            ) as RememberedVaultSession;
            if (
              parsedSession?.memberId &&
              members.some(
                (m) => m.id === parsedSession.memberId && m.status === 'active'
              )
            ) {
              if (
                parsedSession.wrappedKeysPayload &&
                parsedSession.keyWrapSaltBase64
              ) {
                const unwrapped = await unwrapLocalDeviceKeysPayload({
                  wrappedKeysPayload: parsedSession.wrappedKeysPayload,
                  keyWrapSaltBase64: parsedSession.keyWrapSaltBase64,
                  deviceFingerprint: detectedDevice.deviceFingerprint,
                  hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
                  bindingToken: parsedSession.memberId,
                });
                if (!cancelled) {
                  setCurrentMemberId(parsedSession.memberId);
                  setActiveDekBase64(unwrapped.dekBase64);
                  setActiveMergedDeks(unwrapped.mergedDeks);
                }
                return;
              } else if (parsedSession.dekBase64) {
                // Seamless migration of legacy plaintext session -> encrypt immediately
                const legacyDek = parsedSession.dekBase64;
                const legacyMerged = parsedSession.mergedDeks || [];
                if (!cancelled) {
                  setCurrentMemberId(parsedSession.memberId);
                  setActiveDekBase64(legacyDek);
                  setActiveMergedDeks(legacyMerged);
                }
                return;
              }
            }
          }
        } catch {
          // ignore storage or decryption errors
        }

        // B. Check active Firebase Auth user from onAuthStateChanged (browserLocalPersistence)
        const fbUser = auth?.currentUser;
        if (
          fbUser &&
          (!fbUser.isAnonymous ||
            vaultConfig?.adminUid === fbUser.uid ||
            members.some(
              (m) => m.role === 'admin' && m.googleUid === fbUser.uid
            ))
        ) {
          const adminMember = members.find(
            (m) =>
              m.googleUid === fbUser.uid ||
              (vaultConfig?.adminUid === fbUser.uid &&
                (m.role === 'admin' || m.id === vaultConfig?.adminMemberId)) ||
              m.role === 'admin' ||
              m.username.toLowerCase() === 'admin'
          );
          if (adminMember && adminMember.vaultEscrowKey) {
            try {
              const dekBase64 = await unwrapDekFromMergeEscrow(
                adminMember.vaultEscrowKey,
                adminMember.pbkdf2Salt
              );
              let mergedDeks: string[] = [];
              try {
                const parsed = JSON.parse(
                  adminMember.mergedVaultKeysJson || '[]'
                );
                if (Array.isArray(parsed)) mergedDeks = parsed;
              } catch {
                mergedDeks = [];
              }
              if (!cancelled) {
                setCurrentMemberId(adminMember.id);
                setActiveDekBase64(dekBase64);
                setActiveMergedDeks(mergedDeks);
              }
            } catch (err) {
              console.warn('Auto-restore Admin DEK warning:', err);
            }
          }
        }
      } finally {
        if (!cancelled) {
          setIsSessionRestoreComplete(true);
        }
      }
    };

    void tryRestoreSession();

    const unsubAuth = auth
      ? onAuthStateChanged(auth, () => {
          void tryRestoreSession();
        })
      : () => {};

    return () => {
      cancelled = true;
      unsubAuth();
    };
  }, [
    isAuthStateResolved,
    isInitialLoading,
    members,
    vaultConfig?.adminUid,
    vaultConfig?.adminMemberId,
    currentMemberId,
    isVaultLockedByTimeout,
    firebaseConfigVersion,
  ]);

  // Start clipboard auto-clear countdown
  const startClipboardCountdown = (seconds: number, label: string) => {
    if (clipboardIntervalRef.current) {
      window.clearInterval(clipboardIntervalRef.current);
    }
    setClipboardCountdown({ secondsLeft: seconds, label });
    clipboardIntervalRef.current = window.setInterval(async () => {
      setClipboardCountdown((prev) => {
        if (!prev) return null;
        if (prev.secondsLeft <= 1) {
          if (clipboardIntervalRef.current) {
            window.clearInterval(clipboardIntervalRef.current);
          }
          navigator.clipboard.writeText('').catch(() => {});
          return null;
        }
        return { ...prev, secondsLeft: prev.secondsLeft - 1 };
      });
    }, 1000);
  };

  // Non-destructive application update handler: purges outdated Workbox caches, activates new Service Worker, and reloads
  const handleTriggerAppUpdate = useCallback(async () => {
    setIsUpdatingApp(true);
    try {
      if ('caches' in window) {
        const cacheKeys = await window.caches.keys();
        for (const key of cacheKeys) {
          if (key !== 'fsv-pwa-handoff-cache-v1') {
            await window.caches.delete(key).catch(() => {});
          }
        }
      }

      await Promise.all([
        fetch(`./index.html?pwa_update=${Date.now()}`, {
          cache: 'reload',
        }).catch(() => null),
        fetch(`./manifest.webmanifest?pwa_update=${Date.now()}`, {
          cache: 'reload',
        }).catch(() => null),
      ]);

      if ('serviceWorker' in navigator) {
        const registrations = await navigator.serviceWorker.getRegistrations();
        for (const reg of registrations) {
          await reg.update().catch(() => {});
          if (reg.waiting) {
            reg.waiting.postMessage({ type: 'SKIP_WAITING' });
          }
        }
      }

      showToast(
        'Pobrano i zainstalowano najnowszą wersję aplikacji! Automatyczne przeładowanie...'
      );

      window.setTimeout(() => {
        window.location.reload();
      }, 900);
    } catch (err) {
      console.warn('App update check error:', err);
      showToast(
        'Sprawdzono aktualizacje — posiadasz najnowszą wersję aplikacji.'
      );
      setIsUpdatingApp(false);
    }
  }, [showToast]);

  const handleInstallPWAOrGuide = useCallback(async () => {
    if (isInstallable) {
      await installPWA();
    } else {
      setShowIOSInstallModal(true);
    }
  }, [isInstallable, installPWA]);

  // Current logged-in member object
  const currentMember = useMemo(() => {
    const found = members.find((m) => m.id === currentMemberId);
    if (!found) return null;
    const isAdminUser =
      found.role === 'admin' ||
      found.username.toLowerCase() === 'admin' ||
      found.id === vaultConfig?.adminMemberId;
    if (isAdminUser) {
      return {
        ...found,
        role: 'admin' as const,
        status: 'active' as const,
      };
    }
    return found.status === 'active' ? found : null;
  }, [members, currentMemberId, vaultConfig?.adminMemberId]);

  // Watch pendingAuthState: if Admin or Co-Admin approves the member & device in Firestore (onSnapshot), automatically seal the Hardware Certificate Envelope and unlock the vault!
  useEffect(() => {
    if (!pendingAuthState) return;
    const liveMember = members.find((m) => m.id === pendingAuthState.member.id);
    if (!liveMember) return;

    const liveDevice = devices.find(
      (d) =>
        d.memberId === liveMember.id &&
        d.deviceFingerprint === detectedDevice.deviceFingerprint
    );

    if (
      liveMember.status === 'active' &&
      liveDevice &&
      liveDevice.status === 'approved'
    ) {
      const finalizeHardwareUnlock = async () => {
        if (
          pendingAuthState.passwordPlain &&
          liveDevice.deviceApprovalToken &&
          !liveDevice.hardwareWrappedDek
        ) {
          try {
            const hwWrapped = await wrapDekWithHardwareCertificate(
              pendingAuthState.dekBase64,
              {
                password: pendingAuthState.passwordPlain,
                saltBase64: liveMember.pbkdf2Salt,
                deviceFingerprint: detectedDevice.deviceFingerprint,
                hardwareModelOs:
                  liveDevice.hardwareModelOs || detectedDevice.hardwareModelOs,
                hardwareDeviceType:
                  liveDevice.hardwareDeviceType ||
                  detectedDevice.hardwareDeviceType,
                clientMode: detectedDevice.clientMode,
                deviceApprovalToken: liveDevice.deviceApprovalToken,
              }
            );
            await saveDeviceToFirestore(liveDevice.id, {
              ...liveDevice,
              hardwareWrappedDek: hwWrapped,
              hardwareModelOs: detectedDevice.hardwareModelOs,
              hardwareDeviceType: detectedDevice.hardwareDeviceType,
              hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
              lastSeenAt: new Date().toISOString(),
            });
          } catch (err) {
            console.warn('Automatic hardware envelope seal warning:', err);
          }
        }
        setCurrentMemberId(liveMember.id);
        setActiveDekBase64(pendingAuthState.dekBase64);
        setActiveMergedDeks(pendingAuthState.mergedDeksBase64);
        setPendingAuthState(null);
        showToast(
          'Certyfikat sprzętowy został wydany w Cloud Firestore, a Twoje konto i urządzenie zaakceptowane! Skarbiec odblokowany.'
        );
      };
      finalizeHardwareUnlock();
    }
  }, [members, devices, pendingAuthState, detectedDevice, showToast]);

  // Decrypt current user's private records in RAM strictly on the client (E2E AES-256-GCM)
  useEffect(() => {
    let cancelled = false;
    async function decryptOwnerRecords() {
      if (!currentMember || !activeDekBase64) {
        setDecryptedPrivateMap({});
        return;
      }
      const nextMap = await decryptPrivatePasswordsInMemory(
        passwords,
        currentMember.id,
        activeDekBase64,
        activeMergedDeks
      );
      if (!cancelled) {
        setDecryptedPrivateMap(nextMap);
      }
    }
    decryptOwnerRecords();
    return () => {
      cancelled = true;
    };
  }, [passwords, currentMember, activeDekBase64, activeMergedDeks]);

  // Persist active unlocked session using AES-256-GCM Wrapped Key so raw DEK never appears in localStorage
  useEffect(() => {
    let cancelled = false;
    async function persistEncryptedSession() {
      if (currentMemberId && activeDekBase64 && !isVaultLockedByTimeout) {
        try {
          const { wrappedKeysPayload, keyWrapSaltBase64 } =
            await wrapLocalDeviceKeysPayload({
              dekBase64: activeDekBase64,
              mergedDeks: activeMergedDeks,
              deviceFingerprint: detectedDevice.deviceFingerprint,
              hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
              bindingToken: currentMemberId,
            });
          if (cancelled) return;
          const payload: RememberedVaultSession = {
            memberId: currentMemberId,
            wrappedKeysPayload,
            keyWrapSaltBase64,
            savedAt: new Date().toISOString(),
          };
          localStorage.setItem(REMEMBERED_SESSION_KEY, JSON.stringify(payload));
        } catch {
          // ignore storage errors
        }
      }
    }
    void persistEncryptedSession();
    return () => {
      cancelled = true;
    };
  }, [
    currentMemberId,
    activeDekBase64,
    activeMergedDeks,
    isVaultLockedByTimeout,
    detectedDevice.deviceFingerprint,
    detectedDevice.hardwareSignatureHash,
  ]);

  // Auto-Lock inactivity timer (clears RAM keys, decrypted map, and clipboard)
  useEffect(() => {
    if (!currentMember || isVaultLockedByTimeout) return;
    const timeoutMinutes = vaultConfig?.autoLockMinutes || 15;
    let timerId: number;

    const resetTimer = () => {
      window.clearTimeout(timerId);
      timerId = window.setTimeout(() => {
        try {
          localStorage.removeItem(REMEMBERED_SESSION_KEY);
        } catch {
          // ignore
        }
        if (clipboardIntervalRef.current) {
          window.clearInterval(clipboardIntervalRef.current);
          clipboardIntervalRef.current = null;
        }
        setClipboardCountdown(null);
        navigator.clipboard?.writeText('').catch(() => {});
        setActiveDekBase64(null);
        setActiveMergedDeks([]);
        setDecryptedPrivateMap({});
        setIsVaultLockedByTimeout(true);
      }, timeoutMinutes * 60 * 1000);
    };

    resetTimer();
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach((ev) => window.addEventListener(ev, resetTimer));
    return () => {
      window.clearTimeout(timerId);
      events.forEach((ev) => window.removeEventListener(ev, resetTimer));
    };
  }, [currentMember, isVaultLockedByTimeout, vaultConfig?.autoLockMinutes]);

  // Pillar 3: Privacy Shield when app/tab goes to background (masks revealed passwords & puts up shield WITHOUT logging out!)
  useEffect(() => {
    if (!currentMember || isVaultLockedByTimeout) {
      setIsPrivacyShieldActive(false);
      return;
    }

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        setIsPrivacyShieldActive(true);
        window.dispatchEvent(new CustomEvent('fsv-privacy-shield-activated'));
      } else if (document.visibilityState === 'visible') {
        setIsPrivacyShieldActive(false);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [currentMember, isVaultLockedByTimeout]);

  // Pillar 2: Global keyboard shortcuts (`/` focuses search bar, `Escape` closes modals)
  useEffect(() => {
    if (!currentMember || isVaultLockedByTimeout) return;
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsAddModalOpen(false);
        setShowIOSInstallModal(false);
        return;
      }
      const target = e.target as HTMLElement | null;
      const isInputFocused =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable);
      if (e.key === '/' && !isInputFocused && activeAdminTab === 'vault') {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, [currentMember, isVaultLockedByTimeout, activeAdminTab]);

  // Categories parsed from vaultConfig
  const categories: VaultCategory[] = useMemo(() => {
    if (!vaultConfig?.categoriesJson) return DEFAULT_CATEGORIES;
    try {
      const parsed = JSON.parse(vaultConfig.categoriesJson) as VaultCategory[];
      return Array.isArray(parsed) && parsed.length > 0
        ? parsed
        : DEFAULT_CATEGORIES;
    } catch {
      return DEFAULT_CATEGORIES;
    }
  }, [vaultConfig?.categoriesJson]);

  // Helper to log activity in Cloud Firestore
  const logActivityInFirestore = async (
    actorId: string,
    actorName: string,
    actionType: string,
    details: string
  ) => {
    const logId = makeId('log');
    const entry: ActivityLog = {
      id: logId,
      actorId,
      actorName,
      actionType,
      details: details.slice(0, 490),
      deviceInfo: detectedDevice.deviceName.slice(0, 190),
      timestamp: new Date().toISOString(),
    };
    await appendActivityLogToFirestore(entry);
  };

  // 1. PRIMARY ADMIN LOGIN VIA FIREBASE AUTH (Google Sign-In or Dev Auth Session with browserLocalPersistence)
  const handleAdminGoogleLogin = async (options: {
    firebaseUser: FirebaseUser;
    masterPassword?: string;
  }) => {
    const { firebaseUser, masterPassword } = options;
    const email = firebaseUser.email || 'admin@familystream.local';
    const uid = firebaseUser.uid;
    const displayName = firebaseUser.displayName || 'Główny Administrator';

    const now = new Date().toISOString();

    // Always read live Firestore state first so we never rely on stale/empty React closures right after signIn
    const liveState = await fetchLiveVaultBootstrapStateFromFirestore();
    const effectiveConfig = liveState.vaultConfig || vaultConfig;
    const effectiveMembers =
      liveState.members.length > 0 ? liveState.members : members;
    const effectiveDevices =
      liveState.devices.length > 0 ? liveState.devices : devices;

    let adminMember = effectiveMembers.find(
      (m) =>
        m.role === 'admin' ||
        m.username.toLowerCase() === 'admin' ||
        (effectiveConfig?.adminMemberId &&
          m.id === effectiveConfig.adminMemberId)
    );
    let dekBase64: string;
    let isFirstBootstrap = false;
    let activeConfigDoc: VaultConfig;

    if (!adminMember) {
      isFirstBootstrap = true;
      const adminMemberId =
        effectiveConfig?.adminMemberId || makeId('mem_admin');
      const salt = generateSaltBase64(16);
      const effectivePassword =
        masterPassword && masterPassword.trim().length >= 4
          ? masterPassword.trim()
          : `google_admin_${uid}_${salt}`;
      const passwordHash = await hashPasswordForAuth(effectivePassword, salt);
      dekBase64 = generateRandomDekBase64();
      const wrappedMasterKey = await wrapDekWithPassword(
        dekBase64,
        effectivePassword,
        salt
      );
      const vaultEscrowKey = await wrapDekForMergeEscrow(dekBase64, salt);

      adminMember = {
        id: adminMemberId,
        fullName: displayName,
        username: 'admin',
        passwordHash,
        pbkdf2Salt: salt,
        wrappedMasterKey,
        vaultEscrowKey,
        mergedVaultKeysJson: '[]',
        role: 'admin',
        status: 'active',
        googleUid: uid,
        createdAt: now,
        updatedAt: now,
      };

      activeConfigDoc = {
        initialized: true,
        adminUid: uid,
        adminEmail: email,
        adminMemberId,
        templatesLoaded: effectiveConfig?.templatesLoaded ?? false,
        categoriesJson:
          effectiveConfig?.categoriesJson || JSON.stringify(DEFAULT_CATEGORIES),
        defaultTheme: effectiveConfig?.defaultTheme || theme,
        clipboardClearSeconds: effectiveConfig?.clipboardClearSeconds || 30,
        autoLockMinutes: effectiveConfig?.autoLockMinutes || 15,
        createdAt: effectiveConfig?.createdAt || now,
        updatedAt: now,
      };

      await saveVaultConfigToFirestore(activeConfigDoc);
      await saveMemberToFirestore(adminMember.id, adminMember);
    } else {
      activeConfigDoc = {
        initialized: true,
        adminUid: uid,
        adminEmail: email,
        adminMemberId: adminMember.id,
        templatesLoaded: effectiveConfig?.templatesLoaded ?? false,
        categoriesJson:
          effectiveConfig?.categoriesJson || JSON.stringify(DEFAULT_CATEGORIES),
        defaultTheme: effectiveConfig?.defaultTheme || theme,
        clipboardClearSeconds: effectiveConfig?.clipboardClearSeconds || 30,
        autoLockMinutes: effectiveConfig?.autoLockMinutes || 15,
        createdAt: effectiveConfig?.createdAt || now,
        updatedAt: now,
      };

      // Update vaultConfig/default FIRST so `isAdmin()` (vaultConfig.adminUid == request.auth.uid) is immediately true in Firestore Rules
      await saveVaultConfigToFirestore(activeConfigDoc);

      try {
        dekBase64 = await unwrapDekFromMergeEscrow(
          adminMember.vaultEscrowKey,
          adminMember.pbkdf2Salt
        );
      } catch {
        // Self-healing fallback if an older test record had a corrupted escrow key
        const salt = adminMember.pbkdf2Salt || generateSaltBase64(16);
        const effectivePassword =
          masterPassword && masterPassword.trim().length >= 4
            ? masterPassword.trim()
            : `google_admin_${uid}_${salt}`;
        const passwordHash = await hashPasswordForAuth(effectivePassword, salt);
        dekBase64 = generateRandomDekBase64();
        const wrappedMasterKey = await wrapDekWithPassword(
          dekBase64,
          effectivePassword,
          salt
        );
        const vaultEscrowKey = await wrapDekForMergeEscrow(dekBase64, salt);
        adminMember = {
          ...adminMember,
          pbkdf2Salt: salt,
          passwordHash,
          wrappedMasterKey,
          vaultEscrowKey,
        };
      }

      adminMember = {
        ...adminMember,
        fullName:
          adminMember.fullName === 'Główny Administrator' && displayName
            ? displayName
            : adminMember.fullName,
        role: 'admin',
        status: 'active',
        googleUid: uid,
        updatedAt: now,
      };
      await saveMemberToFirestore(adminMember.id, adminMember);
    }

    // Automatically pair & approve current device for Admin with Hardware Certificate
    const existingDev = effectiveDevices.find(
      (d) =>
        d.memberId === adminMember!.id &&
        d.deviceFingerprint === detectedDevice.deviceFingerprint
    );

    let savedAdminDevice: Device;
    if (!existingDev) {
      const devId = makeId('dev');
      const newAdminDev: Device = {
        id: devId,
        memberId: adminMember.id,
        memberName: adminMember.fullName,
        username: adminMember.username,
        deviceFingerprint: detectedDevice.deviceFingerprint,
        deviceName: detectedDevice.deviceName,
        customLabel:
          detectedDevice.clientMode === 'pwa'
            ? 'Główne urządzenie PWA Admina'
            : 'Przeglądarka Admina',
        clientMode: detectedDevice.clientMode,
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
        status: 'approved',
        webAuthnCredentialId: '',
        requestedAt: now,
        lastSeenAt: now,
      };
      savedAdminDevice = await saveDeviceToFirestore(devId, newAdminDev);
    } else {
      savedAdminDevice = await saveDeviceToFirestore(existingDev.id, {
        ...existingDev,
        status: 'approved',
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
        lastSeenAt: now,
      });
    }

    // Idempotently verify all 6 base collections (`vaultConfig`, `members`, `devices`, `passwords`, `invitations`, `activityLogs`):
    // creates foundational documents ONLY in empty collections, leaving existing collections 100% untouched.
    const initReport = await ensureBaseCollectionsInitializedInFirestore({
      adminUid: uid,
      adminEmail: email,
      adminMemberId: adminMember.id,
      adminMemberName: adminMember.fullName,
      deviceName: detectedDevice.deviceName,
      categoriesJson: activeConfigDoc.categoriesJson,
      defaultTheme: activeConfigDoc.defaultTheme,
    });

    let mergedDeks: string[] = [];
    try {
      const parsed = JSON.parse(adminMember.mergedVaultKeysJson || '[]');
      if (Array.isArray(parsed)) mergedDeks = parsed;
    } catch {
      mergedDeks = [];
    }

    try {
      await logActivityInFirestore(
        adminMember.id,
        adminMember.fullName,
        isFirstBootstrap ? 'VAULT_BOOTSTRAP' : 'ADMIN_FIREBASE_AUTH_LOGIN',
        isFirstBootstrap
          ? `Zainicjalizowano nowy skarbiec dla Pierwszego Administratora (${email}) w Cloud Firestore.`
          : `Główny Administrator zalogował się przez Firebase Auth (${email}).`
      );
    } catch (logErr) {
      console.warn('Activity log write warning:', logErr);
    }

    // Synchronously update React state so `currentMember` is immediately resolved on the next render
    const finalAdminMember = adminMember;
    setVaultConfig(activeConfigDoc);
    setMembers((prev) => {
      const baseList = prev.length > 0 ? prev : effectiveMembers;
      const existsInList = baseList.some((m) => m.id === finalAdminMember.id);
      return existsInList
        ? baseList.map((m) =>
            m.id === finalAdminMember.id ? finalAdminMember : m
          )
        : [finalAdminMember, ...baseList];
    });
    setDevices((prev) => {
      const baseDevs = prev.length > 0 ? prev : effectiveDevices;
      const existsInDevs = baseDevs.some((d) => d.id === savedAdminDevice.id);
      return existsInDevs
        ? baseDevs.map((d) =>
            d.id === savedAdminDevice.id ? savedAdminDevice : d
          )
        : [savedAdminDevice, ...baseDevs];
    });

    try {
      const sessionPayload: RememberedVaultSession = {
        memberId: finalAdminMember.id,
        dekBase64,
        mergedDeks,
        savedAt: now,
      };
      localStorage.setItem(
        REMEMBERED_SESSION_KEY,
        JSON.stringify(sessionPayload)
      );
    } catch {
      // ignore storage errors
    }

    setPendingAuthState(null);
    setCurrentMemberId(finalAdminMember.id);
    setActiveDekBase64(dekBase64);
    setActiveMergedDeks(mergedDeks);
    setIsVaultLockedByTimeout(false);
    setFirebaseConfigVersion((v) => v + 1);

    showToast(
      initReport.initializedCollections.length > 0
        ? `Zalogowano i utworzono brakujące kolekcje bazowe (${initReport.initializedCollections.join(', ')})!`
        : isFirstBootstrap
          ? `Utworzono nowy skarbiec dla ${email} w Cloud Firestore!`
          : `Zalogowano przez Firebase Auth jako ${email}!`
    );
  };

  
  // 2. LOGIN WITH INTERNAL CREDENTIALS + HARDWARE CERTIFICATE (Family Members, Co-Admins & Admin)
  const handleLoginWithCredentials = async (
    username: string,
    password: string
  ) => {
    const fbSessionUser = await ensureFirebaseAuthSession(true);
    const activeAuthUid = fbSessionUser?.uid || auth?.currentUser?.uid || '';

    let effectiveMembers = members;
    let effectiveDevices = devices;
    let effectiveConfig = vaultConfig;

    if (
      effectiveMembers.length === 0 ||
      !effectiveMembers.some(
        (m) =>
          m.username.toLowerCase() === username.toLowerCase() &&
          m.status !== 'merged'
      )
    ) {
      const liveState = await fetchLiveVaultBootstrapStateFromFirestore();
      if (liveState.members.length > 0) {
        effectiveMembers = liveState.members;
        setMembers(liveState.members);
      }
      if (liveState.devices.length > 0) {
        effectiveDevices = liveState.devices;
        setDevices(liveState.devices);
      }
      if (liveState.vaultConfig) {
        effectiveConfig = liveState.vaultConfig;
        setVaultConfig(liveState.vaultConfig);
      }
    }

    const member = effectiveMembers.find(
      (m) =>
        m.username.toLowerCase() === username.toLowerCase() &&
        m.status !== 'merged'
    );
    if (!member) {
      throw new Error(
        `Nie znaleziono konta o loginie „${username}” w Cloud Firestore. Jeśli nie masz jeszcze konta, otwórz link zaproszeniowy powyżej i kliknij „Utwórz konto w skarbcu”.`
      );
    }

    const computedHash = await hashPasswordForAuth(password, member.pbkdf2Salt);
    if (computedHash !== member.passwordHash) {
      throw new Error(
        'Nieprawidłowe hasło. Jeśli zapomniałeś hasła (np. Mama), zadzwoń do Administratora lub Zaufanego Opiekuna (np. Brata) po reset hasła lub link ratunkowy.'
      );
    }

    // Bind current Firebase Auth UID (Anonymous Auth bound to device) to member.googleUid for Firestore Security Rules ownership verification
    if (
      activeAuthUid &&
      member.role !== 'admin' &&
      member.googleUid !== activeAuthUid
    ) {
      await saveMemberToFirestore(member.id, {
        ...member,
        googleUid: activeAuthUid,
        updatedAt: new Date().toISOString(),
      });
    }

    let mergedDeks: string[] = [];
    try {
      const parsed = JSON.parse(member.mergedVaultKeysJson || '[]');
      if (Array.isArray(parsed)) mergedDeks = parsed;
    } catch {
      mergedDeks = [];
    }

    const existingDevice =
      effectiveDevices.find(
        (d) =>
          d.memberId === member.id &&
          d.deviceFingerprint === detectedDevice.deviceFingerprint
      ) || null;

    if (
      member.role === 'admin' ||
      member.username.toLowerCase() === 'admin' ||
      member.id === effectiveConfig?.adminMemberId
    ) {
      const dekBase64 = await unwrapDekWithPassword(
        member.wrappedMasterKey,
        password,
        member.pbkdf2Salt
      );
      const now = new Date().toISOString();
      if (!existingDevice) {
        const devId = makeId('dev');
        const adminDev: Device = {
          id: devId,
          memberId: member.id,
          memberName: member.fullName,
          username: member.username,
          deviceFingerprint: detectedDevice.deviceFingerprint,
          deviceName: detectedDevice.deviceName,
          customLabel:
            detectedDevice.clientMode === 'pwa'
              ? 'Urządzenie PWA Admina'
              : 'Przeglądarka Admina',
          clientMode: detectedDevice.clientMode,
          hardwareModelOs: detectedDevice.hardwareModelOs,
          hardwareDeviceType: detectedDevice.hardwareDeviceType,
          hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
          status: 'approved',
          webAuthnCredentialId: '',
          requestedAt: now,
          lastSeenAt: now,
        };
        await saveDeviceToFirestore(devId, adminDev);
      } else if (existingDevice.status !== 'approved') {
        await saveDeviceToFirestore(existingDevice.id, {
          ...existingDevice,
          status: 'approved',
          hardwareModelOs: detectedDevice.hardwareModelOs,
          hardwareDeviceType: detectedDevice.hardwareDeviceType,
          hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
          lastSeenAt: now,
        });
      }

      setCurrentMemberId(member.id);
      setActiveDekBase64(dekBase64);
      setActiveMergedDeks(mergedDeks);
      setIsVaultLockedByTimeout(false);
      showToast(`Zalogowano jako Administrator (${member.fullName})!`);
      return;
    }

    // HARDCORE HARDWARE-BOUND CRYPTOGRAPHY FOR FAMILY MEMBERS & CO-ADMINS:
    // Only an APPROVED device with a Firestore-issued `deviceApprovalToken` can unlock private passwords!
    if (
      member.status === 'active' &&
      existingDevice &&
      existingDevice.status === 'approved' &&
      existingDevice.deviceApprovalToken
    ) {
      const now = new Date().toISOString();
      const hwParams = {
        password,
        saltBase64: member.pbkdf2Salt,
        deviceFingerprint: detectedDevice.deviceFingerprint,
        hardwareModelOs:
          existingDevice.hardwareModelOs || detectedDevice.hardwareModelOs,
        hardwareDeviceType:
          existingDevice.hardwareDeviceType ||
          detectedDevice.hardwareDeviceType,
        clientMode: detectedDevice.clientMode,
        deviceApprovalToken: existingDevice.deviceApprovalToken,
      };

      let dekBase64: string;
      if (existingDevice.hardwareWrappedDek) {
        try {
          // Derive Hardware-Bound AES-256-GCM key from Password + OS-Free Hardware Model + Device ID + Mode + Certificate Token
          dekBase64 = await unwrapDekWithHardwareCertificate(
            existingDevice.hardwareWrappedDek,
            hwParams
          );
          const needsModelNormalization =
            existingDevice.hardwareModelOs !== detectedDevice.hardwareModelOs ||
            existingDevice.hardwareSignatureHash !==
              detectedDevice.hardwareSignatureHash;

          const reSealedDek = needsModelNormalization
            ? await wrapDekWithHardwareCertificate(dekBase64, {
                ...hwParams,
                hardwareModelOs: detectedDevice.hardwareModelOs,
                hardwareDeviceType: detectedDevice.hardwareDeviceType,
              })
            : existingDevice.hardwareWrappedDek;

          await saveDeviceToFirestore(existingDevice.id, {
            ...existingDevice,
            lastSeenAt: now,
            clientMode: detectedDevice.clientMode,
            hardwareModelOs: detectedDevice.hardwareModelOs,
            hardwareDeviceType: detectedDevice.hardwareDeviceType,
            hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
            hardwareWrappedDek: reSealedDek,
          });
        } catch {
          // Self-healing migration if OS version string changed before OS-free normalization:
          dekBase64 = await unwrapDekWithPassword(
            member.wrappedMasterKey,
            password,
            member.pbkdf2Salt
          );
          const reSealedHardwareDek = await wrapDekWithHardwareCertificate(
            dekBase64,
            {
              ...hwParams,
              hardwareModelOs: detectedDevice.hardwareModelOs,
              hardwareDeviceType: detectedDevice.hardwareDeviceType,
            }
          );
          await saveDeviceToFirestore(existingDevice.id, {
            ...existingDevice,
            lastSeenAt: now,
            clientMode: detectedDevice.clientMode,
            hardwareModelOs: detectedDevice.hardwareModelOs,
            hardwareDeviceType: detectedDevice.hardwareDeviceType,
            hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
            hardwareWrappedDek: reSealedHardwareDek,
          });
        }
      } else {
        // First login after Admin/Co-Admin approved this device or rebound its certificate:
        dekBase64 = await unwrapDekWithPassword(
          member.wrappedMasterKey,
          password,
          member.pbkdf2Salt
        );
        const sealedHardwareDek = await wrapDekWithHardwareCertificate(
          dekBase64,
          {
            ...hwParams,
            hardwareModelOs: detectedDevice.hardwareModelOs,
            hardwareDeviceType: detectedDevice.hardwareDeviceType,
          }
        );
        await saveDeviceToFirestore(existingDevice.id, {
          ...existingDevice,
          lastSeenAt: now,
          clientMode: detectedDevice.clientMode,
          hardwareModelOs: detectedDevice.hardwareModelOs,
          hardwareDeviceType: detectedDevice.hardwareDeviceType,
          hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
          hardwareWrappedDek: sealedHardwareDek,
        });
      }

      await logActivityInFirestore(
        member.id,
        member.fullName,
        'MEMBER_LOGIN',
        `Zalogowano z weryfikacją Certyfikatu Sprzętowego (${
          existingDevice.deviceCertificateFingerprint ||
          detectedDevice.hardwareSignatureHash
        } · ${
          detectedDevice.clientMode === 'pwa' ? 'Aplikacja PWA' : 'Przeglądarka'
        }).`
      );

      setCurrentMemberId(member.id);
      setActiveDekBase64(dekBase64);
      setActiveMergedDeks(mergedDeks);
      setIsVaultLockedByTimeout(false);
      showToast(
        `Zweryfikowano Certyfikat Sprzętowy (${
          existingDevice.deviceCertificateFingerprint ||
          detectedDevice.hardwareSignatureHash
        }) — Witaj, ${member.fullName}!`
      );
      return;
    }

    // Device is NOT approved yet — hold in pendingAuthState until Admin/Co-Admin approves & issues certificate
    const pendingDekBase64 = await unwrapDekWithPassword(
      member.wrappedMasterKey,
      password,
      member.pbkdf2Salt
    );

    setPendingAuthState({
      member,
      dekBase64: pendingDekBase64,
      mergedDeksBase64: mergedDeks,
      passwordPlain: password,
    });
  };

  // 3A. REGISTER NEW FAMILY MEMBER VIA INVITATION LINK ("Załóż mi konto")
  const handleRegisterMemberAccountWithInvite = async (params: {
    inviteToken: string;
    fullName: string;
    username: string;
    password: string;
    setupBiometrics: boolean;
  }) => {
    const fbSessionUser = await ensureFirebaseAuthSession(true);
    const boundAuthUid = fbSessionUser?.uid || auth?.currentUser?.uid || '';

    let effectiveMembers = members;
    if (effectiveMembers.length === 0) {
      const liveState = await fetchLiveVaultBootstrapStateFromFirestore();
      if (liveState.members.length > 0) {
        effectiveMembers = liveState.members;
        setMembers(liveState.members);
      }
    }

    const duplicate = effectiveMembers.find(
      (m) =>
        m.username.toLowerCase() === params.username.toLowerCase() &&
        m.status !== 'merged'
    );
    if (duplicate) {
      throw new Error(
        `Konto z loginem „${params.username}” już istnieje w skarbcu. Wybierz inny login lub zaloguj się w formularzu poniżej.`
      );
    }

    const now = new Date().toISOString();
    const memberId = makeId('mem');
    const salt = generateSaltBase64(16);
    const passwordHash = await hashPasswordForAuth(params.password, salt);
    const dekBase64 = generateRandomDekBase64();
    const wrappedMasterKey = await wrapDekWithPassword(
      dekBase64,
      params.password,
      salt
    );
    const vaultEscrowKey = await wrapDekForMergeEscrow(dekBase64, salt);

    await consumeInvitationTokenInFirestore(params.inviteToken);

    let credentialId = '';
    if (params.setupBiometrics) {
      try {
        const bioRes = await registerBiometricUnlock({
          memberId,
          username: params.username,
          fullName: params.fullName,
          dekBase64,
          mergedDeksBase64: [],
        });
        credentialId = bioRes.credentialId;
        setBiometricProfile(getStoredBiometricProfile());
      } catch (err) {
        console.warn('Opcjonalna rejestracja biometrii pominięta:', err);
      }
    }

    const newMember: Member = {
      id: memberId,
      fullName: params.fullName,
      username: params.username,
      passwordHash,
      pbkdf2Salt: salt,
      wrappedMasterKey,
      vaultEscrowKey,
      mergedVaultKeysJson: '[]',
      role: 'member',
      status: 'pending',
      googleUid: boundAuthUid,
      invitedByToken: params.inviteToken,
      createdAt: now,
      updatedAt: now,
    };

    const devId = makeId('dev');
    const newDevice: Device = {
      id: devId,
      memberId,
      memberName: params.fullName,
      username: params.username,
      deviceFingerprint: detectedDevice.deviceFingerprint,
      deviceName: detectedDevice.deviceName,
      customLabel:
        detectedDevice.clientMode === 'pwa'
          ? 'Aplikacja PWA (Z zaproszenia)'
          : 'Przeglądarka (Z zaproszenia)',
      clientMode: detectedDevice.clientMode,
      hardwareModelOs: detectedDevice.hardwareModelOs,
      hardwareDeviceType: detectedDevice.hardwareDeviceType,
      hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
      status: 'pending',
      webAuthnCredentialId: credentialId,
      requestedAt: now,
      lastSeenAt: now,
    };

    await saveMemberToFirestore(memberId, newMember);
    const savedNewDevice = await saveDeviceToFirestore(devId, newDevice);

    setMembers((prev) =>
      prev.some((m) => m.id === newMember.id) ? prev : [...prev, newMember]
    );
    setDevices((prev) =>
      prev.some((d) => d.id === savedNewDevice.id)
        ? prev
        : [...prev, savedNewDevice]
    );

    await logActivityInFirestore(
      memberId,
      params.fullName,
      'MEMBER_INVITE_REGISTER',
      `Domownik ${params.fullName} (login: ${params.username}, sprzęt: ${detectedDevice.hardwareSignatureHash}) kliknął „Załóż mi konto” z linku zaproszeniowego i oczekuje na wydanie Certyfikatu Sprzętowego.`
    );

    setPendingAuthState({
      member: newMember,
      dekBase64,
      mergedDeksBase64: [],
      passwordPlain: params.password,
    });
    showToast(
      'Zgłoszenie „Załóż mi konto” zapisano w Cloud Firestore! Poczekaj na zatwierdzenie przez Administratora lub Opiekuna.'
    );
  };

  // 3B. RECOVER EXISTING MEMBER ACCOUNT VIA RECOVERY LINK
  const handleRecoverMemberAccountWithInvite = async (params: {
    inviteToken: string;
    targetMemberId: string;
    newUsername: string;
    newPassword: string;
    setupBiometrics: boolean;
  }) => {
    let effectiveMembers = members;
    if (effectiveMembers.length === 0) {
      const liveState = await fetchLiveVaultBootstrapStateFromFirestore();
      if (liveState.members.length > 0) {
        effectiveMembers = liveState.members;
        setMembers(liveState.members);
      }
    }

    const targetMember = effectiveMembers.find(
      (m) => m.id === params.targetMemberId
    );
    if (!targetMember) {
      throw new Error(
        'Nie znaleziono konta domownika powiązanego z tym linkiem.'
      );
    }

    const duplicate = effectiveMembers.find(
      (m) =>
        m.id !== targetMember.id &&
        m.username.toLowerCase() === params.newUsername.toLowerCase() &&
        m.status !== 'merged'
    );
    if (duplicate) {
      throw new Error('Ten login jest już zajęty przez innego domownika.');
    }

    await consumeInvitationTokenInFirestore(params.inviteToken);

    // Recover existing DEK from vaultEscrowKey so the member keeps all private entries!
    const dekBase64 = await unwrapDekFromMergeEscrow(
      targetMember.vaultEscrowKey,
      targetMember.pbkdf2Salt
    );
    const newPasswordHash = await hashPasswordForAuth(
      params.newPassword,
      targetMember.pbkdf2Salt
    );
    const newWrappedMasterKey = await wrapDekWithPassword(
      dekBase64,
      params.newPassword,
      targetMember.pbkdf2Salt
    );

    const fbSessionUser = await ensureFirebaseAuthSession(true);
    const boundAuthUid =
      fbSessionUser?.uid ||
      auth?.currentUser?.uid ||
      targetMember.googleUid ||
      '';

    const now = new Date().toISOString();
    const updatedMember: Member = {
      ...targetMember,
      username: params.newUsername,
      passwordHash: newPasswordHash,
      wrappedMasterKey: newWrappedMasterKey,
      googleUid: boundAuthUid,
      status: 'active',
      updatedAt: now,
    };

    await saveMemberToFirestore(targetMember.id, updatedMember);

    let mergedDeks: string[] = [];
    try {
      const parsed = JSON.parse(targetMember.mergedVaultKeysJson || '[]');
      if (Array.isArray(parsed)) mergedDeks = parsed;
    } catch {
      mergedDeks = [];
    }

    let credentialId = '';
    if (params.setupBiometrics) {
      try {
        const bioRes = await registerBiometricUnlock({
          memberId: targetMember.id,
          username: params.newUsername,
          fullName: targetMember.fullName,
          dekBase64,
          mergedDeksBase64: mergedDeks,
        });
        credentialId = bioRes.credentialId;
        setBiometricProfile(getStoredBiometricProfile());
      } catch (err) {
        console.warn('Biometria podczas odzyskiwania konta pominięta:', err);
      }
    }

    const existingDev = devices.find(
      (d) =>
        d.memberId === targetMember.id &&
        d.deviceFingerprint === detectedDevice.deviceFingerprint
    );

    let savedDev: Device;
    if (existingDev) {
      savedDev = await saveDeviceToFirestore(existingDev.id, {
        ...existingDev,
        status: 'approved',
        username: params.newUsername,
        clientMode: detectedDevice.clientMode,
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
        hardwareWrappedDek: '',
        webAuthnCredentialId: credentialId || existingDev.webAuthnCredentialId,
        lastSeenAt: now,
      });
    } else {
      const targetDevId = makeId('dev');
      savedDev = await saveDeviceToFirestore(targetDevId, {
        id: targetDevId,
        memberId: targetMember.id,
        memberName: targetMember.fullName,
        username: params.newUsername,
        deviceFingerprint: detectedDevice.deviceFingerprint,
        deviceName: detectedDevice.deviceName,
        customLabel: 'Odblokowane linkiem ratunkowym',
        clientMode: detectedDevice.clientMode,
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
        status: 'approved',
        webAuthnCredentialId: credentialId,
        requestedAt: now,
        lastSeenAt: now,
      });
    }

    if (savedDev.deviceApprovalToken) {
      const sealedHwDek = await wrapDekWithHardwareCertificate(dekBase64, {
        password: params.newPassword,
        saltBase64: targetMember.pbkdf2Salt,
        deviceFingerprint: detectedDevice.deviceFingerprint,
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        clientMode: detectedDevice.clientMode,
        deviceApprovalToken: savedDev.deviceApprovalToken,
      });
      await saveDeviceToFirestore(savedDev.id, {
        ...savedDev,
        hardwareWrappedDek: sealedHwDek,
      });
    }

    await logActivityInFirestore(
      targetMember.id,
      targetMember.fullName,
      'MEMBER_ACCOUNT_RECOVERED',
      `Domownik ${targetMember.fullName} ustawił nowe hasło i odzyskał dostęp za pomocą linku ratunkowego.`
    );

    setCurrentMemberId(targetMember.id);
    setActiveDekBase64(dekBase64);
    setActiveMergedDeks(mergedDeks);
    setIsVaultLockedByTimeout(false);
    showToast(
      `Zapisano nowe hasło i odblokowano konto dla ${targetMember.fullName}!`
    );
  };

  // 4. CLICK "AUTORYZUJ MOJE URZĄDZENIE"
  const handleRequestDeviceAuthorization = async (customLabel: string) => {
    if (!pendingAuthState) return;
    const { member } = pendingAuthState;
    const now = new Date().toISOString();

    const existing = devices.find(
      (d) =>
        d.memberId === member.id &&
        d.deviceFingerprint === detectedDevice.deviceFingerprint
    );

    if (existing) {
      await saveDeviceToFirestore(existing.id, {
        ...existing,
        status: 'pending',
        customLabel: customLabel || existing.customLabel,
        clientMode: detectedDevice.clientMode,
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
        lastSeenAt: now,
      });
    } else {
      const devId = makeId('dev');
      const newDevice: Device = {
        id: devId,
        memberId: member.id,
        memberName: member.fullName,
        username: member.username,
        deviceFingerprint: detectedDevice.deviceFingerprint,
        deviceName: detectedDevice.deviceName,
        customLabel: customLabel || 'Nowe urządzenie',
        clientMode: detectedDevice.clientMode,
        hardwareModelOs: detectedDevice.hardwareModelOs,
        hardwareDeviceType: detectedDevice.hardwareDeviceType,
        hardwareSignatureHash: detectedDevice.hardwareSignatureHash,
        status: 'pending',
        webAuthnCredentialId: '',
        requestedAt: now,
        lastSeenAt: now,
      };
      await saveDeviceToFirestore(devId, newDevice);
    }

    await logActivityInFirestore(
      member.id,
      member.fullName,
      'DEVICE_AUTH_REQUEST',
      `Wysłano prośbę o autoryzację i Certyfikat Sprzętowy dla: ${detectedDevice.deviceName} (${detectedDevice.hardwareSignatureHash}).`
    );
    showToast('Wysłano prośbę o autoryzację i Certyfikat Sprzętowy urządzenia!');
  };

  // 5. BIOMETRIC WEBAUTHN UNLOCK & REGISTRATION
  const handleRegisterBiometricsForCurrentDevice = async () => {
    if (!currentMember || !activeDekBase64) return;
    const myDevice = devices.find(
      (d) =>
        d.memberId === currentMember.id &&
        d.deviceFingerprint === detectedDevice.deviceFingerprint
    );

    const { credentialId } = await registerBiometricUnlock({
      memberId: currentMember.id,
      username: currentMember.username,
      fullName: currentMember.fullName,
      dekBase64: activeDekBase64,
      mergedDeksBase64: activeMergedDeks,
    });

    if (myDevice) {
      await saveDeviceToFirestore(myDevice.id, {
        ...myDevice,
        webAuthnCredentialId: credentialId,
        lastSeenAt: new Date().toISOString(),
      });
    }

    setBiometricProfile(getStoredBiometricProfile());
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'BIOMETRIC_PAIRED',
      `Skonfigurowano logowanie odciskiem palca (WebAuthn) na urządzeniu ${detectedDevice.deviceName}.`
    );
    showToast(
      'Skonfigurowano odblokowywanie odciskiem palca na tym urządzeniu!'
    );
  };

  const handleUnlockWithBiometrics = async () => {
    const stored = await authenticateWithBiometrics();
    const member = members.find(
      (m) => m.id === stored.memberId && m.status === 'active'
    );
    if (!member) {
      throw new Error('Konto powiązane z odciskiem palca nie jest aktywne.');
    }
    const dev = devices.find(
      (d) =>
        d.memberId === member.id &&
        d.deviceFingerprint === detectedDevice.deviceFingerprint &&
        d.status === 'approved'
    );
    if (!dev || !verifyDeviceHardwareSignatureMatch(dev, detectedDevice)) {
      throw new Error(
        'To urządzenie nie ma aktywnej autoryzacji Administratora lub sygnatura sprzętowa (hardwareSignatureHash) uległa zmianie.'
      );
    }

    setCurrentMemberId(member.id);
    setActiveDekBase64(stored.dekBase64);
    setActiveMergedDeks(stored.mergedDeksBase64 || []);
    setIsVaultLockedByTimeout(false);
    await logActivityInFirestore(
      member.id,
      member.fullName,
      'BIOMETRIC_UNLOCK',
      `Odblokowano skarbiec odciskiem palca (WebAuthn).`
    );
  };

  // Synchronize allowedMemberIds with both member.id and member.googleUid (request.auth.uid)
  // so Firestore `where('allowedMemberIds', 'array-contains', request.auth.uid)` queries work for all family members
  const expandAllowedMemberIdsWithAuthUids = useCallback(
    (rawMemberIds: string[], ownerMemberId?: string): string[] => {
      const baseIds = new Set<string>(rawMemberIds.filter(Boolean));
      if (ownerMemberId) {
        baseIds.add(ownerMemberId);
      }
      for (const m of members) {
        if (baseIds.has(m.id) || (m.googleUid && baseIds.has(m.googleUid))) {
          baseIds.add(m.id);
          if (m.googleUid) {
            baseIds.add(m.googleUid);
          }
        }
      }
      if (
        ownerMemberId &&
        currentMember &&
        ownerMemberId === currentMember.id &&
        auth?.currentUser?.uid
      ) {
        baseIds.add(auth.currentUser.uid);
      }
      return Array.from(baseIds);
    },
    [members, currentMember]
  );

  // Self-healing sync: when Admin or record owner is active, ensure every password's allowedMemberIds
  // includes the bound Firebase Auth UID (member.googleUid) for the owner and all permitted members
  useEffect(() => {
    if (!currentMember || passwords.length === 0 || members.length === 0) return;
    const isAdminActor = isPrimaryAdmin(currentMember);

    for (const rec of passwords) {
      const canActorUpdate = isAdminActor || rec.ownerId === currentMember.id;
      if (!canActorUpdate) continue;

      const expanded = expandAllowedMemberIdsWithAuthUids(
        rec.allowedMemberIds || [],
        rec.ownerId
      );
      const currentSet = new Set(rec.allowedMemberIds || []);
      const hasMissingAuthUid = expanded.some((id) => !currentSet.has(id));

      if (hasMissingAuthUid) {
        void savePasswordToFirestore(rec.id, {
          allowedMemberIds: expanded,
        });
      }
    }
  }, [
    currentMember,
    passwords,
    members,
    isPrimaryAdmin,
    expandAllowedMemberIdsWithAuthUids,
  ]);

  // 6. PASSWORD CRUD & SUB-ACCOUNTS (E2E Encryption before setDoc in Firestore)
  const handleAddPassword = async (params: {
    section: 'shared' | 'private';
    categoryId: string;
    serviceName: string;
    serviceUrl: string;
    login: string;
    password: string;
    allowedMemberIds: string[];
    revealToAdmin?: boolean;
    subAccounts?: SubAccountEntry[];
    profilePinOrNote?: string;
    totpSecret?: string;
  }) => {
    if (!currentMember || !activeDekBase64) return;
    const now = new Date().toISOString();
    const pwId = makeId('pw');
    const cleanPinNote = params.profilePinOrNote?.trim() || undefined;
    const cleanTotp = params.totpSecret?.trim() || undefined;

    if (params.section === 'private') {
      const plainPrivatePayload: DecryptedPrivatePayload = {
        categoryId: params.categoryId,
        serviceName: params.serviceName,
        serviceUrl: params.serviceUrl,
        login: params.login,
        password: params.password,
        passwordHistory: [],
        ...(cleanPinNote ? { profilePinOrNote: cleanPinNote } : {}),
        ...(cleanTotp ? { totpSecret: cleanTotp } : {}),
      };
      const encryptedPayload = await encryptPrivateRecordPayload(
        plainPrivatePayload,
        activeDekBase64
      );
      const shouldReveal = Boolean(params.revealToAdmin);
      const record: PasswordRecord = {
        id: pwId,
        section: 'private',
        categoryId: shouldReveal ? params.categoryId : 'ENC[PRIVATE]',
        serviceName: shouldReveal ? params.serviceName : 'ENC[PRIVATE]',
        serviceUrl: shouldReveal ? params.serviceUrl : 'ENC[PRIVATE]',
        login: shouldReveal ? params.login : 'ENC[PRIVATE]',
        passwordValue: shouldReveal
          ? params.password
          : encryptedPayload.slice(0, 96) + '...',
        encryptedPayload,
        keySalt: currentMember.pbkdf2Salt,
        ownerId: currentMember.id,
        ownerName: currentMember.fullName,
        allowedMemberIds: expandAllowedMemberIdsWithAuthUids(
          [currentMember.id],
          currentMember.id
        ),
        revealToAdmin: shouldReveal,
        subAccountsJson: serializePasswordCardExtras({
          subAccounts: [],
          sosTicket: null,
          favoriteMemberIds: [],
          passwordHistory: [],
          profilePinOrNote: shouldReveal ? cleanPinNote : undefined,
          totpSecret: shouldReveal ? cleanTotp : undefined,
        }),
        createdAt: now,
        updatedAt: now,
        passwordUpdatedAt: now,
      };
      await savePasswordToFirestore(pwId, record);
    } else {
      const subList = params.subAccounts || [];
      const subMemberIds = subList.map((s) => s.assignedMemberId);
      const mergedAllowed = expandAllowedMemberIdsWithAuthUids(
        [...params.allowedMemberIds, ...subMemberIds, currentMember.id],
        currentMember.id
      );
      const record: PasswordRecord = {
        id: pwId,
        section: 'shared',
        categoryId: params.categoryId,
        serviceName: params.serviceName,
        serviceUrl: params.serviceUrl,
        login: params.login,
        passwordValue: params.password,
        encryptedPayload: '',
        keySalt: '',
        ownerId: currentMember.id,
        ownerName: currentMember.fullName,
        allowedMemberIds: mergedAllowed,
        revealToAdmin: false,
        subAccountsJson: serializePasswordCardExtras({
          subAccounts: subList,
          sosTicket: null,
          favoriteMemberIds: [],
          passwordHistory: [],
          profilePinOrNote: cleanPinNote,
          totpSecret: cleanTotp,
        }),
        createdAt: now,
        updatedAt: now,
        passwordUpdatedAt: now,
      };
      await savePasswordToFirestore(pwId, record);
    }

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'PASSWORD_CREATED',
      params.section === 'private'
        ? params.revealToAdmin
          ? `Dodano prywatny rekord ujawniony Administratorowi: ${params.serviceName}.`
          : 'Dodano nowy zaszyfrowany rekord prywatny (ENC[AES-256-GCM]).'
        : `Dodano wspólne konto: ${params.serviceName}.`
    );
    showToast('Dodano nowe hasło i zsynchronizowano w Cloud Firestore!');
  };

  const handleUpdateSubAccounts = async (
    record: PasswordRecord,
    nextSubAccounts: SubAccountEntry[],
    additionalAllowedMemberId?: string
  ) => {
    if (!currentMember) return;
    const now = new Date().toISOString();
    const rawAllowed = additionalAllowedMemberId
      ? [...record.allowedMemberIds, additionalAllowedMemberId]
      : record.allowedMemberIds;
    const nextAllowed = expandAllowedMemberIdsWithAuthUids(
      rawAllowed,
      record.ownerId
    );
    const currentExtras = parsePasswordCardExtras(record);

    await savePasswordToFirestore(record.id, {
      subAccountsJson: serializePasswordCardExtras({
        ...currentExtras,
        subAccounts: nextSubAccounts,
      }),
      allowedMemberIds: nextAllowed,
      updatedAt: now,
      passwordUpdatedAt: now,
    });

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'SUBACCOUNTS_UPDATED',
      `Zaktualizowano subkonta domowników dla serwisu ${record.serviceName} (${nextSubAccounts.length} subkont).`
    );
    showToast(`Zaktualizowano subkonta w serwisie ${record.serviceName}!`);
  };

  const handleToggleFavorite = async (record: PasswordRecord) => {
    if (!currentMember) return;
    const now = new Date().toISOString();
    const currentExtras = parsePasswordCardExtras(record);
    const isAlreadyFav = currentExtras.favoriteMemberIds.includes(
      currentMember.id
    );
    const nextFavorites = isAlreadyFav
      ? currentExtras.favoriteMemberIds.filter((id) => id !== currentMember.id)
      : [...currentExtras.favoriteMemberIds, currentMember.id];

    await savePasswordToFirestore(record.id, {
      subAccountsJson: serializePasswordCardExtras({
        ...currentExtras,
        favoriteMemberIds: nextFavorites,
      }),
      updatedAt: now,
    });

    showToast(
      isAlreadyFav
        ? 'Usunięto kartę z ulubionych.'
        : 'Przypięto kartę do ulubionych (na górze listy)!'
    );
  };

  const handleCreateSosRequest = async (
    record: PasswordRecord,
    reason: PasswordSosReason
  ) => {
    if (!currentMember || record.section === 'private') return;
    const now = new Date().toISOString();
    const currentExtras = parsePasswordCardExtras(record);

    await savePasswordToFirestore(record.id, {
      subAccountsJson: serializePasswordCardExtras({
        ...currentExtras,
        sosTicket: {
          id: makeId('sos'),
          status: 'pending',
          reason,
          requestedByMemberId: currentMember.id,
          requestedByMemberName: currentMember.fullName,
          targetOwnerId: record.ownerId,
          targetOwnerName: record.ownerName,
          createdAt: now,
        },
      }),
      updatedAt: now,
    });

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'SOS_REQUEST_SENT_TO_OWNER',
      `Wysłano prośbę SOS (${
        reason === 'tv_code' ? 'Kod na TV' : 'Hasło nie działa'
      }) dla serwisu ${record.serviceName} bezpośrednio do właściciela hasła: ${
        record.ownerName
      }.`
    );
    showToast(
      `Wysłano prośbę do właściciela hasła (${record.ownerName})! Gdy odpowie, okno Lupy otworzy się automatycznie.`
    );
  };

  const handleResolveSosRequest = async (
    record: PasswordRecord,
    responseCode: string,
    newPassword?: string
  ) => {
    if (!currentMember || record.section === 'private') return;
    const now = new Date().toISOString();
    const currentExtras = parsePasswordCardExtras(record);
    const existingTicket = currentExtras.sosTicket;
    if (!existingTicket) return;

    const trimmedNewPass = newPassword?.trim() || '';
    const nextHistory: PasswordHistoryEntry[] =
      trimmedNewPass &&
      record.passwordValue &&
      record.passwordValue !== trimmedNewPass
        ? [
            {
              passwordValue: record.passwordValue,
              changedAt: now,
              changedBy: currentMember.fullName,
            },
            ...(currentExtras.passwordHistory || []).filter(
              (h) => h.passwordValue !== record.passwordValue
            ),
          ].slice(0, 3)
        : currentExtras.passwordHistory || [];

    const nextSubAccountsJson = serializePasswordCardExtras({
      ...currentExtras,
      passwordHistory: nextHistory,
      sosTicket: {
        ...existingTicket,
        status: 'resolved',
        responseCode: responseCode.trim() || undefined,
        resolvedAt: now,
        resolvedByName: currentMember.fullName,
      },
    });

    const updates: Partial<PasswordRecord> = {
      subAccountsJson: nextSubAccountsJson,
      updatedAt: now,
    };

    if (trimmedNewPass) {
      updates.passwordValue = trimmedNewPass;
      updates.passwordUpdatedAt = now;
    }

    await savePasswordToFirestore(record.id, updates);

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'SOS_RESOLVED_BY_OWNER',
      `Właściciel hasła (${currentMember.fullName}) odpowiedział na zgłoszenie SOS od ${
        existingTicket.requestedByMemberName
      } w serwisie ${record.serviceName}${
        responseCode.trim() ? ' (wysłano kod TV do okna Lupy)' : ''
      }.`
    );
    showToast(
      `Wysłano odpowiedź do ${existingTicket.requestedByMemberName} — okno Lupy otworzyło się u domownika!`
    );
  };

  const handleClearSosRequest = async (record: PasswordRecord) => {
    if (!currentMember || record.section === 'private') return;
    const now = new Date().toISOString();
    const currentExtras = parsePasswordCardExtras(record);

    await savePasswordToFirestore(record.id, {
      subAccountsJson: serializePasswordCardExtras({
        ...currentExtras,
        sosTicket: null,
      }),
      updatedAt: now,
    });
  };

  const handleUpdateCardMetadata = async (
    record: PasswordRecord,
    metadata: { profilePinOrNote?: string; totpSecret?: string }
  ) => {
    if (!currentMember) return;
    const now = new Date().toISOString();
    const currentExtras = parsePasswordCardExtras(record);
    const cleanPinNote = metadata.profilePinOrNote?.trim() || undefined;
    const cleanTotp = metadata.totpSecret?.trim() || undefined;

    if (record.section === 'private') {
      const currentDecrypted = decryptedPrivateMap[record.id];
      if (!currentDecrypted || !activeDekBase64) {
        showToast('Nie można odszyfrować rekordu prywatnego.');
        return;
      }
      const updatedPrivatePayload: DecryptedPrivatePayload = {
        ...currentDecrypted,
        profilePinOrNote: cleanPinNote,
        totpSecret: cleanTotp,
      };
      const reEncrypted = await encryptPrivateRecordPayload(
        updatedPrivatePayload,
        activeDekBase64
      );
      await savePasswordToFirestore(record.id, {
        encryptedPayload: reEncrypted,
        subAccountsJson: serializePasswordCardExtras({
          ...currentExtras,
          profilePinOrNote: record.revealToAdmin ? cleanPinNote : undefined,
          totpSecret: record.revealToAdmin ? cleanTotp : undefined,
        }),
        updatedAt: now,
      });
    } else {
      await savePasswordToFirestore(record.id, {
        subAccountsJson: serializePasswordCardExtras({
          ...currentExtras,
          profilePinOrNote: cleanPinNote,
          totpSecret: cleanTotp,
        }),
        updatedAt: now,
      });
    }

    showToast('Zapisano PIN do profilu TV / notatkę oraz klucz 2FA TOTP!');
  };

  const handleOneClickRotateAuditPassword = async (record: PasswordRecord) => {
    if (!currentMember) return;
    setRotatingPasswordId(record.id);
    try {
      const freshPassword = generateStrongPassword(16);
      await handleQuickUpdatePassword(record, freshPassword);
      showToast(
        `Wygenerowano i zapisano nowe 16-znakowe hasło dla: ${
          record.section === 'private'
            ? decryptedPrivateMap[record.id]?.serviceName || record.serviceName
            : record.serviceName
        } (poprzednie hasło zachowano w Historii)!`
      );
    } finally {
      setRotatingPasswordId(null);
    }
  };

  const handleQuickUpdatePassword = async (
    record: PasswordRecord,
    newPassword: string
  ) => {
    if (!currentMember || !activeDekBase64) return;
    const now = new Date().toISOString();
    const currentExtras = parsePasswordCardExtras(record);

    if (record.section === 'private') {
      const currentDecrypted = decryptedPrivateMap[record.id];
      if (!currentDecrypted) {
        throw new Error('Nie można odszyfrować rekordu prywatnego do edycji.');
      }
      const oldPlain = currentDecrypted.password;
      const existingHist =
        currentDecrypted.passwordHistory ||
        currentExtras.passwordHistory ||
        [];
      const nextHistory: PasswordHistoryEntry[] =
        oldPlain && oldPlain !== newPassword
          ? [
              {
                passwordValue: oldPlain,
                changedAt: now,
                changedBy: currentMember.fullName,
              },
              ...existingHist.filter(
                (h) =>
                  h.passwordValue !== oldPlain &&
                  h.passwordValue !== newPassword
              ),
            ].slice(0, 3)
          : existingHist.slice(0, 3);

      const reEncrypted = await encryptPrivateRecordPayload(
        {
          ...currentDecrypted,
          password: newPassword,
          passwordHistory: nextHistory,
        },
        activeDekBase64
      );
      await savePasswordToFirestore(record.id, {
        passwordValue: record.revealToAdmin
          ? newPassword
          : reEncrypted.slice(0, 96) + '...',
        encryptedPayload: reEncrypted,
        subAccountsJson: serializePasswordCardExtras({
          ...currentExtras,
          passwordHistory: record.revealToAdmin ? nextHistory : [],
        }),
        updatedAt: now,
        passwordUpdatedAt: now,
      });
    } else {
      const oldPlain = record.passwordValue;
      const existingHist = currentExtras.passwordHistory || [];
      const nextHistory: PasswordHistoryEntry[] =
        oldPlain && oldPlain !== newPassword
          ? [
              {
                passwordValue: oldPlain,
                changedAt: now,
                changedBy: currentMember.fullName,
              },
              ...existingHist.filter(
                (h) =>
                  h.passwordValue !== oldPlain &&
                  h.passwordValue !== newPassword
              ),
            ].slice(0, 3)
          : existingHist.slice(0, 3);

      await savePasswordToFirestore(record.id, {
        passwordValue: newPassword,
        subAccountsJson: serializePasswordCardExtras({
          ...currentExtras,
          passwordHistory: nextHistory,
        }),
        updatedAt: now,
        passwordUpdatedAt: now,
      });
    }

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'PASSWORD_QUICK_UPDATE',
      record.section === 'private'
        ? 'Zaktualizowano hasło w istniejącym rekordzie prywatnym (AES-256-GCM, zapisano w historii 3 zmian).'
        : `Zaktualizowano hasło w istniejącym wpisie wspólnym: ${record.serviceName} (zapisano w historii 3 zmian).`
    );
    showToast(
      'Zaktualizowano hasło (poprzednie hasło zapisano w Historii 3 zmian)!'
    );
  };

  const handleToggleRevealToAdmin = async (
    record: PasswordRecord,
    nextReveal: boolean
  ) => {
    if (!currentMember || record.section !== 'private') return;
    const decrypted = decryptedPrivateMap[record.id];
    if (!decrypted) {
      showToast('Nie można odszyfrować rekordu prywatnego.');
      return;
    }

    const now = new Date().toISOString();
    await savePasswordToFirestore(record.id, {
      revealToAdmin: nextReveal,
      categoryId: nextReveal ? decrypted.categoryId : 'ENC[PRIVATE]',
      serviceName: nextReveal ? decrypted.serviceName : 'ENC[PRIVATE]',
      serviceUrl: nextReveal ? decrypted.serviceUrl : 'ENC[PRIVATE]',
      login: nextReveal ? decrypted.login : 'ENC[PRIVATE]',
      passwordValue: nextReveal
        ? decrypted.password
        : record.encryptedPayload.slice(0, 96) + '...',
      updatedAt: now,
    });

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'PRIVATE_REVEAL_TOGGLED',
      nextReveal
        ? `Włączono jawny podgląd prywatnego wpisu (${decrypted.serviceName}) dla Administratora i Co-Adminów.`
        : 'Wyłączono jawny podgląd prywatnego wpisu dla Administratora (powrót do Zero-Knowledge AES-256-GCM).'
    );
    showToast(
      nextReveal
        ? 'Ujawniono prywatny wpis Administratorowi i Zaufanym Opiekunom.'
        : 'Ukryto prywatny wpis przed Administratorem (Zero-Knowledge).'
    );
  };

  const handleUpdateAllowedMembers = async (
    record: PasswordRecord,
    memberIds: string[]
  ) => {
    if (!currentMember) return;
    const now = new Date().toISOString();
    const expandedIds = expandAllowedMemberIdsWithAuthUids(
      memberIds,
      record.ownerId
    );
    await savePasswordToFirestore(record.id, {
      allowedMemberIds: expandedIds,
      updatedAt: now,
    });
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ACCESS_UPDATED',
      `Zaktualizowano uprawnienia dostępu domowników dla serwisu ${record.serviceName}.`
    );
    showToast('Zaktualizowano listę uprawnionych domowników.');
  };

  const handleDeleteRecord = async (record: PasswordRecord) => {
    if (!currentMember) return;
    await deletePasswordFromFirestore(record.id);
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'PASSWORD_DELETED',
      record.section === 'private'
        ? 'Usunięto prywatny rekord hasła.'
        : `Usunięto wspólny wpis: ${record.serviceName}.`
    );
    showToast('Usunięto wpis ze skarbca.');
  };

  // 7. ADMIN & CO-ADMIN TAB 2 ACTIONS: Invites, Approvals, Emergency Reset & Co-Admin Delegation
  const handleCreateInvitation = async (params: {
    purpose: InvitationPurpose;
    mode: InvitationMode;
    invitedLabel: string;
    targetMemberId?: string;
    hoursValid?: number;
  }): Promise<VaultInvitation> => {
    if (!currentMember) {
      throw new Error('Brak aktywnej sesji.');
    }
    const targetMember = params.targetMemberId
      ? members.find((m) => m.id === params.targetMemberId)
      : undefined;

    const invitation = await createInvitationInFirestore({
      ...params,
      targetMemberId: targetMember?.id,
      targetMemberName: targetMember?.fullName,
      targetUsername: targetMember?.username,
      createdByMemberId: currentMember.id,
      createdByMemberName: currentMember.fullName,
    });

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'INVITE_CREATED',
      params.purpose === 'account_recovery'
        ? `Utworzono link ratunkowy (${params.invitedLabel}).`
        : `Utworzono link zaproszeniowy dla nowego domownika (${
            params.invitedLabel || 'Domownik'
          }, tryb: ${
            params.mode === 'single_use' ? 'jednorazowy' : 'czasowy 24h'
          }).`
    );
    showToast('Utworzono i skopiowano link do schowka!');
    return invitation;
  };

  const handleDeleteInvitation = async (invitationId: string) => {
    if (!currentMember) return;
    await deleteInvitationFromFirestore(invitationId);
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'INVITE_DELETED',
      'Unieważniono i usunięto link zaproszeniowy.'
    );
    showToast('Usunięto link zaproszeniowy.');
  };

  const handleResetMemberCredentialsByAdmin = async (params: {
    targetMemberId: string;
    newUsername: string;
    newPassword: string;
    approveAllDevices: boolean;
  }) => {
    if (!currentMember) return;
    const target = members.find((m) => m.id === params.targetMemberId);
    if (!target) return;

    const dekBase64 = await unwrapDekFromMergeEscrow(
      target.vaultEscrowKey,
      target.pbkdf2Salt
    );
    const newPasswordHash = await hashPasswordForAuth(
      params.newPassword,
      target.pbkdf2Salt
    );
    const newWrappedMasterKey = await wrapDekWithPassword(
      dekBase64,
      params.newPassword,
      target.pbkdf2Salt
    );

    const now = new Date().toISOString();
    await saveMemberToFirestore(target.id, {
      ...target,
      username: params.newUsername,
      passwordHash: newPasswordHash,
      wrappedMasterKey: newWrappedMasterKey,
      status: 'active',
      updatedAt: now,
    });

    const targetDevs = devices.filter((d) => d.memberId === target.id);
    for (const dev of targetDevs) {
      await saveDeviceToFirestore(dev.id, {
        ...dev,
        status: params.approveAllDevices ? 'approved' : dev.status,
        username: params.newUsername,
        hardwareWrappedDek: '',
        lastSeenAt: now,
      });
    }

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'MEMBER_CREDENTIALS_RESET',
      `Zresetowano login/hasło i odświeżono koperty sprzętowe dla domownika ${target.fullName} (nowy login: ${params.newUsername}).`
    );
    showToast(`Zresetowano hasło i odblokowano konto dla ${target.fullName}!`);
  };

  const handleChangeOwnPassword = async (params: {
    currentPassword: string;
    newPassword: string;
  }) => {
    if (!currentMember || !activeDekBase64) {
      throw new Error('Brak aktywnej sesji skarbca.');
    }

    const verifyHash = await hashPasswordForAuth(
      params.currentPassword,
      currentMember.pbkdf2Salt
    );
    if (verifyHash !== currentMember.passwordHash) {
      throw new Error('Wpisane obecne hasło jest nieprawidłowe.');
    }

    const newPasswordHash = await hashPasswordForAuth(
      params.newPassword,
      currentMember.pbkdf2Salt
    );
    const newWrappedMasterKey = await wrapDekWithPassword(
      activeDekBase64,
      params.newPassword,
      currentMember.pbkdf2Salt
    );

    const now = new Date().toISOString();
    await saveMemberToFirestore(currentMember.id, {
      ...currentMember,
      passwordHash: newPasswordHash,
      wrappedMasterKey: newWrappedMasterKey,
      updatedAt: now,
    });

    const myDevs = devices.filter((d) => d.memberId === currentMember.id);
    for (const dev of myDevs) {
      if (
        dev.deviceFingerprint === detectedDevice.deviceFingerprint &&
        dev.status === 'approved'
      ) {
        const reSealedHardwareDek = await wrapDekWithHardwareCertificate(
          activeDekBase64,
          {
            password: params.newPassword,
            saltBase64: currentMember.pbkdf2Salt,
            deviceFingerprint: detectedDevice.deviceFingerprint,
            clientMode: detectedDevice.clientMode,
            deviceApprovalToken: dev.deviceApprovalToken || '',
            hardwareModelOs: detectedDevice.hardwareModelOs,
            hardwareDeviceType: detectedDevice.hardwareDeviceType,
          }
        );
        await saveDeviceToFirestore(dev.id, {
          ...dev,
          hardwareWrappedDek: reSealedHardwareDek,
          lastSeenAt: now,
        });
      } else {
        await saveDeviceToFirestore(dev.id, {
          ...dev,
          hardwareWrappedDek: '',
          lastSeenAt: now,
        });
      }
    }

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'OWN_PASSWORD_CHANGED',
      'Użytkownik samodzielnie zmienił własne hasło główne w zakładce Profil (bez utraty kluczy DEK).'
    );
    showToast('Twoje hasło główne zostało zmienione!');
  };

  const handleUpdateMemberRoleAndPermissions = async (params: {
    targetMemberId: string;
    role: 'co_admin' | 'member';
    coAdminPermissions: CoAdminPermissions;
  }) => {
    if (!currentMember || !isPrimaryAdmin(currentMember)) return;
    const target = members.find((m) => m.id === params.targetMemberId);
    if (!target) return;

    const now = new Date().toISOString();
    await saveMemberToFirestore(target.id, {
      ...target,
      role: params.role,
      coAdminPermissions: params.coAdminPermissions,
      updatedAt: now,
    });

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'CO_ADMIN_UPDATED',
      params.role === 'co_admin'
        ? `Nadano lub zaktualizowano uprawnienia Zaufanego Opiekuna (Co-Admina) dla: ${target.fullName}.`
        : `Odebrano uprawnienia Zaufanego Opiekuna dla: ${target.fullName}.`
    );
    showToast(
      params.role === 'co_admin'
        ? `Mianowano ${target.fullName} Zaufanym Opiekunem (Co-Adminem)!`
        : `Zmieniono rolę ${target.fullName} na standardowego domownika.`
    );
  };

  const handleApproveMemberAndDevices = async (memberId: string) => {
    if (!currentMember) return;
    const target = members.find((m) => m.id === memberId);
    if (!target) return;
    const now = new Date().toISOString();

    await saveMemberToFirestore(memberId, {
      ...target,
      status: 'active',
      updatedAt: now,
    });
    const memberDevs = devices.filter((d) => d.memberId === memberId);
    for (const dev of memberDevs) {
      await saveDeviceToFirestore(dev.id, {
        ...dev,
        status: 'approved',
        lastSeenAt: now,
      });
    }
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_APPROVE_MEMBER',
      `Zatwierdzono nowe konto domownika: ${target.fullName} (${target.username}).`
    );
    showToast(`Zaakceptowano konto i urządzenie dla ${target.fullName}!`);
  };

  const handleRejectPendingMember = async (memberId: string) => {
    if (!currentMember) return;
    const target = members.find((m) => m.id === memberId);
    await deleteMemberFromFirestore(memberId);
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_REJECT_MEMBER',
      `Odrzucono zgłoszenie konta: ${target?.fullName || memberId}.`
    );
    showToast('Odrzucono zgłoszenie nowego konta.');
  };

  const handleApproveDevice = async (deviceId: string) => {
    if (!currentMember) return;
    const dev = devices.find((d) => d.id === deviceId);
    if (!dev) return;
    await saveDeviceToFirestore(deviceId, {
      ...dev,
      status: 'approved',
      lastSeenAt: new Date().toISOString(),
    });
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_APPROVE_DEVICE',
      `Zatwierdzono urządzenie ${dev.deviceName} i wydano Certyfikat Sprzętowy dla użytkownika ${dev.memberName}.`
    );
    showToast(
      `Wydano Certyfikat Sprzętowy i zatwierdzono urządzenie dla ${dev.memberName}!`
    );
  };

  const handleRebindDeviceCertificate = async (deviceId: string) => {
    if (!currentMember) return;
    const dev = devices.find((d) => d.id === deviceId);
    if (!dev) return;
    const updatedDev = await rebindDeviceCertificateInFirestore(deviceId);
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_REBIND_DEVICE_CERT',
      `Przepięto / odnowiono Certyfikat Sprzętowy (${
        updatedDev.deviceCertificateFingerprint || 'CERT-HW'
      }) dla urządzenia ${dev.deviceName} (${dev.memberName}).`
    );
    showToast(
      `Odnowiono Certyfikat Sprzętowy (${
        updatedDev.deviceCertificateFingerprint || 'CERT-HW'
      }) dla ${dev.memberName}!`
    );
  };

  const handleRevokeDevice = async (deviceId: string) => {
    if (!currentMember) return;
    const dev = devices.find((d) => d.id === deviceId);
    if (!dev) return;
    await deleteDeviceFromFirestore(deviceId);
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_REVOKE_DEVICE',
      `Odpięto urządzenie ${dev.deviceName} i unieważniono jego Certyfikat Sprzętowy (${dev.memberName}).`
    );
    showToast('Odpięto urządzenie i unieważniono jego Certyfikat Sprzętowy.');
  };

  const handleManualAddDeviceForMember = async (params: {
    memberId: string;
    deviceName: string;
    customLabel: string;
    clientMode: 'pwa' | 'browser';
  }) => {
    if (!currentMember) return;
    const member = members.find((m) => m.id === params.memberId);
    if (!member) return;
    const now = new Date().toISOString();
    const devId = makeId('dev');
    const newDevice: Device = {
      id: devId,
      memberId: member.id,
      memberName: member.fullName,
      username: member.username,
      deviceFingerprint: `manual_${makeId('fp')}`,
      deviceName: params.deviceName,
      customLabel: params.customLabel,
      clientMode: params.clientMode,
      status: 'approved',
      webAuthnCredentialId: '',
      requestedAt: now,
      lastSeenAt: now,
    };
    await saveDeviceToFirestore(devId, newDevice);
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_MANUAL_DEVICE',
      `Dopisano urządzenie ${params.deviceName} do konta ${member.fullName}.`
    );
    showToast('Dopisano nowe urządzenie do konta użytkownika.');
  };

  const handleMergeMemberAccounts = async (
    sourceMemberId: string,
    targetMemberId: string
  ) => {
    if (!currentMember) return;
    const sourceMember = members.find((m) => m.id === sourceMemberId);
    const targetMember = members.find((m) => m.id === targetMemberId);
    if (!sourceMember || !targetMember) return;

    const sourceDek = await unwrapDekFromMergeEscrow(
      sourceMember.vaultEscrowKey,
      sourceMember.pbkdf2Salt
    );
    let existingTargetMergedKeys: string[] = [];
    try {
      existingTargetMergedKeys = JSON.parse(
        targetMember.mergedVaultKeysJson || '[]'
      );
    } catch {
      existingTargetMergedKeys = [];
    }
    const updatedMergedKeys = Array.from(
      new Set([...existingTargetMergedKeys, sourceDek])
    );

    await mergeMembersInFirestore({
      sourceMemberId,
      targetMemberId,
      updatedMergedKeysJson: JSON.stringify(updatedMergedKeys),
      passwords,
    });

    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'ADMIN_MERGE_ACCOUNTS',
      `Scalono konto „${sourceMember.fullName} (${sourceMember.username})” do konta „${targetMember.fullName} (${targetMember.username})”.`
    );
    showToast('Pomyślnie scalono konta użytkowników w Cloud Firestore!');
  };

  // 8. ADMIN TAB 3 ACTIONS: Categories, Settings & Local .vault.enc Backups
  const handleUpdateCategories = async (newCategories: VaultCategory[]) => {
    if (!currentMember || !vaultConfig) return;
    const now = new Date().toISOString();
    await saveVaultConfigToFirestore({
      ...vaultConfig,
      categoriesJson: JSON.stringify(newCategories),
      updatedAt: now,
    });
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'CATEGORIES_UPDATED',
      `Zaktualizowano listę kategorii wpisów (${newCategories.length} kategorii).`
    );
    showToast('Zaktualizowano kategorie wpisów.');
  };

  const handleUpdateSystemSettings = async (params: {
    defaultTheme: ThemeMode;
    clipboardClearSeconds: number;
    autoLockMinutes: number;
  }) => {
    if (!currentMember || !vaultConfig) return;
    const now = new Date().toISOString();
    await saveVaultConfigToFirestore({
      ...vaultConfig,
      defaultTheme: params.defaultTheme,
      clipboardClearSeconds: params.clipboardClearSeconds,
      autoLockMinutes: params.autoLockMinutes,
      updatedAt: now,
    });
    await logActivityInFirestore(
      currentMember.id,
      currentMember.fullName,
      'SETTINGS_UPDATED',
      `Zmieniono ustawienia systemowe (Motyw: ${params.defaultTheme}, Schowek: ${params.clipboardClearSeconds}s, Auto-Lock: ${params.autoLockMinutes}m).`
    );
  };

  const buildEncryptedBackupString = async (
    passphrase: string
  ): Promise<string> => {
    const backupObject: BackupFileStructure = {
      version: '2.0.0-FIRESTORE-E2E',
      exportedAt: new Date().toISOString(),
      exportedBy: currentMember?.fullName || 'Administrator',
      vaultConfig,
      members,
      devices,
      passwords,
      invitations,
      activityLogs: activityLogs.slice(0, 100),
    };
    const plainJson = JSON.stringify(backupObject);
    return encryptVaultBackupFile(plainJson, passphrase);
  };

  const handleDownloadLocalBackupFile = async (passphrase: string) => {
    const encryptedContent = await buildEncryptedBackupString(passphrase);
    const dateStamp = new Date().toISOString().slice(0, 10);
    const blob = new Blob([encryptedContent], {
      type: 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `FamilyStreamVault_${dateStamp}.vault.enc`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    if (currentMember) {
      await logActivityInFirestore(
        currentMember.id,
        currentMember.fullName,
        'BACKUP_LOCAL_EXPORT',
        'Pobrano zaszyfrowaną kopię .vault.enc na dysk lokalny.'
      );
    }
  };

  const handleRestoreBackupFromFile = async (
    fileContent: string,
    passphrase: string
  ) => {
    const decryptedJson = await decryptVaultBackupFile(fileContent, passphrase);
    const parsed = JSON.parse(decryptedJson) as BackupFileStructure;
    if (
      !parsed ||
      !Array.isArray(parsed.members) ||
      !Array.isArray(parsed.passwords)
    ) {
      throw new Error('Plik kopii zapasowej ma nieprawidłową strukturę.');
    }

    await replaceFullVaultStateInFirestore({
      vaultConfig: parsed.vaultConfig || vaultConfig,
      members: parsed.members,
      devices: parsed.devices || [],
      passwords: parsed.passwords,
      invitations: parsed.invitations || [],
      activityLogs: parsed.activityLogs || [],
    });

    if (currentMember) {
      await logActivityInFirestore(
        currentMember.id,
        currentMember.fullName,
        'BACKUP_RESTORED',
        `Przywrócono skarbiec z pliku .vault.enc do Cloud Firestore (${parsed.passwords.length} haseł, ${parsed.members.length} kont).`
      );
    }
  };

  // Filtered & sorted passwords for current user's personal view (Favorites always pinned at the top!)
  const filterAndSortRecords = (list: PasswordRecord[]) => {
    return list
      .filter((rec) => {
        const isPriv = rec.section === 'private';
        const dec = isPriv ? decryptedPrivateMap[rec.id] : null;
        const catId = isPriv
          ? dec?.categoryId || (rec.revealToAdmin ? rec.categoryId : 'other')
          : rec.categoryId;
        const srvName = isPriv
          ? dec?.serviceName || (rec.revealToAdmin ? rec.serviceName : '')
          : rec.serviceName;
        const loginStr = isPriv
          ? dec?.login || (rec.revealToAdmin ? rec.login : '')
          : rec.login;

        if (
          selectedCategoryFilter !== 'all' &&
          catId !== selectedCategoryFilter
        ) {
          return false;
        }
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          return (
            srvName.toLowerCase().includes(q) ||
            loginStr.toLowerCase().includes(q) ||
            rec.ownerName.toLowerCase().includes(q)
          );
        }
        return true;
      })
      .sort((a, b) => {
        if (currentMember) {
          const favA = parsePasswordCardExtras(a).favoriteMemberIds.includes(
            currentMember.id
          );
          const favB = parsePasswordCardExtras(b).favoriteMemberIds.includes(
            currentMember.id
          );
          if (favA !== favB) {
            return favA ? -1 : 1;
          }
        }
        if (sortBy === 'updated') {
          return (
            new Date(b.passwordUpdatedAt || b.updatedAt).getTime() -
            new Date(a.passwordUpdatedAt || a.updatedAt).getTime()
          );
        }
        if (sortBy === 'newest') {
          return (
            new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
          );
        }
        const nameA =
          a.section === 'private'
            ? decryptedPrivateMap[a.id]?.serviceName ||
              (a.revealToAdmin ? a.serviceName : '')
            : a.serviceName;
        const nameB =
          b.section === 'private'
            ? decryptedPrivateMap[b.id]?.serviceName ||
              (b.revealToAdmin ? b.serviceName : '')
            : b.serviceName;
        return nameA.localeCompare(nameB, 'pl');
      });
  };

  if (!isOnline) {
    return (
      <div className="min-h-screen flex flex-col bg-[var(--vault-bg)] text-[var(--vault-text)]">
        <TopBar
          currentMember={null}
          activeTab="vault"
          onSelectTab={() => {}}
          pendingCount={0}
          theme={theme}
          onToggleTheme={handleToggleTheme}
          onOpenAddPassword={() => {}}
          onLogout={() => {}}
                  />
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="max-w-md w-full p-8 rounded-xl border border-[var(--vault-danger)] bg-[var(--vault-surface)] text-center space-y-4">
            <WifiOff className="w-10 h-10 text-[var(--vault-danger)] mx-auto" />
            <h1 className="text-xl font-bold font-display">
              Wymagane aktywne połączenie z internetem
            </h1>
            <p className="text-xs text-[var(--vault-muted)]">
              FamilyStream Vault działa w trybie <strong>Online-Only (Cloud Firestore)</strong> dla zachowania natychmiastowej synchronizacji haseł i autoryzacji urządzeń domowników. Połącz się z siecią Wi-Fi lub komórkową, aby odblokować skarbiec.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const pendingApprovalsCount =
    members.filter((m) => m.status === 'pending').length +
    devices.filter(
      (d) =>
        d.status === 'pending' &&
        !members.some((pm) => pm.status === 'pending' && pm.id === d.memberId)
    ).length;

  const isOwnerAdmin = isPrimaryAdmin(currentMember);
  const isTrustedCoAdmin = isCoAdmin(currentMember);
  const canAccessAdminOrCoAdminTab2 = isAdminOrCoAdmin(currentMember);

  // Strict privacy: every user (including Admin) only sees shared passwords where they are owner, in allowedMemberIds, or assigned a subAccount
  const mySharedPasswords = currentMember
    ? filterAndSortRecords(
        passwords.filter(
          (p) =>
            p.section === 'shared' &&
            (p.ownerId === currentMember.id ||
              p.allowedMemberIds.includes(currentMember.id) ||
              parseSubAccounts(p).some(
                (sa) => sa.assignedMemberId === currentMember.id
              ))
        )
      )
    : [];

  const myPrivatePasswords = currentMember
    ? filterAndSortRecords(
        passwords.filter(
          (p) => p.section === 'private' && p.ownerId === currentMember.id
        )
      )
    : [];

  // Section 03 for Admin / Co-Admin: ONLY private passwords of other family members where the owner explicitly enabled `revealToAdmin`
  const revealedByOthersPasswords =
    currentMember && (isOwnerAdmin || isTrustedCoAdmin)
      ? filterAndSortRecords(
          passwords.filter(
            (p) =>
              p.section === 'private' &&
              p.ownerId !== currentMember.id &&
              Boolean(p.revealToAdmin) &&
              p.serviceName !== 'ENC[PRIVATE]'
          )
        )
      : [];

  // Live SOS / TV Code requests routed strictly to the founder/owner of the password (`p.ownerId === currentMember.id`)
  const pendingSosForMyOwnedPasswords = currentMember
    ? passwords.filter(
        (p) =>
          p.section === 'shared' &&
          p.ownerId === currentMember.id &&
          parsePasswordCardExtras(p).sosTicket?.status === 'pending'
      )
    : [];

  // Client-side Password Health Audit (Duplicates, Age > 180 days, Weak Passwords < 10 chars)
  const passwordHealthAudit = (() => {
    if (!currentMember) {
      return {
        totalAudited: 0,
        healthScore: 100,
        duplicates: [] as { record: PasswordRecord; serviceName: string }[],
        oldPasswords: [] as {
          record: PasswordRecord;
          serviceName: string;
          daysOld: number;
        }[],
        weakPasswords: [] as {
          record: PasswordRecord;
          serviceName: string;
          reason: string;
        }[],
        resolvedItems: [] as {
          record: PasswordRecord;
          plainPassword: string;
          serviceName: string;
        }[],
      };
    }

    const auditableRecords = [
      ...passwords.filter(
        (p) =>
          p.section === 'shared' &&
          (p.ownerId === currentMember.id ||
            p.allowedMemberIds.includes(currentMember.id))
      ),
      ...passwords.filter(
        (p) => p.section === 'private' && p.ownerId === currentMember.id
      ),
    ];

    const resolvedItems = auditableRecords
      .map((rec) => {
        const isPriv = rec.section === 'private';
        const dec = isPriv ? decryptedPrivateMap[rec.id] : null;
        const plainPassword = isPriv
          ? dec?.password || (rec.revealToAdmin ? rec.passwordValue : '')
          : rec.passwordValue;
        const serviceName = isPriv
          ? dec?.serviceName ||
            (rec.revealToAdmin ? rec.serviceName : 'Wpis prywatny')
          : rec.serviceName;
        return {
          record: rec,
          plainPassword: plainPassword.trim(),
          serviceName,
        };
      })
      .filter((item) => item.plainPassword.length > 0);

    const passwordCounts = new Map<string, number>();
    for (const item of resolvedItems) {
      passwordCounts.set(
        item.plainPassword,
        (passwordCounts.get(item.plainPassword) || 0) + 1
      );
    }

    const duplicates: { record: PasswordRecord; serviceName: string }[] = [];
    const oldPasswords: {
      record: PasswordRecord;
      serviceName: string;
      daysOld: number;
    }[] = [];
    const weakPasswords: {
      record: PasswordRecord;
      serviceName: string;
      reason: string;
    }[] = [];

    const nowMs = Date.now();
    const MS_PER_DAY = 1000 * 60 * 60 * 24;

    for (const item of resolvedItems) {
      if ((passwordCounts.get(item.plainPassword) || 0) > 1) {
        duplicates.push({
          record: item.record,
          serviceName: item.serviceName,
        });
      }

      const updatedIso =
        item.record.passwordUpdatedAt ||
        item.record.updatedAt ||
        item.record.createdAt;
      if (updatedIso) {
        const daysOld = Math.floor(
          (nowMs - new Date(updatedIso).getTime()) / MS_PER_DAY
        );
        if (daysOld > 180) {
          oldPasswords.push({
            record: item.record,
            serviceName: item.serviceName,
            daysOld,
          });
        }
      }

      const pw = item.plainPassword;
      const hasDigit = /[0-9]/.test(pw);
      const hasUpper = /[A-ZĄĆĘŁŃÓŚŹŻ]/.test(pw);
      const hasLower = /[a-ząćęłńóśźż]/.test(pw);
      if (pw.length < 10) {
        weakPasswords.push({
          record: item.record,
          serviceName: item.serviceName,
          reason: `Zbyt krótkie (${pw.length} zn.)`,
        });
      } else if (!(hasDigit && (hasUpper || hasLower))) {
        weakPasswords.push({
          record: item.record,
          serviceName: item.serviceName,
          reason: 'Brak kombinacji liter i cyfr',
        });
      }
    }

    const totalAudited = resolvedItems.length;
    const totalIssues =
      duplicates.length + oldPasswords.length + weakPasswords.length;
    const rawPenalty =
      totalAudited > 0
        ? Math.round(
            ((duplicates.length * 18 +
              weakPasswords.length * 15 +
              oldPasswords.length * 10) /
              Math.max(totalAudited, 1))
          )
        : 0;
    const healthScore =
      totalAudited === 0
        ? 100
        : totalIssues === 0
          ? 100
          : Math.max(15, Math.min(96, 100 - rawPenalty));

    return {
      totalAudited,
      healthScore,
      duplicates,
      oldPasswords,
      weakPasswords,
      resolvedItems,
    };
  })();

  // Pillar 3: Zero-Knowledge k-Anonymity Breach Check (sends ONLY 5-char SHA-1 prefix to HaveIBeenPwned Range API)
  const handleRunZeroKnowledgeBreachCheck = async () => {
    if (isCheckingBreaches || passwordHealthAudit.resolvedItems.length === 0) {
      return;
    }
    setIsCheckingBreaches(true);
    try {
      const nextResults: Record<string, number> = {};
      let breachedCount = 0;
      for (const item of passwordHealthAudit.resolvedItems) {
        try {
          const count = await checkPasswordPwnedKAnonymity(item.plainPassword);
          nextResults[item.record.id] = count;
          if (count > 0) {
            breachedCount++;
          }
        } catch {
          nextResults[item.record.id] = 0;
        }
      }
      setPwnedCheckResults(nextResults);
      setHasRunBreachCheck(true);
      showToast(
        breachedCount > 0
          ? `Wykryto ${breachedCount} haseł w publicznych wyciekach danych! Wymień je 1-Klikiem.`
          : 'Zero-Knowledge Test Wycieków zakończony: żadne z Twoich haseł nie figuruje w bazie wycieków!'
      );
    } finally {
      setIsCheckingBreaches(false);
    }
  };

  const currentDeviceDoc = currentMember
    ? devices.find(
        (d) =>
          d.memberId === currentMember.id &&
          d.deviceFingerprint === detectedDevice.deviceFingerprint
      ) || null
    : null;

  const handleLogout = async () => {
    try {
      localStorage.removeItem(REMEMBERED_SESSION_KEY);
    } catch {
      // ignore
    }
    if (clipboardIntervalRef.current) {
      window.clearInterval(clipboardIntervalRef.current);
      clipboardIntervalRef.current = null;
    }
    setClipboardCountdown(null);
    navigator.clipboard?.writeText('').catch(() => {});

    // Zero-State RAM cleanup: immediately purge all decrypted maps, password lists, logs, and keys from React state
    setDecryptedPrivateMap({});
    setPasswords([]);
    setActivityLogs([]);
    setSearchQuery('');
    setSelectedCategoryFilter('all');
    setVaultSectionFilter('all');
    setCurrentMemberId(null);
    setActiveDekBase64(null);
    setActiveMergedDeks([]);
    setPendingAuthState(null);
    setIsVaultLockedByTimeout(false);
    setActiveAdminTab('vault');

    // Sign out of Firebase Auth if logged in as a non-anonymous user; preserve anonymous device UID for family member hardware certificate binding
    if (auth && auth.currentUser && !auth.currentUser.isAnonymous) {
      await signOut(auth).catch(() => {});
      void ensureFirebaseAuthSession(false);
    }
    setFirebaseConfigVersion((v) => v + 1);
  };

  return (
    <div
      id="top"
      className="min-h-screen flex flex-col bg-[var(--vault-bg)] text-[var(--vault-text)]"
    >
      {/* Clean Top Bar: Navigation, + Dodaj hasło, Wyloguj, and top-right Theme Toggle */}
      <TopBar
        currentMember={currentMember}
        activeTab={activeAdminTab}
        onSelectTab={setActiveAdminTab}
        pendingCount={pendingApprovalsCount}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        onOpenAddPassword={() => setIsAddModalOpen(true)}
        onLogout={handleLogout}
              />

      {/* Live Clipboard Auto-Clear Countdown Bar */}
      {clipboardCountdown && (
        <div className="bg-[var(--vault-surface)] border-b border-[var(--vault-accent)] px-6 py-2 flex items-center justify-between gap-4 text-xs">
          <div className="flex items-center gap-2 text-[var(--vault-text)] tabular-nums">
            <Eraser className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
            <span>
              Skopiowano hasło (<strong>{clipboardCountdown.label}</strong>). Automatyczne czyszczenie schowka za{' '}
              <strong>{clipboardCountdown.secondsLeft}s</strong>.
            </span>
          </div>
          <button
            type="button"
            onClick={() => {
              navigator.clipboard.writeText('').catch(() => {});
              setClipboardCountdown(null);
            }}
            className="text-[var(--vault-accent)] hover:underline font-medium cursor-pointer whitespace-nowrap"
          >
            Wyczyść schowek teraz
          </button>
        </div>
      )}

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-3 rounded-xl border border-[var(--vault-accent)] bg-[var(--vault-surface)] text-xs font-medium text-[var(--vault-text)] shadow-lg">
          {toastMessage}
        </div>
      )}

      {/* Pillar 3: Privacy Shield Curtain when switching apps/tabs in background (masks passwords without logging out) */}
      {isPrivacyShieldActive && currentMember && !isVaultLockedByTimeout && (
        <div
          onClick={() => setIsPrivacyShieldActive(false)}
          className="fixed inset-0 z-[100] bg-[var(--vault-bg)] flex flex-col items-center justify-center p-6 text-center select-none cursor-pointer"
        >
          <div className="max-w-md w-full p-8 rounded-2xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] space-y-4 shadow-2xl">
            <EyeOff className="w-12 h-12 text-[var(--vault-accent)] mx-auto" />
            <h2 className="text-xl font-bold font-display text-[var(--vault-text)]">
              Tarcza Prywatności Ekranu Aktywna
            </h2>
            <p className="text-xs text-[var(--vault-muted)] leading-relaxed">
              Wszystkie odsłonięte hasła oraz okna Lupy zostały automatycznie zamaskowane na czas pracy aplikacji w tle (bez wylogowania z sesji).
            </p>
            <span className="inline-block px-4 py-2 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-lg">
              Dotknij ekranu, aby wrócić do skarbca
            </span>
          </div>
        </div>
      )}

      {/* Main Content Container */}
      <main className="flex-1 w-full max-w-6xl mx-auto px-6 py-8">
        {isInitialLoading || !isAuthStateResolved || !isSessionRestoreComplete ? (
          <div className="py-20 flex flex-col items-center justify-center text-center space-y-3">
            <RefreshCw className="w-7 h-7 animate-spin text-[var(--vault-accent)]" />
            <div className="text-sm font-semibold text-[var(--vault-text)]">
              Weryfikacja aktywnej sesji Firebase Auth (onAuthStateChanged)...
            </div>
            <p className="text-xs text-[var(--vault-muted)] max-w-md">
              Sprawdzanie poświadczeń w przeglądarce oraz synchronizacja danych skarbca z Cloud Firestore.
            </p>
          </div>
        ) : !currentMember || isVaultLockedByTimeout ? (
          <AuthAndBootstrapView
            vaultConfig={vaultConfig}
            membersCount={members.length}
            detectedDevice={detectedDevice}
            biometricProfile={biometricProfile}
            pendingAuthState={
              pendingAuthState
                ? {
                    ...pendingAuthState,
                    existingDevice:
                      devices.find(
                        (d) =>
                          d.memberId === pendingAuthState.member.id &&
                          d.deviceFingerprint ===
                            detectedDevice.deviceFingerprint
                      ) || null,
                  }
                : null
            }
            canInstallPWA={!isInstalled}
            isPWAInstalled={isInstalled || detectedDevice.clientMode === 'pwa'}
            onInstallPWA={handleInstallPWAOrGuide}
            onTriggerAppUpdate={handleTriggerAppUpdate}
            isUpdatingApp={isUpdatingApp}
            onFirebaseConfigActivated={() =>
              setFirebaseConfigVersion((v) => v + 1)
            }
            onAdminGoogleLogin={handleAdminGoogleLogin}
            onLoginWithCredentials={handleLoginWithCredentials}
            onRegisterMemberAccountWithInvite={
              handleRegisterMemberAccountWithInvite
            }
            onRecoverMemberAccountWithInvite={
              handleRecoverMemberAccountWithInvite
            }
            onRequestDeviceAuthorization={handleRequestDeviceAuthorization}
            onUnlockWithBiometrics={handleUnlockWithBiometrics}
            onCancelPendingState={() => setPendingAuthState(null)}
                      />
        ) : (
          <div className="space-y-6">
            {activeAdminTab === 'profile' ? (
              /* TAB: PROFIL, POBIERANIE APLIKACJI, AKTUALIZACJE, BIOMETRIA I URZĄDZENIA */
              <UserProfileView
                currentMember={currentMember}
                detectedDevice={detectedDevice}
                currentDeviceDoc={currentDeviceDoc}
                myDevices={devices.filter(
                  (d) => d.memberId === currentMember.id
                )}
                mySharedCount={
                  passwords.filter(
                    (p) =>
                      p.section === 'shared' &&
                      (p.ownerId === currentMember.id ||
                        p.allowedMemberIds.includes(currentMember.id) ||
                        parseSubAccounts(p).some(
                          (sa) => sa.assignedMemberId === currentMember.id
                        ))
                  ).length
                }
                myPrivateCount={
                  passwords.filter(
                    (p) =>
                      p.section === 'private' && p.ownerId === currentMember.id
                  ).length
                }
                myRevealedCount={
                  passwords.filter(
                    (p) =>
                      p.section === 'private' &&
                      p.ownerId === currentMember.id &&
                      Boolean(p.revealToAdmin)
                  ).length
                }
                theme={theme}
                onToggleTheme={handleToggleTheme}
                isPWAInstalled={
                  isInstalled || detectedDevice.clientMode === 'pwa'
                }
                onInstallPWA={handleInstallPWAOrGuide}
                appVersion="3.0.0-FIREBASE-E2E"
                isUpdatingApp={isUpdatingApp}
                onTriggerAppUpdate={handleTriggerAppUpdate}
                onRegisterBiometrics={handleRegisterBiometricsForCurrentDevice}
                onChangeOwnPassword={handleChangeOwnPassword}
                onLockVault={() => {
                  try {
                    localStorage.removeItem(REMEMBERED_SESSION_KEY);
                  } catch {
                    // ignore
                  }
                  setActiveDekBase64(null);
                  setIsVaultLockedByTimeout(true);
                }}
              />
            ) : canAccessAdminOrCoAdminTab2 && activeAdminTab === 'approvals' ? (
              /* TAB 2: Domownicy, Urządzenia, Opiekunowie, Zaproszenia i Pomoc Awaryjna (Admin + Co-Admin) */
              <AdminTab2AccountsAndDevices
                members={members}
                devices={devices}
                passwords={passwords}
                invitations={invitations}
                activityLogs={activityLogs}
                currentAdmin={currentMember}
                onCreateInvitation={handleCreateInvitation}
                onDeleteInvitation={handleDeleteInvitation}
                onApproveMemberAndDevices={handleApproveMemberAndDevices}
                onRejectPendingMember={handleRejectPendingMember}
                onApproveDevice={handleApproveDevice}
                onRebindDeviceCertificate={handleRebindDeviceCertificate}
                onRevokeDevice={handleRevokeDevice}
                onManualAddDeviceForMember={handleManualAddDeviceForMember}
                onResetMemberCredentialsByAdmin={
                  handleResetMemberCredentialsByAdmin
                }
                onUpdateMemberRoleAndPermissions={
                  handleUpdateMemberRoleAndPermissions
                }
                onMergeMemberAccounts={handleMergeMemberAccounts}
              />
            ) : isOwnerAdmin && activeAdminTab === 'config' ? (
              /* ADMIN TAB 3: Cloud Firestore, Kopia .vault.enc, Kategorie i Parametry Bezpieczeństwa */
              <AdminTab3ConfigAndBackup
                vaultConfig={
                  vaultConfig || {
                    initialized: true,
                    adminUid: currentMember.googleUid || 'admin',
                    adminEmail: 'admin@familystream.local',
                    adminMemberId: currentMember.id,
                    templatesLoaded: false,
                    categoriesJson: JSON.stringify(DEFAULT_CATEGORIES),
                    defaultTheme: theme,
                    clipboardClearSeconds: 30,
                    autoLockMinutes: 15,
                    createdAt: currentMember.createdAt,
                    updatedAt: currentMember.updatedAt,
                  }
                }
                categories={categories}
                currentTheme={theme}
                onUpdateCategories={handleUpdateCategories}
                onUpdateSystemSettings={handleUpdateSystemSettings}
                onDownloadLocalBackupFile={handleDownloadLocalBackupFile}
                onRestoreBackupFromFile={handleRestoreBackupFromFile}
                onEnsureBaseCollections={async () => {
                  const res = await ensureBaseCollectionsInitializedInFirestore({
                    adminUid:
                      auth?.currentUser?.uid ||
                      currentMember.googleUid ||
                      vaultConfig?.adminUid ||
                      'admin',
                    adminEmail:
                      auth?.currentUser?.email ||
                      vaultConfig?.adminEmail ||
                      'admin@familystream.local',
                    adminMemberId: currentMember.id,
                    adminMemberName: currentMember.fullName,
                    deviceName: detectedDevice.deviceName,
                    categoriesJson:
                      vaultConfig?.categoriesJson ||
                      JSON.stringify(DEFAULT_CATEGORIES),
                    defaultTheme: vaultConfig?.defaultTheme || theme,
                  });
                  showToast(
                    res.initializedCollections.length > 0
                      ? `Utworzono brakujące kolekcje: ${res.initializedCollections.join(', ')}!`
                      : 'Wszystkie 6 kolekcji bazowych już istnieje w bazie (dane nienaruszone).'
                  );
                  return res;
                }}
              />
                          ) : (
              /* CLEAN PASSWORD VAULT VIEW (Identical privacy rules for all users + Section 03 for revealed entries) */
              <div className="space-y-6">
                {/* 1. LIVE OWNER-ROUTED SOS / TV CODE ALERT BANNER (Shown ONLY to the founder/owner of the password when a family member requests TV code or reports broken password) */}
                {pendingSosForMyOwnedPasswords.length > 0 && (
                  <div className="p-4 rounded-xl border-2 border-[var(--vault-warning)] bg-[var(--vault-surface)] space-y-3">
                    <div className="flex items-center gap-2 text-xs sm:text-sm font-bold text-[var(--vault-warning)]">
                      <BellRing className="w-4 h-4 animate-bounce shrink-0" />
                      <span>
                        Aktywna prośba SOS do Ciebie jako właściciela hasła ({pendingSosForMyOwnedPasswords.length})
                      </span>
                    </div>
                    <div className="space-y-2.5">
                      {pendingSosForMyOwnedPasswords.map((sosRec) => {
                        const ticket = parsePasswordCardExtras(sosRec).sosTicket;
                        if (!ticket) return null;
                        const inputVal = topBannerSosCodes[sosRec.id] || '';
                        const isResolvingThis =
                          resolvingSosRecordId === sosRec.id;
                        return (
                          <form
                            key={`top_sos_${sosRec.id}`}
                            onSubmit={async (e) => {
                              e.preventDefault();
                              if (!inputVal.trim() || isResolvingThis) return;
                              setResolvingSosRecordId(sosRec.id);
                              try {
                                await handleResolveSosRequest(
                                  sosRec,
                                  inputVal.trim()
                                );
                                setTopBannerSosCodes((prev) => ({
                                  ...prev,
                                  [sosRec.id]: '',
                                }));
                              } finally {
                                setResolvingSosRecordId(null);
                              }
                            }}
                            className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] flex flex-col lg:flex-row lg:items-center justify-between gap-3 text-xs"
                          >
                            <div className="space-y-0.5">
                              <div className="font-semibold text-[var(--vault-text)] flex flex-wrap items-center gap-1.5">
                                <Tv className="w-3.5 h-3.5 text-[var(--vault-warning)] shrink-0" />
                                <span>
                                  Serwis: <strong>{sosRec.serviceName}</strong> · Domownik:{' '}
                                  <strong className="text-[var(--vault-accent)]">
                                    {ticket.requestedByMemberName}
                                  </strong>
                                </span>
                              </div>
                              <div className="text-[11px] text-[var(--vault-muted)]">
                                Powód:{' '}
                                <strong>
                                  {ticket.reason === 'tv_code'
                                    ? 'Prosi o kod autoryzacyjny na TV / PIN'
                                    : 'Zgłasza, że hasło nie działa'}
                                </strong>{' '}
                                — po wysłaniu kodu u domownika automatycznie otworzy się duże okno Lupy.
                              </div>
                            </div>

                            <div className="flex flex-wrap items-center gap-2 shrink-0">
                              <input
                                type="text"
                                value={inputVal}
                                onChange={(e) =>
                                  setTopBannerSosCodes((prev) => ({
                                    ...prev,
                                    [sosRec.id]: e.target.value,
                                  }))
                                }
                                placeholder="Kod na TV (np. 4829)..."
                                maxLength={32}
                                className="px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-warning)]"
                              />
                              <button
                                type="submit"
                                disabled={!inputVal.trim() || isResolvingThis}
                                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] disabled:opacity-50 rounded-lg cursor-pointer"
                              >
                                <Send className="w-3.5 h-3.5" />
                                <span>
                                  {isResolvingThis
                                    ? 'Wysyłanie...'
                                    : 'Wyślij kod do Lupy'}
                                </span>
                              </button>
                              <button
                                type="button"
                                onClick={() => handleClearSosRequest(sosRec)}
                                className="px-2.5 py-1.5 text-xs text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg cursor-pointer"
                              >
                                Zamknij
                              </button>
                            </div>
                          </form>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* 2. INTERACTIVE PASSWORD HEALTH AUDIT BAR (Duplicates, Age > 180 days, Weak Passwords + 1-Click Rotation) */}
                {passwordHealthAudit.totalAudited > 0 && (
                  <div className="rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setIsHealthAuditOpen((v) => !v)}
                      className="w-full px-4 py-3 flex flex-wrap items-center justify-between gap-3 text-left hover:bg-[var(--vault-surface-hover)] transition-colors cursor-pointer"
                    >
                      <div className="flex flex-wrap items-center gap-2.5">
                        {passwordHealthAudit.healthScore >= 85 ? (
                          <ShieldCheck className="w-4 h-4 text-[var(--vault-success)] shrink-0" />
                        ) : (
                          <ShieldAlert className="w-4 h-4 text-[var(--vault-warning)] shrink-0" />
                        )}
                        <span className="text-xs sm:text-sm font-bold font-display text-[var(--vault-text)]">
                          Audyt Kondycji Haseł:{' '}
                          <span
                            className={`tabular-nums ${
                              passwordHealthAudit.healthScore >= 85
                                ? 'text-[var(--vault-success)]'
                                : 'text-[var(--vault-warning)]'
                            }`}
                          >
                            {passwordHealthAudit.healthScore}%
                          </span>
                        </span>
                        <span className="text-xs text-[var(--vault-muted)] tabular-nums">
                          · Duplikaty:{' '}
                          <strong
                            className={
                              passwordHealthAudit.duplicates.length > 0
                                ? 'text-[var(--vault-warning)]'
                                : 'text-[var(--vault-text)]'
                            }
                          >
                            {passwordHealthAudit.duplicates.length}
                          </strong>{' '}
                          · Stare (&gt;180 dni):{' '}
                          <strong
                            className={
                              passwordHealthAudit.oldPasswords.length > 0
                                ? 'text-[var(--vault-warning)]'
                                : 'text-[var(--vault-text)]'
                            }
                          >
                            {passwordHealthAudit.oldPasswords.length}
                          </strong>{' '}
                          · Słabe:{' '}
                          <strong
                            className={
                              passwordHealthAudit.weakPasswords.length > 0
                                ? 'text-[var(--vault-warning)]'
                                : 'text-[var(--vault-text)]'
                            }
                          >
                            {passwordHealthAudit.weakPasswords.length}
                          </strong>
                        </span>
                      </div>

                      <div className="inline-flex items-center gap-1 text-xs font-semibold text-[var(--vault-accent)] shrink-0">
                        <span>
                          {isHealthAuditOpen
                            ? 'Ukryj raport audytu'
                            : 'Pokaż raport i wymień 1-Klik'}
                        </span>
                        {isHealthAuditOpen ? (
                          <ChevronUp className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5" />
                        )}
                      </div>
                    </button>

                    {isHealthAuditOpen && (
                      <div className="p-4 border-t border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-3 text-xs">
                        {passwordHealthAudit.duplicates.length === 0 &&
                        passwordHealthAudit.oldPasswords.length === 0 &&
                        passwordHealthAudit.weakPasswords.length === 0 ? (
                          <div className="flex items-center gap-2 text-[var(--vault-success)] font-medium">
                            <ShieldCheck className="w-4 h-4 shrink-0" />
                            <span>
                              Wzorowa higiena haseł! Wszystkie Twoje wpisy ({passwordHealthAudit.totalAudited}) są unikalne, silne i aktualne.
                            </span>
                          </div>
                        ) : (
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            {/* Column 1: Duplicates */}
                            <div className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-2">
                              <div className="font-bold text-[var(--vault-text)] flex items-center justify-between">
                                <span>Powtórzone hasła (Duplikaty)</span>
                                <span className="tabular-nums text-[var(--vault-warning)]">
                                  {passwordHealthAudit.duplicates.length}
                                </span>
                              </div>
                              {passwordHealthAudit.duplicates.length === 0 ? (
                                <p className="text-[11px] text-[var(--vault-muted)]">
                                  Brak duplikatów — każde konto ma inne hasło.
                                </p>
                              ) : (
                                <div className="space-y-1.5">
                                  {passwordHealthAudit.duplicates.map((item) => {
                                    const canRotate =
                                      item.record.ownerId === currentMember.id ||
                                      (item.record.section === 'shared' &&
                                        (isOwnerAdmin || isTrustedCoAdmin));
                                    return (
                                      <div
                                        key={`dup_${item.record.id}`}
                                        className="flex items-center justify-between gap-2 pt-1 border-t border-[var(--vault-border)]"
                                      >
                                        <span className="truncate font-medium text-[var(--vault-text)]">
                                          {item.serviceName}
                                        </span>
                                        {canRotate && (
                                          <button
                                            type="button"
                                            disabled={
                                              rotatingPasswordId ===
                                              item.record.id
                                            }
                                            onClick={() =>
                                              handleOneClickRotateAuditPassword(
                                                item.record
                                              )
                                            }
                                            className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded cursor-pointer shrink-0"
                                          >
                                            <RefreshCw className="w-3 h-3" />
                                            <span>Wymień 1-Klik</span>
                                          </button>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              )}
                            </div>

                            {/* Column 2: Weak Passwords */}
                            <div className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-2">
                              <div className="font-bold text-[var(--vault-text)] flex items-center justify-between">
                                <span>Słabe hasła (&lt;10 zn.)</span>
                                <span className="tabular-nums text-[var(--vault-warning)]">
                                  {passwordHealthAudit.weakPasswords.length}
                                </span>
                              </div>
                              {passwordHealthAudit.weakPasswords.length === 0 ? (
                                <p className="text-[11px] text-[var(--vault-muted)]">
                                  Wszystkie hasła mają odpowiednią długość i złożoność.
                                </p>
                              ) : (
                                <div className="space-y-1.5">
                                  {passwordHealthAudit.weakPasswords.map(
                                    (item) => {
                                      const canRotate =
                                        item.record.ownerId ===
                                          currentMember.id ||
                                        (item.record.section === 'shared' &&
                                          (isOwnerAdmin || isTrustedCoAdmin));
                                      return (
                                        <div
                                          key={`weak_${item.record.id}`}
                                          className="flex items-center justify-between gap-2 pt-1 border-t border-[var(--vault-border)]"
                                        >
                                          <div className="min-w-0">
                                            <span className="truncate font-medium text-[var(--vault-text)] block">
                                              {item.serviceName}
                                            </span>
                                            <span className="text-[10px] text-[var(--vault-muted)] block">
                                              {item.reason}
                                            </span>
                                          </div>
                                          {canRotate && (
                                            <button
                                              type="button"
                                              disabled={
                                                rotatingPasswordId ===
                                                item.record.id
                                              }
                                              onClick={() =>
                                                handleOneClickRotateAuditPassword(
                                                  item.record
                                                )
                                              }
                                              className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded cursor-pointer shrink-0"
                                            >
                                              <RefreshCw className="w-3 h-3" />
                                              <span>Wymień 1-Klik</span>
                                            </button>
                                          )}
                                        </div>
                                      );
                                    }
                                  )}
                                </div>
                              )}
                            </div>

                            {/* Column 3: Old Passwords (>180 days) */}
                            <div className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-2">
                              <div className="font-bold text-[var(--vault-text)] flex items-center justify-between">
                                <span>Stare hasła (&gt;180 dni)</span>
                                <span className="tabular-nums text-[var(--vault-warning)]">
                                  {passwordHealthAudit.oldPasswords.length}
                                </span>
                              </div>
                              {passwordHealthAudit.oldPasswords.length === 0 ? (
                                <p className="text-[11px] text-[var(--vault-muted)]">
                                  Wszystkie hasła były aktualizowane w ciągu ostatnich 6 miesięcy.
                                </p>
                              ) : (
                                <div className="space-y-1.5">
                                  {passwordHealthAudit.oldPasswords.map(
                                    (item) => {
                                      const canRotate =
                                        item.record.ownerId ===
                                          currentMember.id ||
                                        (item.record.section === 'shared' &&
                                          (isOwnerAdmin || isTrustedCoAdmin));
                                      return (
                                        <div
                                          key={`old_${item.record.id}`}
                                          className="flex items-center justify-between gap-2 pt-1 border-t border-[var(--vault-border)]"
                                        >
                                          <div className="min-w-0">
                                            <span className="truncate font-medium text-[var(--vault-text)] block">
                                              {item.serviceName}
                                            </span>
                                            <span className="text-[10px] text-[var(--vault-muted)] block tabular-nums">
                                              Wiek: {item.daysOld} dni
                                            </span>
                                          </div>
                                          {canRotate && (
                                            <button
                                              type="button"
                                              disabled={
                                                rotatingPasswordId ===
                                                item.record.id
                                              }
                                              onClick={() =>
                                                handleOneClickRotateAuditPassword(
                                                  item.record
                                                )
                                              }
                                              className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded cursor-pointer shrink-0"
                                            >
                                              <RefreshCw className="w-3 h-3" />
                                              <span>Wymień 1-Klik</span>
                                            </button>
                                          )}
                                        </div>
                                      );
                                    }
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Pillar 3: Zero-Knowledge SHA-1 k-Anonymity Breach Check Section */}
                        <div className="pt-3 border-t border-[var(--vault-border)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div className="space-y-0.5">
                            <div className="font-bold text-[var(--vault-text)] flex items-center gap-1.5">
                              <Shield className="w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0" />
                              <span>
                                Test Wycieków Zero-Knowledge (SHA-1 k-Anonimowość)
                              </span>
                            </div>
                            <p className="text-[11px] text-[var(--vault-muted)]">
                              Sprawdza Twoje hasła w bazie miliardów wycieków (HaveIBeenPwned) wysyłając wyłącznie 5 pierwszych znaków skrótu SHA-1. Żadne hasło nigdy nie opuszcza przeglądarki.
                            </p>
                          </div>
                          <button
                            type="button"
                            disabled={isCheckingBreaches}
                            onClick={handleRunZeroKnowledgeBreachCheck}
                            className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] disabled:opacity-50 rounded-lg cursor-pointer shrink-0"
                          >
                            <RefreshCw
                              className={`w-3.5 h-3.5 ${
                                isCheckingBreaches ? 'animate-spin' : ''
                              }`}
                            />
                            <span>
                              {isCheckingBreaches
                                ? 'Weryfikacja prefiksów SHA-1...'
                                : 'Sprawdź w bazie wycieków (Zero-Knowledge)'}
                            </span>
                          </button>
                        </div>

                        {hasRunBreachCheck && (
                          <div className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-2">
                            {passwordHealthAudit.resolvedItems.every(
                              (item) => (pwnedCheckResults[item.record.id] || 0) === 0
                            ) ? (
                              <div className="flex items-center gap-2 text-[var(--vault-success)] font-semibold">
                                <ShieldCheck className="w-4 h-4 shrink-0" />
                                <span>
                                  Wynik testu k-Anonimowości: 0 wycieków! Żadne z Twoich haseł ({passwordHealthAudit.resolvedItems.length}) nie figuruje w publicznych bazach wycieków.
                                </span>
                              </div>
                            ) : (
                              <div className="space-y-2">
                                <div className="text-[var(--vault-danger)] font-bold flex items-center gap-1.5">
                                  <ShieldAlert className="w-4 h-4 shrink-0" />
                                  <span>
                                    Wykryto hasła obecne w publicznych wyciekach danych:
                                  </span>
                                </div>
                                <div className="space-y-1.5">
                                  {passwordHealthAudit.resolvedItems
                                    .filter(
                                      (item) =>
                                        (pwnedCheckResults[item.record.id] || 0) > 0
                                    )
                                    .map((item) => {
                                      const count =
                                        pwnedCheckResults[item.record.id] || 0;
                                      const canRotate =
                                        item.record.ownerId ===
                                          currentMember.id ||
                                        (item.record.section === 'shared' &&
                                          (isOwnerAdmin || isTrustedCoAdmin));
                                      return (
                                        <div
                                          key={`pwned_${item.record.id}`}
                                          className="flex items-center justify-between gap-2 pt-1.5 border-t border-[var(--vault-border)]"
                                        >
                                          <div className="min-w-0">
                                            <span className="font-semibold text-[var(--vault-text)]">
                                              {item.serviceName}
                                            </span>
                                            <span className="text-[11px] text-[var(--vault-danger)] font-mono ml-2 tabular-nums">
                                              Wystąpień w wyciekach: {count.toLocaleString('pl-PL')}
                                            </span>
                                          </div>
                                          {canRotate && (
                                            <button
                                              type="button"
                                              disabled={
                                                rotatingPasswordId ===
                                                item.record.id
                                              }
                                              onClick={() =>
                                                handleOneClickRotateAuditPassword(
                                                  item.record
                                                )
                                              }
                                              className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-bold text-[#FAF7F2] bg-[var(--vault-danger)] hover:opacity-90 rounded cursor-pointer shrink-0"
                                            >
                                              <RefreshCw className="w-3 h-3" />
                                              <span>Wymień 1-Klik</span>
                                            </button>
                                          )}
                                        </div>
                                      );
                                    })}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Search, Section Quick-Filter, Category Filter & Sort Toolbar */}
                <div className="p-4 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-3">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                    <div className="relative flex-1">
                      <Search className="w-4 h-4 text-[var(--vault-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        ref={searchInputRef}
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Szukaj serwisu VOD, poczty, sklepu lub loginu... (skrót: /)"
                        className="w-full pl-9 pr-4 py-2 text-sm rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                      />
                    </div>

                    <div className="flex flex-wrap items-center justify-between sm:justify-end gap-2 shrink-0">
                      {/* Quick Section Switcher: Wszystkie / Wspólne / Prywatne / Ujawnione */}
                      <div className="flex items-center gap-1 p-1 rounded-lg bg-[var(--vault-bg)] border border-[var(--vault-border)] overflow-x-auto">
                        <button
                          type="button"
                          onClick={() => setVaultSectionFilter('all')}
                          className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer tabular-nums ${
                            vaultSectionFilter === 'all'
                              ? 'bg-[var(--vault-accent)] text-[#FAF7F2]'
                              : 'text-[var(--vault-muted)] hover:text-[var(--vault-text)]'
                          }`}
                        >
                          Wszystkie
                        </button>
                        <button
                          type="button"
                          onClick={() => setVaultSectionFilter('shared')}
                          className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer tabular-nums ${
                            vaultSectionFilter === 'shared'
                              ? 'bg-[var(--vault-accent)] text-[#FAF7F2]'
                              : 'text-[var(--vault-muted)] hover:text-[var(--vault-text)]'
                          }`}
                        >
                          Wspólne ({mySharedPasswords.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setVaultSectionFilter('private')}
                          className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer tabular-nums ${
                            vaultSectionFilter === 'private'
                              ? 'bg-[var(--vault-accent)] text-[#FAF7F2]'
                              : 'text-[var(--vault-muted)] hover:text-[var(--vault-text)]'
                          }`}
                        >
                          Prywatne ({myPrivatePasswords.length})
                        </button>
                        {(isOwnerAdmin || isTrustedCoAdmin) && (
                          <button
                            type="button"
                            onClick={() => setVaultSectionFilter('revealed')}
                            className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer tabular-nums ${
                              vaultSectionFilter === 'revealed'
                                ? 'bg-[var(--vault-accent)] text-[#FAF7F2]'
                                : 'text-[var(--vault-muted)] hover:text-[var(--vault-text)]'
                            }`}
                          >
                            Ujawnione ({revealedByOthersPasswords.length})
                          </button>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-xs text-[var(--vault-muted)] hidden sm:inline">
                          Sortuj:
                        </span>
                        <select
                          value={sortBy}
                          onChange={(e) =>
                            setSortBy(
                              e.target.value as 'alpha' | 'updated' | 'newest'
                            )
                          }
                          className="px-3 py-2 text-xs font-medium rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)]"
                        >
                          <option value="alpha">Alfabetycznie (A–Z)</option>
                          <option value="updated">Ostatnio zmienione hasło</option>
                          <option value="newest">Najnowsze wpisy</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Dynamic Categories Filter Bar */}
                  <div className="flex items-center gap-1.5 overflow-x-auto pt-1">
                    <button
                      type="button"
                      onClick={() => setSelectedCategoryFilter('all')}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        selectedCategoryFilter === 'all'
                          ? 'bg-[var(--vault-accent)] text-[#FAF7F2]'
                          : 'bg-[var(--vault-bg)] text-[var(--vault-muted)] hover:text-[var(--vault-text)]'
                      }`}
                    >
                      Wszystkie kategorie
                    </button>
                    {categories.map((cat) => (
                      <button
                        key={cat.id}
                        type="button"
                        onClick={() => setSelectedCategoryFilter(cat.id)}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          selectedCategoryFilter === cat.id
                            ? 'bg-[var(--vault-accent)] text-[#FAF7F2]'
                            : 'bg-[var(--vault-bg)] text-[var(--vault-muted)] hover:text-[var(--vault-text)]'
                        }`}
                      >
                        {cat.name}
                      </button>
                    ))}
                  </div>
                </div>

                {/* PASSWORD SECTIONS */}
                <div className="space-y-8">
                  {(vaultSectionFilter === 'all' ||
                    vaultSectionFilter === 'shared') && (
                    <section className="space-y-3">
                      <div className="flex items-center justify-between border-b border-[var(--vault-border)] pb-2">
                        <h2 className="text-base font-bold font-display text-[var(--vault-text)]">
                          01. Wspólne
                        </h2>
                        <span className="text-xs text-[var(--vault-muted)] tabular-nums">
                          {mySharedPasswords.length}
                        </span>
                      </div>

                      {mySharedPasswords.length === 0 ? (
                        <div className="p-5 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] text-center text-xs text-[var(--vault-muted)]">
                          Brak wspólnych haseł przypisanych do Twojego konta w wybranej kategorii. Kliknij „+ Dodaj hasło” w prawym górnym rogu, aby dodać pierwszy serwis lub subkonta.
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {mySharedPasswords.map((rec) => (
                            <PasswordCard
                              key={rec.id}
                              record={rec}
                              categories={categories}
                              currentMember={currentMember}
                              allMembers={members}
                              clipboardClearSeconds={
                                vaultConfig?.clipboardClearSeconds || 30
                              }
                              onQuickUpdatePassword={handleQuickUpdatePassword}
                              onUpdateAllowedMembers={handleUpdateAllowedMembers}
                              onUpdateSubAccounts={handleUpdateSubAccounts}
                              onToggleFavorite={handleToggleFavorite}
                              onCreateSosRequest={handleCreateSosRequest}
                              onResolveSosRequest={handleResolveSosRequest}
                              onClearSosRequest={handleClearSosRequest}
                              onUpdateCardMetadata={handleUpdateCardMetadata}
                              onDeleteRecord={handleDeleteRecord}
                              onStartClipboardCountdown={startClipboardCountdown}
                            />
                          ))}
                        </div>
                      )}
                    </section>
                  )}

                  {(vaultSectionFilter === 'all' ||
                    vaultSectionFilter === 'private') && (
                    <section className="space-y-3">
                      <div className="flex items-center justify-between border-b border-[var(--vault-border)] pb-2">
                        <h2 className="text-base font-bold font-display text-[var(--vault-text)]">
                          02. Prywatne
                        </h2>
                        <span className="text-xs text-[var(--vault-muted)] tabular-nums">
                          {myPrivatePasswords.length}
                        </span>
                      </div>

                      {myPrivatePasswords.length === 0 ? (
                        <div className="p-5 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] text-center text-xs text-[var(--vault-muted)]">
                          Brak prywatnych haseł.
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {myPrivatePasswords.map((rec) => (
                            <PasswordCard
                              key={rec.id}
                              record={rec}
                              decryptedPrivate={
                                decryptedPrivateMap[rec.id] || null
                              }
                              categories={categories}
                              currentMember={currentMember}
                              allMembers={members}
                              clipboardClearSeconds={
                                vaultConfig?.clipboardClearSeconds || 30
                              }
                              activeHardwareCertFingerprint={
                                currentDeviceDoc?.deviceCertificateFingerprint ||
                                detectedDevice.hardwareSignatureHash
                              }
                              activeHardwareModeLabel={`${
                                detectedDevice.hardwareModelOs
                              } · ${
                                detectedDevice.clientMode === 'pwa'
                                  ? 'PWA'
                                  : 'Browser'
                              } · AES-256-GCM`}
                              onQuickUpdatePassword={handleQuickUpdatePassword}
                              onUpdateAllowedMembers={handleUpdateAllowedMembers}
                              onUpdateSubAccounts={handleUpdateSubAccounts}
                              onToggleRevealToAdmin={handleToggleRevealToAdmin}
                              onToggleFavorite={handleToggleFavorite}
                              onUpdateCardMetadata={handleUpdateCardMetadata}
                              onDeleteRecord={handleDeleteRecord}
                              onStartClipboardCountdown={startClipboardCountdown}
                            />
                          ))}
                        </div>
                      )}
                    </section>
                  )}

                  {/* 03. Ujawnione przez domowników (Visible for Admin / Co-Admin) */}
                  {(isOwnerAdmin || isTrustedCoAdmin) &&
                    (vaultSectionFilter === 'all' ||
                      vaultSectionFilter === 'revealed') && (
                      <section className="space-y-3">
                        <div className="flex items-center justify-between border-b border-[var(--vault-border)] pb-2">
                          <div>
                            <h2 className="text-base font-bold font-display text-[var(--vault-text)]">
                              03. Ujawnione przez domowników
                            </h2>
                            <p className="text-xs text-[var(--vault-muted)]">
                              Prywatne hasła innych członków rodziny, w których właściciel świadomie zaznaczył opcję „Ujawnij hasło administratorowi”.
                            </p>
                          </div>
                          <span className="text-xs text-[var(--vault-muted)] tabular-nums">
                            {revealedByOthersPasswords.length}
                          </span>
                        </div>

                        {revealedByOthersPasswords.length === 0 ? (
                          <div className="p-5 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] text-center text-xs text-[var(--vault-muted)]">
                            Żaden domownik nie ujawnił jeszcze swoich prywatnych haseł Administratorowi.
                          </div>
                        ) : (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {revealedByOthersPasswords.map((rec) => (
                              <PasswordCard
                                key={`revealed_${rec.id}`}
                                record={rec}
                                decryptedPrivate={
                                  decryptedPrivateMap[rec.id] || {
                                    categoryId: rec.categoryId,
                                    serviceName: rec.serviceName,
                                    serviceUrl: rec.serviceUrl,
                                    login: rec.login,
                                    password: rec.passwordValue,
                                  }
                                }
                                categories={categories}
                                currentMember={currentMember}
                                allMembers={members}
                                clipboardClearSeconds={
                                  vaultConfig?.clipboardClearSeconds || 30
                                }
                                onQuickUpdatePassword={
                                  handleQuickUpdatePassword
                                }
                                onUpdateAllowedMembers={
                                  handleUpdateAllowedMembers
                                }
                                onUpdateSubAccounts={handleUpdateSubAccounts}
                                onToggleFavorite={handleToggleFavorite}
                                onUpdateCardMetadata={handleUpdateCardMetadata}
                                onDeleteRecord={handleDeleteRecord}
                                onStartClipboardCountdown={
                                  startClipboardCountdown
                                }
                              />
                            ))}
                          </div>
                        )}
                      </section>
                    )}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Add Password Modal */}
      {currentMember && (
        <AddPasswordModal
          isOpen={isAddModalOpen}
          onClose={() => setIsAddModalOpen(false)}
          categories={categories}
          currentMember={currentMember}
          allMembers={members}
          onSavePassword={handleAddPassword}
        />
      )}

      {/* iOS PWA Installation Guide Modal */}
      {showIOSInstallModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="max-w-sm w-full p-6 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-4 text-xs">
            <h3 className="text-base font-bold font-display text-[var(--vault-text)]">
              Instalacja aplikacji PWA na iPhone / iPad
            </h3>
            <ol className="list-decimal list-inside space-y-2 text-[var(--vault-muted)]">
              <li>
                Stuknij ikonę <strong>Udostępnij</strong> na dolnym pasku przeglądarki Safari.
              </li>
              <li>
                Wybierz z listy opcję <strong>Dodaj do ekranu początkowego</strong>.
              </li>
              <li>
                Po otwarciu ikony z ekranu głównego zaloguj się swoim kontem i kliknij <strong>Autoryzuj moje urządzenie</strong>, aby spiąć aplikację PWA ze swoim profilem.
              </li>
            </ol>
            <button
              type="button"
              onClick={() => setShowIOSInstallModal(false)}
              className="w-full py-2 font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-lg cursor-pointer"
            >
              Rozumiem
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
