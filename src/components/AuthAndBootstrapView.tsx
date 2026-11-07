import React, { useEffect, useState } from 'react';
import {
  Fingerprint,
  Smartphone,
  ShieldCheck,
  Clock,
  Monitor,
  UserPlus,
  LogIn,
  CheckCircle2,
  Download,
  RefreshCw,
  Lock,
  KeyRound,
  Link2,
  AlertTriangle,
  Copy,
  Check,
  Cloud,
  Upload,
  Database,
  Settings,
} from 'lucide-react';
import {
  onAuthStateChanged,
  signInWithPopup,
  User as FirebaseUser,
} from 'firebase/auth';
import {
  auth,
  clearCustomFirebaseConfig,
  decodeFirebaseConfigFromInviteUrl,
  diagnoseFirebaseAuthConfiguration,
  exportActiveFirebaseConfigJson,
  getDeviceInstanceRole,
  getFirebaseProjectInfo,
  googleProvider,
  isFirebaseConfigured,
  parseAndValidateFirebaseConfigInput,
  PRODUCTION_FIRESTORE_RULES,
  PWA_HANDOFF_CACHE_NAME,
  saveCustomFirebaseConfigAsAdmin,
  saveCustomFirebaseConfigAsMember,
  setDeviceInstanceRole,
} from '../lib/firebase';
import { verifyInvitationTokenInFirestore } from '../lib/firestoreVaultService';
import {
  Device,
  Member,
  VaultConfig,
  VaultInvitation,
} from '../types/vault';
import {
  DetectedDeviceProfile,
  StoredBiometricProfile,
} from '../lib/deviceAndBiometrics';
import { FirebaseSetupGuideDropdown } from './FirebaseSetupGuideDropdown';

interface AuthAndBootstrapViewProps {
  vaultConfig: VaultConfig | null;
  membersCount: number;
  detectedDevice: DetectedDeviceProfile;
  biometricProfile: StoredBiometricProfile | null;
  pendingAuthState: {
    member: Member;
    dekBase64: string;
    mergedDeksBase64: string[];
    existingDevice: Device | null;
  } | null;
  canInstallPWA: boolean;
  isPWAInstalled: boolean;
  onInstallPWA: () => void;
  onTriggerAppUpdate: () => Promise<void>;
  isUpdatingApp: boolean;
  onFirebaseConfigActivated: () => void;
  onAdminGoogleLogin: (options: {
    firebaseUser: FirebaseUser;
    masterPassword?: string;
  }) => Promise<void>;
  onLoginWithCredentials: (username: string, password: string) => Promise<void>;
  onRegisterMemberAccountWithInvite: (params: {
    inviteToken: string;
    fullName: string;
    username: string;
    password: string;
    setupBiometrics: boolean;
  }) => Promise<void>;
  onRecoverMemberAccountWithInvite: (params: {
    inviteToken: string;
    targetMemberId: string;
    newUsername: string;
    newPassword: string;
    setupBiometrics: boolean;
  }) => Promise<void>;
  onRequestDeviceAuthorization: (customLabel: string) => Promise<void>;
  onUnlockWithBiometrics: () => Promise<void>;
  onCancelPendingState: () => void;
  }

const PWA_INVITE_HANDOFF_KEY = 'fsv_invite_token_v1';
const PWA_FB_CONFIG_HANDOFF_KEY = 'fsv_invite_fb_param_v1';

function extractInviteAndFbFromInput(raw: string): {
  inviteToken: string;
  fbParam: string;
} {
  const trimmed = raw.trim();
  if (!trimmed) return { inviteToken: '', fbParam: '' };

  // 1. Direct regex extraction (handles full URLs, query strings, or URLs embedded inside SMS/WhatsApp messages)
  const invMatch = trimmed.match(/[?&]invite=([a-zA-Z0-9_-]+)/i);
  const fbMatch = trimmed.match(/[?&]fb=([a-zA-Z0-9_=-]+)/i);
  if (invMatch?.[1] || fbMatch?.[1]) {
    return {
      inviteToken: invMatch?.[1] ? decodeURIComponent(invMatch[1]).trim() : '',
      fbParam: fbMatch?.[1] ? decodeURIComponent(fbMatch[1]).trim() : '',
    };
  }

  // 2. Fallback URL parsing if a URL object can be constructed
  try {
    const urlCandidateMatch = trimmed.match(/https?:\/\/[^\s"'<>]+/i);
    const targetUrlStr = urlCandidateMatch
      ? urlCandidateMatch[0]
      : trimmed.startsWith('http')
        ? trimmed
        : `https://vault.local/${trimmed.replace(/^\//, '')}`;
    if (targetUrlStr.includes('invite=') || targetUrlStr.includes('fb=')) {
      const url = new URL(targetUrlStr);
      return {
        inviteToken: (url.searchParams.get('invite') || '').trim(),
        fbParam: (url.searchParams.get('fb') || '').trim(),
      };
    }
  } catch {
    // ignore URL parse error
  }

  // 3. Direct token string (e.g. inv_123456...)
  const directTokenMatch = trimmed.match(/\b(inv_[a-zA-Z0-9_-]+)\b/i);
  if (directTokenMatch?.[1]) {
    return { inviteToken: directTokenMatch[1].trim(), fbParam: '' };
  }

  return { inviteToken: trimmed, fbParam: '' };
}

async function saveInviteAndFbForPwaHandoff(
  inviteToken: string,
  fbParam: string
): Promise<void> {
  try {
    if (inviteToken) localStorage.setItem(PWA_INVITE_HANDOFF_KEY, inviteToken);
    if (fbParam) localStorage.setItem(PWA_FB_CONFIG_HANDOFF_KEY, fbParam);
  } catch {
    // ignore
  }
  if (typeof window !== 'undefined' && 'caches' in window) {
    try {
      const cache = await window.caches.open(PWA_HANDOFF_CACHE_NAME);
      await cache.put(
        new Request('/__fsv_invite_handoff__'),
        new Response(
          JSON.stringify({
            inviteToken: inviteToken || '',
            fbParam: fbParam || '',
          }),
          {
            headers: { 'Content-Type': 'application/json' },
          }
        )
      );
    } catch {
      // ignore
    }
  }
}

async function loadInviteAndFbFromPwaHandoff(): Promise<{
  inviteToken: string;
  fbParam: string;
}> {
  let inviteToken = '';
  let fbParam = '';
  try {
    inviteToken = localStorage.getItem(PWA_INVITE_HANDOFF_KEY) || '';
    fbParam = localStorage.getItem(PWA_FB_CONFIG_HANDOFF_KEY) || '';
  } catch {
    // ignore
  }
  if (
    (!inviteToken || !fbParam) &&
    typeof window !== 'undefined' &&
    'caches' in window
  ) {
    try {
      const cache = await window.caches.open(PWA_HANDOFF_CACHE_NAME);
      const res = await cache.match(new Request('/__fsv_invite_handoff__'));
      if (res) {
        const data = (await res.json()) as {
          inviteToken?: string;
          fbParam?: string;
        };
        if (!inviteToken && data?.inviteToken) inviteToken = data.inviteToken;
        if (!fbParam && data?.fbParam) fbParam = data.fbParam;
      }
    } catch {
      // ignore
    }
  }
  return { inviteToken, fbParam };
}

async function clearInviteTokenHandoff(): Promise<void> {
  try {
    localStorage.removeItem(PWA_INVITE_HANDOFF_KEY);
    localStorage.removeItem(PWA_FB_CONFIG_HANDOFF_KEY);
  } catch {
    // ignore
  }
  if (typeof window !== 'undefined' && 'caches' in window) {
    try {
      const cache = await window.caches.open(PWA_HANDOFF_CACHE_NAME);
      await cache.delete(new Request('/__fsv_invite_handoff__'));
    } catch {
      // ignore
    }
  }
}

export const AuthAndBootstrapView: React.FC<AuthAndBootstrapViewProps> = ({
  vaultConfig,
  membersCount,
  detectedDevice,
  biometricProfile,
  pendingAuthState,
  canInstallPWA,
  isPWAInstalled,
  onInstallPWA,
  onTriggerAppUpdate,
  isUpdatingApp,
  onFirebaseConfigActivated,
  onAdminGoogleLogin,
  onLoginWithCredentials,
  onRegisterMemberAccountWithInvite,
  onRecoverMemberAccountWithInvite,
  onRequestDeviceAuthorization,
  onUnlockWithBiometrics,
  onCancelPendingState,
  }) => {
  const [firebaseReady, setFirebaseReady] = useState<boolean>(() =>
    isFirebaseConfigured()
  );
  const [deviceRole, setDeviceRole] = useState<'admin' | 'member' | null>(() =>
    getDeviceInstanceRole()
  );

  // Gatekeep 2: Local Firebase Config JSON loader state
  const [rawFirebaseJsonInput, setRawFirebaseJsonInput] = useState('');
  const [customDatabaseIdInput, setCustomDatabaseIdInput] = useState('');
  const [firebaseConfigError, setFirebaseConfigError] = useState<string | null>(
    null
  );
  const [showChangeFirebaseConfigModal, setShowChangeFirebaseConfigModal] =
    useState(false);

  const isVaultInitialized = Boolean(
    (vaultConfig && vaultConfig.initialized) || membersCount > 0
  );

  // Invitation token from URL (?invite=...) or restored from PWA Handoff CacheStorage
  const [inviteToken, setInviteToken] = useState<string>(() => {
    if (typeof window === 'undefined') return '';
    return extractInviteAndFbFromInput(window.location.search).inviteToken;
  });
  const [isInitializingHandoff, setIsInitializingHandoff] = useState(true);

  const [manualInviteInput, setManualInviteInput] = useState('');
  const [showManualInviteBox, setShowManualInviteBox] = useState(false);

  const [verifiedInvite, setVerifiedInvite] =
    useState<VaultInvitation | null>(null);
  const [isVerifyingInvite, setIsVerifyingInvite] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [retryInviteCounter, setRetryInviteCounter] = useState(0);

  // Login form state & Brute-Force Protection (5 attempts -> 60s lockout)
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showAdminFallbackPasswordLogin, setShowAdminFallbackPasswordLogin] =
    useState(false);
  const [failedLoginAttempts, setFailedLoginAttempts] = useState(0);
  const [lockoutSecondsLeft, setLockoutSecondsLeft] = useState(0);

  // Invite registration / recovery form state
  const [regFullName, setRegFullName] = useState('');
  const [regUsername, setRegUsername] = useState('');
  const [regUsernameManuallyEdited, setRegUsernameManuallyEdited] =
    useState(false);
  const [regPassword, setRegPassword] = useState('');
  const [setupBiometricsOnInvite, setSetupBiometricsOnInvite] = useState(false);

  const [deviceCustomLabel, setDeviceCustomLabel] = useState(
    detectedDevice.clientMode === 'pwa'
      ? 'Moja aplikacja PWA'
      : 'Moja przeglądarka'
  );

  const [isAdminLoading, setIsAdminLoading] = useState(false);
  const [isFamilyLoading, setIsFamilyLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [unauthorizedDomainHost, setUnauthorizedDomainHost] = useState<
    string | null
  >(null);
  const [copiedDomainHost, setCopiedDomainHost] = useState(false);
  const [copiedFirestoreRules, setCopiedFirestoreRules] = useState(false);

  // Native Firebase Auth Google user state (persisted via browserLocalPersistence)
  const [firebaseAuthUser, setFirebaseAuthUser] = useState<FirebaseUser | null>(
    () =>
      isFirebaseConfigured() &&
      auth &&
      auth.currentUser &&
      !auth.currentUser.isAnonymous
        ? auth.currentUser
        : null
  );
  const [adminMasterPasswordInput, setAdminMasterPasswordInput] = useState('');
  const [copiedCustomLink, setCopiedCustomLink] = useState(false);

  // Strict PWA-only enforcement outside AI Studio (GATEKEEP 1)
  const isRunningInInstalledPwa =
    isPWAInstalled || detectedDevice.clientMode === 'pwa';
  const isBrowserBlocked = !isAiStudioPreview && !isRunningInInstalledPwa;

  // Listen to native Firebase Auth state (browserLocalPersistence) when Firebase is configured
  useEffect(() => {
    if (!firebaseReady || !auth) return;
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setFirebaseAuthUser(user && !user.isAnonymous ? user : null);
    });
    return () => unsubscribe();
  }, [firebaseReady]);

  // Brute-Force lockout countdown timer (60s cooldown after 5 failed attempts)
  useEffect(() => {
    if (lockoutSecondsLeft <= 0) return;
    const timer = window.setInterval(() => {
      setLockoutSecondsLeft((prev) => {
        if (prev <= 1) {
          setFailedLoginAttempts(0);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [lockoutSecondsLeft]);

  // Save/restore ?invite=TOKEN&fb=CONFIG across browser -> installed PWA handoff
  useEffect(() => {
    let active = true;
    async function initInviteHandoff() {
      try {
        if (typeof window !== 'undefined') {
          const { inviteToken: urlInvite, fbParam: urlFb } =
            extractInviteAndFbFromInput(window.location.search);

          if (urlFb && !isAiStudioPreview) {
            const decodedCfg = decodeFirebaseConfigFromInviteUrl(urlFb);
            if (decodedCfg) {
              saveCustomFirebaseConfigAsMember(decodedCfg);
              if (active) {
                setFirebaseReady(true);
                setDeviceRole('member');
              }
              onFirebaseConfigActivated();
            }
          }

          if (urlInvite) {
            await saveInviteAndFbForPwaHandoff(urlInvite, urlFb);
            if (active) {
              setInviteToken(urlInvite);
              setDeviceRole('member');
            }
            return;
          }
        }

        // If this device is already configured as an Admin instance (e.g. after uploading firebase-config.json or in AI Studio Dev),
        // never let a stale CacheStorage handoff overwrite the Admin view into Member mode!
        if (getDeviceInstanceRole() === 'admin' || isAiStudioPreview) {
          await clearInviteTokenHandoff();
          if (active) {
            setDeviceRole('admin');
          }
          return;
        }

        const restored = await loadInviteAndFbFromPwaHandoff();
        if (restored.fbParam) {
          const decodedCfg = decodeFirebaseConfigFromInviteUrl(
            restored.fbParam
          );
          if (decodedCfg) {
            saveCustomFirebaseConfigAsMember(decodedCfg);
            if (active) {
              setFirebaseReady(true);
              setDeviceRole('member');
            }
            onFirebaseConfigActivated();
          }
        }
        if (active && restored.inviteToken && !inviteToken) {
          setInviteToken(restored.inviteToken);
          setDeviceRole('member');
        }
      } finally {
        if (active) setIsInitializingHandoff(false);
      }
    }
    initInviteHandoff();
    return () => {
      active = false;
    };
  }, []);

  // Verify invite token directly in Cloud Firestore whenever `inviteToken` and `firebaseReady` are active
  useEffect(() => {
    let cancelled = false;
    if (!inviteToken || isInitializingHandoff || !firebaseReady) {
      if (!inviteToken) {
        setVerifiedInvite(null);
        setInviteError(null);
      }
      return;
    }

    setIsVerifyingInvite(true);
    setInviteError(null);

    verifyInvitationTokenInFirestore(inviteToken)
      .then((invitation) => {
        if (cancelled) return;
        setVerifiedInvite(invitation);
        if (
          invitation.purpose === 'account_recovery' &&
          invitation.targetUsername
        ) {
          setRegUsername(invitation.targetUsername);
          setRegFullName(invitation.targetMemberName || '');
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setVerifiedInvite(null);
        setInviteError(
          err instanceof Error
            ? err.message
            : 'Ten link zaproszeniowy jest nieprawidłowy lub wygasł.'
        );
      })
      .finally(() => {
        if (!cancelled) setIsVerifyingInvite(false);
      });

    return () => {
      cancelled = true;
    };
  }, [inviteToken, isInitializingHandoff, firebaseReady, retryInviteCounter]);

  const clearInviteFromUrlAndState = () => {
    setInviteToken('');
    setVerifiedInvite(null);
    setInviteError(null);
    clearInviteTokenHandoff().catch(() => {});
    if (
      typeof window !== 'undefined' &&
      (window.location.search.includes('invite=') ||
        window.location.search.includes('fb='))
    ) {
      const url = new URL(window.location.href);
      url.searchParams.delete('invite');
      url.searchParams.delete('fb');
      window.history.replaceState({}, '', url.pathname + url.search);
    }
  };

  // Auto-suggest login from full name if user hasn't edited login field manually
  const handleFullNameChange = (val: string) => {
    setRegFullName(val);
    if (!regUsernameManuallyEdited) {
      const firstWord = val
        .trim()
        .split(/\s+/)[0]
        ?.toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/ł/g, 'l')
        .replace(/[^a-z0-9]/g, '');
      if (firstWord) {
        setRegUsername(firstWord);
      }
    }
  };

  const handleCopyCurrentCustomUrl = () => {
    if (typeof window === 'undefined') return;
    navigator.clipboard.writeText(window.location.href).catch(() => {});
    setCopiedCustomLink(true);
    setTimeout(() => setCopiedCustomLink(false), 2500);
  };

  // GATEKEEP 2 HANDLERS: Upload or Paste Firebase Config JSON -> Activates Admin Instance!
  const handleFirebaseJsonFileSelect = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFirebaseConfigError(null);
    try {
      const text = await file.text();
      setRawFirebaseJsonInput(text);
      const validated = parseAndValidateFirebaseConfigInput(
        text,
        customDatabaseIdInput
      );
      clearInviteFromUrlAndState();
      saveCustomFirebaseConfigAsAdmin(validated);
      setFirebaseReady(true);
      setDeviceRole('admin');
      setShowChangeFirebaseConfigModal(false);
      onFirebaseConfigActivated();
    } catch (err) {
      setFirebaseConfigError(
        err instanceof Error
          ? err.message
          : 'Nie udało się wczytać pliku JSON konfiguracji Firebase.'
      );
    } finally {
      e.target.value = '';
    }
  };

  const handleFirebaseJsonSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFirebaseConfigError(null);
    try {
      const validated = parseAndValidateFirebaseConfigInput(
        rawFirebaseJsonInput,
        customDatabaseIdInput
      );
      clearInviteFromUrlAndState();
      saveCustomFirebaseConfigAsAdmin(validated);
      setFirebaseReady(true);
      setDeviceRole('admin');
      setShowChangeFirebaseConfigModal(false);
      onFirebaseConfigActivated();
    } catch (err) {
      setFirebaseConfigError(
        err instanceof Error
          ? err.message
          : 'Nieprawidłowa konfiguracja Firebase.'
      );
    }
  };

  const handleApplyManualInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    const { inviteToken: extractedInvite, fbParam: extractedFb } =
      extractInviteAndFbFromInput(manualInviteInput);
    if (!extractedInvite) return;

    if (extractedFb) {
      const decodedCfg = decodeFirebaseConfigFromInviteUrl(extractedFb);
      if (decodedCfg) {
        saveCustomFirebaseConfigAsMember(decodedCfg);
        setFirebaseReady(true);
        setDeviceRole('member');
        onFirebaseConfigActivated();
      }
    }

    await saveInviteAndFbForPwaHandoff(extractedInvite, extractedFb);
    setInviteToken(extractedInvite);
    setDeviceRole('member');
    setShowManualInviteBox(false);
    setManualInviteInput('');
  };

  // ============================================================================
  // GATEKEEP 1: STRICT BROWSER BLOCK GATE (Force PWA Installation first)
  // ============================================================================
  if (isBrowserBlocked) {
    const hasCustomInviteInUrlOrHandoff = Boolean(
      inviteToken ||
        (typeof window !== 'undefined' &&
          window.location.search.includes('invite='))
    );

    return (
      <div className="max-w-lg mx-auto my-6 p-6 sm:p-8 rounded-xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] space-y-6 shadow-md">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--vault-accent)]">
            <Smartphone className="w-4 h-4 shrink-0" />
            <span>
              Krok 01 · Wymagana Instalacja Aplikacji PWA (Blokada Przeglądarki)
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold font-display text-[var(--vault-text)] leading-snug">
            Zainstaluj FamilyStream Vault jako aplikację PWA, aby kontynuować
          </h1>
          <p className="text-xs sm:text-sm text-[var(--vault-muted)] leading-relaxed">
            Ze względów bezpieczeństwa oraz trwałego powiązania Certyfikatu Sprzętowego korzystanie ze skarbca w zwykłej karcie przeglądarki jest wyłączone. Zainstaluj aplikację lokalnie na swoim urządzeniu i otwórz ją z ikony na ekranie głównym.
          </p>
        </div>

        {hasCustomInviteInUrlOrHandoff && (
          <div className="p-4 rounded-xl border border-[var(--vault-success)] bg-[var(--vault-bg)] space-y-3">
            <div className="flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-[var(--vault-success)] shrink-0 mt-0.5" />
              <div className="space-y-1 text-xs">
                <div className="font-semibold text-[var(--vault-text)]">
                  Wykryto link zaproszeniowy do Skarbca Rodzinnego!
                </div>
                <p className="text-[var(--vault-muted)] leading-relaxed">
                  Zaproszenie oraz parametry połączenia z bazą zostały zapisane w pamięci podręcznej urządzenia. Po zainstalowaniu i uruchomieniu aplikacji PWA od razu zobaczysz ekran <strong>„Utwórz konto”</strong>.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleCopyCurrentCustomUrl}
              className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-surface)] hover:bg-[var(--vault-surface-hover)] rounded-lg transition-colors cursor-pointer"
            >
              {copiedCustomLink ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[var(--vault-success)] shrink-0" />
                  <span>Skopiowano link zaproszeniowy do schowka!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0" />
                  <span>
                    Kopiuj ten link zaproszeniowy (zapasowo przed instalacją PWA)
                  </span>
                </>
              )}
            </button>
          </div>
        )}

        <div className="space-y-3">
          <button
            type="button"
            onClick={onInstallPWA}
            className="w-full inline-flex items-center justify-center gap-2 px-5 py-3.5 text-sm font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl transition-colors cursor-pointer shadow-sm text-center"
          >
            <Download className="w-4 h-4 shrink-0" />
            <span>
              {canInstallPWA
                ? 'Zainstaluj aplikację FamilyStream Vault (PWA)'
                : 'Pokaż instrukcję instalacji PWA na tym telefonie'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => onTriggerAppUpdate()}
            disabled={isUpdatingApp}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-medium text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-bg)] hover:bg-[var(--vault-surface-hover)] rounded-xl transition-colors cursor-pointer"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0 ${
                isUpdatingApp ? 'animate-spin' : ''
              }`}
            />
            <span>
              {isUpdatingApp
                ? 'Odświeżanie najnowszej wersji...'
                : 'Odśwież wersję aplikacji przed instalacją'}
            </span>
          </button>
        </div>

        <div className="p-4 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-2.5 text-xs">
          <div className="font-semibold text-[var(--vault-text)]">
            Jak zainstalować aplikację w 10 sekund:
          </div>
          <ul className="list-disc list-inside space-y-1.5 text-[var(--vault-muted)] leading-relaxed">
            <li>
              <strong className="text-[var(--vault-text)]">
                Android (Chrome / Edge / Brave):
              </strong>{' '}
              Kliknij przycisk powyżej lub otwórz menu przeglądarki (trzy kropki{' '}
              <code>⋮</code> w prawym górnym rogu) i wybierz{' '}
              <strong>„Zainstaluj aplikację”</strong> /{' '}
              <strong>„Dodaj do ekranu głównego”</strong>.
            </li>
            <li>
              <strong className="text-[var(--vault-text)]">
                iPhone / iPad (Safari):
              </strong>{' '}
              Stuknij ikonę <strong>Udostępnij</strong> na dolnym pasku i wybierz{' '}
              <strong>„Dodaj do ekranu początkowego”</strong>.
            </li>
            <li>
              <strong className="text-[var(--vault-text)]">
                Po instalacji:
              </strong>{' '}
              Zamknij tę kartę przeglądarki i uruchom <strong>FamilyStream Vault</strong> bezpośrednio z nowej ikony na ekranie telefonu.
            </li>
          </ul>
        </div>
      </div>
    );
  }

  // Reusable top bar for 1-tap PWA Service Worker update across all pre-login screens
  const renderTopPwaUpdateBar = () => (
    <div className="p-4 rounded-xl border border-[var(--vault-accent)] bg-[var(--vault-surface)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
      <div className="space-y-0.5">
        <div className="text-xs font-semibold text-[var(--vault-text)] flex items-center gap-1.5">
          <Smartphone className="w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0" />
          <span>
            {isRunningInInstalledPwa
              ? 'Aplikacja FamilyStream Vault działa w trybie zainstalowanym (PWA)'
              : 'Zainstaluj skarbiec jako aplikację PWA'}
          </span>
        </div>
        <p className="text-[11px] text-[var(--vault-muted)]">
          {isRunningInInstalledPwa
            ? 'Kliknij „Aktualizuj aplikację”, aby pobrać najnowszą wersję kodu z GitHub Pages bez utraty danych w Cloud Firestore.'
            : 'Zainstaluj jako aplikację PWA na telefonie lub zaktualizuj program jednym kliknięciem.'}
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 shrink-0">
        {!isRunningInInstalledPwa && (
          <button
            type="button"
            onClick={onInstallPWA}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 shrink-0" />
            <span>Zainstaluj jako aplikację (PWA)</span>
          </button>
        )}

        <button
          type="button"
          onClick={() => onTriggerAppUpdate()}
          disabled={isUpdatingApp}
          className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-bg)] hover:bg-[var(--vault-surface-hover)] rounded-lg transition-colors cursor-pointer"
        >
          <RefreshCw
            className={`w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0 ${
              isUpdatingApp ? 'animate-spin' : ''
            }`}
          />
          <span>
            {isUpdatingApp ? 'Aktualizowanie...' : 'Aktualizuj aplikację'}
          </span>
        </button>
      </div>
    </div>
  );

  // ============================================================================
  // GATEKEEP 2: CLEAN PWA WITHOUT FIREBASE CONFIG -> ADMIN LOCAL JSON LOADER
  // ============================================================================
  if (!firebaseReady || showChangeFirebaseConfigModal) {
    return (
      <div className="max-w-lg mx-auto my-4 space-y-6">
        {renderTopPwaUpdateBar()}

        <div className="p-6 sm:p-8 rounded-xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] space-y-6 shadow-md">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--vault-accent)]">
              <Database className="w-4 h-4 shrink-0" />
              <span>
                Krok 02 · Inicjalizacja Własnej Instancji Skarbca (Brak Configu w GitHub)
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold font-display text-[var(--vault-text)] leading-snug">
              Załaduj lokalnie konfigurację z Firebase Console
            </h1>
            <p className="text-xs sm:text-sm text-[var(--vault-muted)] leading-relaxed">
              Publiczne repozytorium na GitHubie nie przechowuje żadnych kluczy Firebase. Wklej skopiowany prosto z Firebase Console obiekt <code className="font-mono text-[var(--vault-text)]">firebaseConfig</code> (dokładnie w takim formacie, w jakim podaje go Google — bez przerabiania na JSON) lub wgraj go z pliku.
            </p>
          </div>

          {/* Collapsible Step-by-Step Guide & Module Educational Explanation */}
          <FirebaseSetupGuideDropdown />

          {/* Option A: 1-Tap File Upload (.json / .txt / .js) */}
          <div className="p-4 rounded-xl border border-[var(--vault-accent)] bg-[var(--vault-bg)] space-y-3">
            <div className="text-xs font-semibold text-[var(--vault-text)]">
              Opcja A: Wybierz plik z konfiguracją (<code className="font-mono">.json</code>, <code className="font-mono">.txt</code> lub <code className="font-mono">.js</code>) z pamięci urządzenia
            </div>
            <label className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 text-sm font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl transition-colors cursor-pointer shadow-sm">
              <Upload className="w-4 h-4 shrink-0" />
              <span>Wybierz plik konfiguracji Firebase z urządzenia</span>
              <input
                type="file"
                accept=".json,.txt,.js,application/json,text/plain,text/javascript"
                onChange={handleFirebaseJsonFileSelect}
                className="hidden"
              />
            </label>
          </div>

          {/* Option B: Paste raw firebaseConfig snippet directly from Firebase Console */}
          <form onSubmit={handleFirebaseJsonSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                Opcja B: Wklej surowy config prosto z Firebase Console (bez żadnego formatowania)
              </label>
              <textarea
                rows={8}
                value={rawFirebaseJsonInput}
                onChange={(e) => setRawFirebaseJsonInput(e.target.value)}
                placeholder={`{\n  apiKey: "AIzaSy...",\n  authDomain: "twoj-projekt.firebaseapp.com",\n  projectId: "twoj-projekt",\n  storageBucket: "twoj-projekt.firebasestorage.app",\n  messagingSenderId: "1234567890",\n  appId: "1:1234567890:web:...",\n  measurementId: "G-..."\n};`}
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-[var(--vault-muted)] mb-1">
                Opcjonalne ID bazy Firestore (pozostaw puste jeśli jest w JSON lub używasz domyślnej bazy)
              </label>
              <input
                type="text"
                value={customDatabaseIdInput}
                onChange={(e) => setCustomDatabaseIdInput(e.target.value)}
                placeholder="np. ai-studio-... lub zostaw puste dla (default)"
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
              />
            </div>

            {firebaseConfigError && (
              <div className="p-3 rounded-lg border border-[var(--vault-danger)] text-xs text-[var(--vault-danger)] break-words">
                {firebaseConfigError}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="submit"
                className="flex-1 inline-flex items-center justify-center gap-2 px-5 py-3 text-xs sm:text-sm font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl transition-colors cursor-pointer"
              >
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>Załaduj konfigurację i uruchom jako Administrator</span>
              </button>

              {showChangeFirebaseConfigModal && firebaseReady && (
                <button
                  type="button"
                  onClick={() => setShowChangeFirebaseConfigModal(false)}
                  className="px-4 py-3 text-xs font-semibold text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-xl cursor-pointer"
                >
                  Anuluj
                </button>
              )}
            </div>
          </form>

          {/* Family Member Invite Link Paste Fallback */}
          <div className="pt-4 border-t border-[var(--vault-border)] space-y-2.5 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 text-[var(--vault-muted)]">
              <span>
                Jesteś domownikiem i otrzymałeś link zaproszeniowy od Administratora?
              </span>
              <button
                type="button"
                onClick={() => setShowManualInviteBox((v) => !v)}
                className="text-[var(--vault-accent)] hover:underline font-semibold cursor-pointer"
              >
                {showManualInviteBox
                  ? 'Ukryj pole linku'
                  : 'Wklej link zaproszeniowy'}
              </button>
            </div>
            {showManualInviteBox && (
              <form
                onSubmit={handleApplyManualInvite}
                className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1"
              >
                <input
                  type="text"
                  value={manualInviteInput}
                  onChange={(e) => setManualInviteInput(e.target.value)}
                  placeholder="Wklej pełny link zaproszeniowy od Administratora..."
                  className="flex-1 px-3 py-2 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)]"
                />
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-lg cursor-pointer shrink-0"
                >
                  Otwórz zaproszenie
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    );
  }

  // ============================================================================
  // WAITING SCREEN FOR PENDING ACCOUNT / DEVICE APPROVAL (Real-time onSnapshot)
  // ============================================================================
  if (pendingAuthState) {
    const { member, existingDevice } = pendingAuthState;
    const isAccountPending = member.status === 'pending';
    const isDevicePending = existingDevice?.status === 'pending';
    const isDeviceRevoked = existingDevice?.status === 'revoked';

    const handleRequestAuth = async (e: React.FormEvent) => {
      e.preventDefault();
      setErrorMsg(null);
      setIsFamilyLoading(true);
      try {
        await onRequestDeviceAuthorization(deviceCustomLabel.trim());
      } catch (err) {
        setErrorMsg(
          err instanceof Error
            ? err.message
            : 'Nie udało się wysłać prośby o autoryzację.'
        );
      } finally {
        setIsFamilyLoading(false);
      }
    };

    return (
      <div className="max-w-lg mx-auto my-4 space-y-6">
        {renderTopPwaUpdateBar()}

        <div className="p-6 sm:p-8 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-6">
          <div className="space-y-2">
            <div className="text-xs font-medium text-[var(--vault-accent)]">
              Dwuetapowa ochrona dostępu · Link Zaproszeniowy + Certyfikat Sprzętowy
            </div>
            <h2 className="text-xl font-bold font-display text-[var(--vault-text)]">
              {existingDevice && isDevicePending
                ? 'Oczekiwanie na akceptację konta przez Administratora lub Opiekuna'
                : 'Rozpoznano Twoje konto — autoryzuj to urządzenie'}
            </h2>
            <p className="text-sm text-[var(--vault-muted)]">
              Zgłoszono profil:{' '}
              <strong className="text-[var(--vault-text)]">
                {member.fullName} (login: {member.username})
              </strong>
              . Dostęp do skarbca otworzy się automatycznie w tej samej sekundzie (przez nasłuchiwanie czasu rzeczywistego <code>onSnapshot</code>), gdy tylko Administrator lub Zaufany Opiekun kliknie „Akceptuj”.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[var(--vault-muted)]">
                Model i system operacyjny:
              </span>
              <span className="font-mono font-semibold text-[var(--vault-text)]">
                {detectedDevice.hardwareModelOs} ({detectedDevice.deviceName})
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[var(--vault-muted)]">
                Sygnatura sprzętowa (do klucza prywatnego):
              </span>
              <span className="font-mono font-semibold text-[var(--vault-accent)]">
                {detectedDevice.hardwareSignatureHash}
              </span>
            </div>
          </div>

          {!existingDevice || isDeviceRevoked ? (
            <form onSubmit={handleRequestAuth} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                  Nazwa pomocnicza tego urządzenia (widoczna dla Ciebie i Admina)
                </label>
                <input
                  type="text"
                  value={deviceCustomLabel}
                  onChange={(e) => setDeviceCustomLabel(e.target.value)}
                  placeholder="np. Telefon Mamy, Laptop w salonie"
                  maxLength={80}
                  className="w-full px-3 py-2 text-sm rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
              </div>

              {errorMsg && (
                <div className="p-3 rounded-lg border border-[var(--vault-danger)] text-xs text-[var(--vault-danger)]">
                  {errorMsg}
                </div>
              )}

              <button
                type="submit"
                disabled={isFamilyLoading}
                className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 text-sm font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl transition-colors cursor-pointer"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>
                  {isFamilyLoading
                    ? 'Wysyłanie prośby...'
                    : 'Autoryzuj moje urządzenie'}
                </span>
              </button>
            </form>
          ) : (
            <div className="p-4 rounded-xl border border-[var(--vault-accent)] bg-[var(--vault-bg)] space-y-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-[var(--vault-text)]">
                <Clock className="w-4 h-4 text-[var(--vault-accent)]" />
                <span>
                  {isAccountPending
                    ? 'Konto zostało utworzone i oczekuje na zatwierdzenie!'
                    : 'Urządzenie oczekuje na zatwierdzenie!'}
                </span>
              </div>
              <p className="text-xs text-[var(--vault-muted)]">
                Gdy Administrator lub Zaufany Opiekun kliknie „Akceptuj”, skarbiec otworzy się automatycznie. Przy kolejnych wejściach będziesz widzieć już tylko ekran logowania.
              </p>
            </div>
          )}

          <div className="pt-2 border-t border-[var(--vault-border)] flex justify-between items-center text-xs">
            <button
              type="button"
              onClick={onCancelPendingState}
              className="text-[var(--vault-muted)] hover:text-[var(--vault-text)] underline cursor-pointer"
            >
              Przejdź do ekranu logowania
            </button>
            <span className="text-[var(--vault-muted)]">
              Cloud Firestore onSnapshot aktywny
            </span>
          </div>
        </div>
      </div>
    );
  }

  // Native Firebase Auth Google login handler (Admin Instance)
  const handleAdminClick = async (forceAccountSelection = false) => {
    setErrorMsg(null);
    setUnauthorizedDomainHost(null);
    setIsAdminLoading(true);
    try {
      let userToUse =
        !forceAccountSelection &&
        auth.currentUser &&
        !auth.currentUser.isAnonymous
          ? auth.currentUser
          : null;
      if (!userToUse) {
        if (forceAccountSelection) {
          googleProvider.setCustomParameters({ prompt: 'select_account' });
        } else {
          const hintEmail =
            vaultConfig?.adminEmail &&
            !vaultConfig.adminEmail.endsWith('.local')
              ? vaultConfig.adminEmail
              : undefined;
          googleProvider.setCustomParameters(
            hintEmail ? { login_hint: hintEmail } : {}
          );
        }
        const credential = await signInWithPopup(auth, googleProvider);
        userToUse = credential.user;
      }

      await onAdminGoogleLogin({
        firebaseUser: userToUse,
        masterPassword: adminMasterPasswordInput.trim() || undefined,
      });
    } catch (err) {
      const code = (err as { code?: string })?.code || '';
      const rawMessage = err instanceof Error ? err.message : String(err);
      if (code === 'auth/unauthorized-domain' || rawMessage.includes('auth/unauthorized-domain')) {
        const host =
          typeof window !== 'undefined'
            ? window.location.hostname
            : 'stradowski-byte.github.io';
        setUnauthorizedDomainHost(host);
        setErrorMsg(
          `Domena „${host}” nie jest jeszcze dodana do autoryzowanych domen w Firebase Auth. Dodaj ją w Firebase Console -> Authentication -> Settings -> Authorized domains.`
        );
      } else if (
        code === 'auth/configuration-not-found' ||
        code === 'auth/operation-not-allowed' ||
        rawMessage.includes('auth/configuration-not-found') ||
        rawMessage.includes('auth/operation-not-allowed')
      ) {
        const diagnosticMessage = await diagnoseFirebaseAuthConfiguration();
        setErrorMsg(diagnosticMessage);
      } else if (code === 'auth/popup-closed-by-user' || rawMessage.includes('auth/popup-closed-by-user')) {
        setErrorMsg('Zamknięto okno logowania Google przed wyborem konta.');
      } else {
        setErrorMsg(
          err instanceof Error
            ? err.message
            : 'Nie udało się zalogować jako Administrator przez Firebase Auth.'
        );
      }
    } finally {
      setIsAdminLoading(false);
    }
  };

  const handleFamilyLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (lockoutSecondsLeft > 0) {
      setErrorMsg(
        `Ochrona anty-Brute-Force: odczekaj jeszcze ${lockoutSecondsLeft}s przed kolejną próbą logowania.`
      );
      return;
    }
    setErrorMsg(null);
    setIsFamilyLoading(true);
    try {
      await onLoginWithCredentials(
        loginUsername.trim().toLowerCase(),
        loginPassword
      );
      setFailedLoginAttempts(0);
      setLockoutSecondsLeft(0);
    } catch (err) {
      const nextFails = failedLoginAttempts + 1;
      setFailedLoginAttempts(nextFails);
      if (nextFails >= 5) {
        setLockoutSecondsLeft(60);
        setErrorMsg(
          'Wykryto 5 nieudanych prób logowania z rzędu! Formularz został tymczasowo zablokowany na 60 sekund (Ochrona anty-Brute-Force).'
        );
      } else {
        const baseMsg =
          err instanceof Error ? err.message : 'Błąd podczas logowania.';
        setErrorMsg(`${baseMsg} (Próba ${nextFails}/5)`);
      }
    } finally {
      setIsFamilyLoading(false);
    }
  };

  const handleInviteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifiedInvite) return;
    setErrorMsg(null);

    if (verifiedInvite.purpose === 'account_recovery') {
      if (!verifiedInvite.targetMemberId) {
        setErrorMsg('Brak przypisanego konta domownika w linku ratunkowym.');
        return;
      }
      if (!regUsername.trim() || regPassword.length < 4) {
        setErrorMsg('Podaj login oraz nowe hasło (minimum 4 znaki).');
        return;
      }
      setIsFamilyLoading(true);
      try {
        await onRecoverMemberAccountWithInvite({
          inviteToken: verifiedInvite.token,
          targetMemberId: verifiedInvite.targetMemberId,
          newUsername: regUsername.trim().toLowerCase(),
          newPassword: regPassword,
          setupBiometrics: setupBiometricsOnInvite,
        });
        clearInviteFromUrlAndState();
      } catch (err) {
        setErrorMsg(
          err instanceof Error
            ? err.message
            : 'Nie udało się zresetować dostępu z linku ratunkowym.'
        );
      } finally {
        setIsFamilyLoading(false);
      }
      return;
    }

    // New member registration via invitation link
    if (!regFullName.trim() || !regUsername.trim() || regPassword.length < 4) {
      setErrorMsg(
        'Wpisz swoje imię i nazwisko, login oraz hasło (min. 4 znaki).'
      );
      return;
    }

    setIsFamilyLoading(true);
    try {
      await onRegisterMemberAccountWithInvite({
        inviteToken: verifiedInvite.token,
        fullName: regFullName.trim(),
        username: regUsername.trim().toLowerCase(),
        password: regPassword,
        setupBiometrics: setupBiometricsOnInvite,
      });
      clearInviteFromUrlAndState();
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'Błąd podczas zakładania konta z zaproszenia.'
      );
    } finally {
      setIsFamilyLoading(false);
    }
  };

  const handleBiometricClick = async () => {
    setErrorMsg(null);
    setIsFamilyLoading(true);
    try {
      await onUnlockWithBiometrics();
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'Nie udało się odblokować odciskiem palca.'
      );
    } finally {
      setIsFamilyLoading(false);
    }
  };

  const rememberedAdminEmail =
    firebaseAuthUser?.email ||
    (vaultConfig?.adminEmail && !vaultConfig.adminEmail.endsWith('.local')
      ? vaultConfig.adminEmail
      : null);

  const fbInfo = getFirebaseProjectInfo();

  // Determine whether this device is operating in Family Member mode (Zero Admin UI) or Admin Instance mode.
  // Any device with an invite link or `deviceRole === 'member'` ALWAYS shows the Family Member login & invite UI!
  const isFamilyMemberMode =
    Boolean(inviteToken) || deviceRole === 'member';

  return (
    <div className="max-w-lg mx-auto my-4 space-y-6">
      {/* MAIN PAGE QUICK ACTION BAR: PWA Status + Update */}
      {renderTopPwaUpdateBar()}

      {/* =====================================================================
          MODE 1: FAMILY MEMBER FIRST-TIME INVITATION ("TYLKO UTWÓRZ KONTO")
         ===================================================================== */}
      {inviteToken && (
        <div className="p-6 rounded-xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] space-y-5">
          {isInitializingHandoff || isVerifyingInvite ? (
            <div className="py-6 text-center text-xs text-[var(--vault-muted)] flex flex-col items-center gap-2">
              <RefreshCw className="w-5 h-5 animate-spin text-[var(--vault-accent)]" />
              <span>
                Weryfikacja kryptograficznego linku zaproszeniowego w Cloud Firestore ({fbInfo.projectId})...
              </span>
            </div>
          ) : inviteError || !verifiedInvite ? (
            <div className="space-y-4">
              <div className="flex items-start gap-2.5 text-[var(--vault-danger)]">
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                <div className="space-y-1.5">
                  <h2 className="text-base font-bold font-display text-[var(--vault-text)]">
                    Nie udało się zweryfikować linku zaproszeniowego
                  </h2>
                  <p className="text-xs text-[var(--vault-danger)] leading-relaxed">
                    {inviteError ||
                      'Ten link został już wykorzystany lub stracił ważność. Poproś Administratora o nowy link lub zaloguj się w formularzu poniżej.'}
                  </p>
                  <div className="p-2.5 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[11px] font-mono text-[var(--vault-muted)]">
                    Projekt Firebase: <strong className="text-[var(--vault-text)]">{fbInfo.projectId}</strong> · Token: <strong className="text-[var(--vault-text)]">{inviteToken}</strong>
                  </div>
                </div>
              </div>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <button
                  type="button"
                  onClick={() => setRetryInviteCounter((c) => c + 1)}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 py-2.5 px-4 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5 shrink-0" />
                  <span>Ponów weryfikację linku</span>
                </button>
                <button
                  type="button"
                  onClick={clearInviteFromUrlAndState}
                  className="py-2.5 px-4 text-xs font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-bg)] rounded-lg cursor-pointer"
                >
                  Ukryj komunikat zaproszenia
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleInviteSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2 text-xs">
                  <span className="font-semibold text-[var(--vault-accent)] flex items-center gap-1.5">
                    <Link2 className="w-3.5 h-3.5" />
                    <span>
                      {verifiedInvite.purpose === 'account_recovery'
                        ? 'Link Ratunkowy — Odzyskiwanie Dostępu'
                        : 'Zaproszenie do Skarbca Rodzinnego'}
                    </span>
                  </span>
                  <span className="font-mono text-[11px] text-[var(--vault-muted)]">
                    {verifiedInvite.mode === 'single_use'
                      ? 'Link jednorazowy'
                      : 'Link czasowy (24h)'}
                  </span>
                </div>

                <h2 className="text-xl font-bold font-display text-[var(--vault-text)]">
                  {verifiedInvite.purpose === 'account_recovery'
                    ? `Ustaw nowe hasło dla: ${
                        verifiedInvite.targetMemberName || 'Domownika'
                      }`
                    : 'Utwórz swoje konto w Skarbcu Rodzinnym'}
                </h2>

                <p className="text-xs text-[var(--vault-muted)]">
                  {verifiedInvite.purpose === 'account_recovery' ? (
                    <>
                      Link wygenerowany przez:{' '}
                      <strong className="text-[var(--vault-text)]">
                        {verifiedInvite.createdByMemberName}
                      </strong>
                      . Wpisz poniżej swoje nowe hasło — Twoje konto oraz to urządzenie zostaną od razu odblokowane.
                    </>
                  ) : (
                    <>
                      Zaproszenie utworzone przez:{' '}
                      <strong className="text-[var(--vault-text)]">
                        {verifiedInvite.createdByMemberName}
                      </strong>{' '}
                      ({verifiedInvite.invitedLabel}). Wpisz swoje imię i nazwisko oraz ustal login i hasło. Po zatwierdzeniu konta przy kolejnych wejściach będziesz widzieć już tylko ekran logowania.
                    </>
                  )}
                </p>
              </div>

              {errorMsg && (
                <div className="p-3 rounded-lg border border-[var(--vault-danger)] text-xs text-[var(--vault-danger)]">
                  {errorMsg}
                </div>
              )}

              {verifiedInvite.purpose === 'new_member' && (
                <div>
                  <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                    Imię i nazwisko
                  </label>
                  <input
                    type="text"
                    value={regFullName}
                    onChange={(e) => handleFullNameChange(e.target.value)}
                    placeholder="np. Anna Kowalska"
                    required
                    maxLength={100}
                    className="w-full px-3 py-2 text-sm rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                  {verifiedInvite.purpose === 'account_recovery'
                    ? 'Twój login do skarbca (możesz go zostawić lub zmienić)'
                    : 'Twój login do odblokowania skarbca'}
                </label>
                <input
                  type="text"
                  value={regUsername}
                  onChange={(e) => {
                    setRegUsername(e.target.value);
                    setRegUsernameManuallyEdited(true);
                  }}
                  placeholder="np. mama, anna, piotr"
                  required
                  maxLength={60}
                  className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                  {verifiedInvite.purpose === 'account_recovery'
                    ? 'Wpisz nowe hasło (min. 4 znaki)'
                    : 'Ustal własne hasło (min. 4 znaki)'}
                </label>
                <input
                  type="password"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  placeholder="Min. 4 znaki..."
                  required
                  minLength={4}
                  maxLength={128}
                  className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
              </div>

              <label className="flex items-start gap-2.5 p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-xs text-[var(--vault-text)] cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={setupBiometricsOnInvite}
                  onChange={(e) => setSetupBiometricsOnInvite(e.target.checked)}
                  className="mt-0.5"
                />
                <div>
                  <span className="font-semibold block">
                    Włącz odblokowywanie odciskiem palca / FaceID na tym urządzeniu
                  </span>
                  <span className="text-[11px] text-[var(--vault-muted)]">
                    Pozwoli Ci wchodzić do skarbca jednym dotknięciem bez konieczności pamiętania hasła.
                  </span>
                </div>
              </label>

              <div className="flex flex-col sm:flex-row items-center gap-2 pt-1">
                <button
                  type="submit"
                  disabled={isFamilyLoading}
                  className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 text-sm font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl transition-colors cursor-pointer"
                >
                  {verifiedInvite.purpose === 'account_recovery' ? (
                    <>
                      <KeyRound className="w-4 h-4" />
                      <span>
                        {isFamilyLoading
                          ? 'Zapisywanie nowego hasła...'
                          : 'Zapisz nowe hasło i odblokuj moje konto'}
                      </span>
                    </>
                  ) : (
                    <>
                      <UserPlus className="w-4 h-4" />
                      <span>
                        {isFamilyLoading
                          ? 'Tworzenie konta...'
                          : 'Utwórz konto w skarbcu'}
                      </span>
                    </>
                  )}
                </button>
              </div>

              <div className="pt-2 border-t border-[var(--vault-border)] flex justify-between items-center text-xs">
                <button
                  type="button"
                  onClick={clearInviteFromUrlAndState}
                  className="text-[var(--vault-muted)] hover:text-[var(--vault-text)] underline cursor-pointer"
                >
                  Masz już aktywne konto? Przejdź do logowania
                </button>
              </div>
            </form>
          )}
        </div>
      )}

      {/* =====================================================================
          MODE 2: FAMILY MEMBER LOGIN FORM (ALWAYS VISIBLE FOR FAMILY MEMBERS)
         ===================================================================== */}
      {isFamilyMemberMode && (
        <>
          {biometricProfile && (
            <div className="p-5 rounded-xl border border-[var(--vault-accent)] bg-[var(--vault-surface)] space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs text-[var(--vault-muted)]">
                    Szybkie odblokowanie biometryczne (WebAuthn)
                  </div>
                  <div className="text-sm font-semibold text-[var(--vault-text)]">
                    {biometricProfile.fullName} ({biometricProfile.username})
                  </div>
                </div>
                <CheckCircle2 className="w-5 h-5 text-[var(--vault-success)]" />
              </div>
              <button
                type="button"
                onClick={handleBiometricClick}
                disabled={isFamilyLoading}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg transition-colors cursor-pointer"
              >
                <Fingerprint className="w-4 h-4" />
                <span>Odblokuj skarbiec odciskiem palca (1-Dotknięcie)</span>
              </button>
            </div>
          )}

          <div className="p-6 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-5">
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-2 text-xs text-[var(--vault-muted)]">
                <span className="font-semibold text-[var(--vault-text)]">
                  Logowanie do Skarbca Rodzinnego
                </span>
                <span className="inline-flex items-center gap-1">
                  {detectedDevice.clientMode === 'pwa' ? (
                    <Smartphone className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                  ) : (
                    <Monitor className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                  )}
                  <span>{detectedDevice.deviceName}</span>
                </span>
              </div>
              <p className="text-xs text-[var(--vault-muted)]">
                Wpisz swój login oraz hasło. Klucz deszyfrujący Twoje prywatne hasła powstaje lokalnie z połączenia Twojego hasła, profilu sprzętowego tego urządzenia oraz certyfikatu zatwierdzenia.
              </p>
              <div className="p-2.5 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-[var(--vault-muted)] mt-2">
                <span>
                  Profil sprzętowy:{' '}
                  <strong className="text-[var(--vault-text)]">
                    {detectedDevice.hardwareModelOs} ·{' '}
                    {detectedDevice.clientMode === 'pwa' ? 'PWA' : 'Browser'}
                  </strong>
                </span>
                <span className="text-[var(--vault-accent)] font-semibold">
                  {detectedDevice.hardwareSignatureHash}
                </span>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3 rounded-lg border border-[var(--vault-danger)] text-xs text-[var(--vault-danger)] break-words">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleFamilyLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                  Twój login
                </label>
                <input
                  type="text"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  placeholder="np. mama, brat, anna"
                  required
                  maxLength={80}
                  className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[var(--vault-muted)] mb-1">
                  Hasło
                </label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Twoje hasło..."
                  required
                  maxLength={128}
                  className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
              </div>

              <button
                type="submit"
                disabled={isFamilyLoading || lockoutSecondsLeft > 0}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] disabled:opacity-50 rounded-xl transition-colors cursor-pointer tabular-nums"
              >
                <LogIn className="w-4 h-4" />
                <span>
                  {lockoutSecondsLeft > 0
                    ? `Blokada anty-Brute-Force (${lockoutSecondsLeft}s)`
                    : isFamilyLoading
                      ? 'Weryfikacja certyfikatu sprzętowego...'
                      : 'Zaloguj się do skarbca'}
                </span>
              </button>
            </form>

            {/* Discreet recovery / invite link paste */}
            <div className="pt-3 border-t border-[var(--vault-border)] space-y-2.5 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[var(--vault-muted)]">
                <span>Otrzymałeś nowy link ratunkowy lub zaproszeniowy?</span>
                <button
                  type="button"
                  onClick={() => setShowManualInviteBox((v) => !v)}
                  className="text-[var(--vault-accent)] hover:underline font-medium cursor-pointer shrink-0"
                >
                  {showManualInviteBox
                    ? 'Ukryj pole linku'
                    : 'Wklej otrzymany link'}
                </button>
              </div>

              {showManualInviteBox && (
                <form
                  onSubmit={handleApplyManualInvite}
                  className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1"
                >
                  <input
                    type="text"
                    value={manualInviteInput}
                    onChange={(e) => setManualInviteInput(e.target.value)}
                    placeholder="Wklej tutaj link od Administratora..."
                    className="flex-1 px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)]"
                  />
                  <button
                    type="submit"
                    className="px-3.5 py-1.5 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-lg cursor-pointer shrink-0"
                  >
                    Otwórz link
                  </button>
                </form>
              )}

              <div className="pt-2 border-t border-[var(--vault-border)] flex flex-wrap items-center justify-between gap-2 text-[var(--vault-muted)]">
                <span>Jesteś Administratorem skarbca?</span>
                <button
                  type="button"
                  onClick={() => {
                    clearInviteFromUrlAndState();
                    setDeviceInstanceRole('admin');
                    setDeviceRole('admin');
                  }}
                  className="text-[var(--vault-accent)] hover:underline font-semibold cursor-pointer"
                >
                  Przełącz na logowanie Google Administratora
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* =====================================================================
          MODE 3: ADMIN INSTANCE (After loading local Firebase Config JSON)
         ===================================================================== */}
      {!inviteToken && !isFamilyMemberMode && (
        <div className="p-6 sm:p-7 rounded-xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] space-y-5 overflow-hidden">
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2 text-xs">
              <span className="inline-flex items-center gap-1.5 font-semibold text-[var(--vault-accent)]">
                <Cloud className="w-4 h-4 shrink-0" />
                <span>Instancja Głównego Administratora · Firebase Auth</span>
              </span>
              <button
                type="button"
                onClick={() => {
                  setRawFirebaseJsonInput(exportActiveFirebaseConfigJson());
                  setShowChangeFirebaseConfigModal(true);
                }}
                className="inline-flex items-center gap-1 text-[11px] font-mono text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer"
                title="Zmień lub podglądnij załadowany config Firebase JSON"
              >
                <Settings className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                <span>
                  {fbInfo.projectId} · {fbInfo.apiKeyMasked}
                </span>
              </button>
            </div>

            <h1 className="text-xl font-bold font-display text-[var(--vault-text)]">
              {isVaultInitialized
                ? 'Odblokuj Skarbiec Głównego Administratora'
                : 'Zaloguj przez Google i utwórz Skarbiec w Cloud Firestore'}
            </h1>
            <p className="text-xs text-[var(--vault-muted)] leading-relaxed">
              Konfiguracja Firebase (<code>{fbInfo.projectId}</code>) jest załadowana lokalnie na tym urządzeniu. Zaloguj się kontem Google, aby {isVaultInitialized ? 'wejść do panelu Administratora' : 'zainicjalizować nową instancję skarbca i zostać jej Administratorem'}.
            </p>
          </div>

          {!isVaultInitialized && (
            <div className="p-4 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-2">
              <label className="block text-[11px] font-medium text-[var(--vault-muted)]">
                Opcjonalne hasło główne Admina (ułatwia awaryjne logowanie loginem <code className="font-mono text-[var(--vault-accent)]">admin</code>)
              </label>
              <input
                type="password"
                value={adminMasterPasswordInput}
                onChange={(e) => setAdminMasterPasswordInput(e.target.value)}
                placeholder="Opcjonalne hasło (min. 4 znaki)..."
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
              />
            </div>
          )}

          {unauthorizedDomainHost && (
            <div className="p-3.5 rounded-xl border border-[var(--vault-danger)] bg-[var(--vault-bg)] space-y-2.5 text-xs">
              <div className="font-semibold text-[var(--vault-danger)]">
                Wymagana jednorazowa autoryzacja domeny w Firebase Console (30 sek.):
              </div>
              <p className="text-[var(--vault-muted)] leading-relaxed">
                Domena{' '}
                <code className="font-mono font-bold text-[var(--vault-text)]">
                  {unauthorizedDomainHost}
                </code>{' '}
                musi zostać dopisana do listy <strong>Authorized domains</strong> w projekcie Firebase (<code>{fbInfo.projectId}</code>).
              </p>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard
                      .writeText(unauthorizedDomainHost)
                      .catch(() => {});
                    setCopiedDomainHost(true);
                    setTimeout(() => setCopiedDomainHost(false), 2500);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] hover:bg-[var(--vault-surface-hover)] text-[var(--vault-text)] font-semibold cursor-pointer"
                >
                  {copiedDomainHost ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--vault-success)]" />
                      <span>Skopiowano: {unauthorizedDomainHost}</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                      <span>1. Kopiuj domenę ({unauthorizedDomainHost})</span>
                    </>
                  )}
                </button>
                <a
                  href={`https://console.firebase.google.com/project/${fbInfo.projectId}/authentication/settings`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] text-[#FAF7F2] font-semibold"
                >
                  <span>2. Otwórz Firebase Console (Authorized domains)</span>
                </a>
              </div>
            </div>
          )}

          {errorMsg && !unauthorizedDomainHost && (
            <div className="p-3.5 rounded-xl border border-[var(--vault-danger)] bg-[var(--vault-bg)] space-y-2.5 text-xs">
              {errorMsg.includes('Missing or insufficient permissions') ? (
                <>
                  <div className="font-semibold text-[var(--vault-danger)]">
                    Wymagana publikacja reguł bezpieczeństwa w Firestore Database → Rules:
                  </div>
                  <p className="text-[var(--vault-muted)] leading-relaxed">
                    Logowanie Google (<strong>{rememberedAdminEmail || 'Administrator'}</strong>) przeszło pomyślnie! Nowa baza danych w projekcie <code className="font-mono font-bold text-[var(--vault-text)]">{fbInfo.projectId}</code> ma jednak domyślnie zablokowany zapis (<code className="font-mono">allow read, write: if false;</code>). Skopiuj reguły przyciskiem poniżej, wklej je w konsoli Firebase w zakładce <strong>Firestore Database → Rules</strong> i kliknij <strong>Publish</strong>:
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard
                          .writeText(PRODUCTION_FIRESTORE_RULES)
                          .catch(() => {});
                        setCopiedFirestoreRules(true);
                        setTimeout(() => setCopiedFirestoreRules(false), 3000);
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-[var(--vault-accent)] bg-[var(--vault-surface)] hover:bg-[var(--vault-surface-hover)] text-[var(--vault-text)] font-semibold cursor-pointer"
                    >
                      {copiedFirestoreRules ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-[var(--vault-success)]" />
                          <span>Skopiowano całe firestore.rules!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                          <span>1. Kopiuj gotowe reguły (firestore.rules)</span>
                        </>
                      )}
                    </button>
                    <a
                      href={`https://console.firebase.google.com/project/${fbInfo.projectId}/firestore/databases/-default-/rules`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] text-[#FAF7F2] font-semibold"
                    >
                      <span>2. Otwórz Firestore Database → Rules</span>
                    </a>
                  </div>
                </>
              ) : (
                <div className="text-[var(--vault-danger)] break-words">
                  {errorMsg}
                </div>
              )}
            </div>
          )}

          <div className="space-y-2">
            <button
              type="button"
              onClick={() => handleAdminClick(false)}
              disabled={isAdminLoading || isFamilyLoading}
              className="gsi-material-button !w-full"
            >
              <div className="gsi-material-button-content-wrapper">
                <div className="gsi-material-button-icon">
                  <svg
                    version="1.1"
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 48 48"
                    style={{ display: 'block' }}
                  >
                    <path
                      fill="#EA4335"
                      d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
                    ></path>
                    <path
                      fill="#4285F4"
                      d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
                    ></path>
                    <path
                      fill="#FBBC05"
                      d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
                    ></path>
                    <path
                      fill="#34A853"
                      d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
                    ></path>
                    <path fill="none" d="M0 0h48v48H0z"></path>
                  </svg>
                </div>
                <span className="gsi-material-button-contents">
                  {isAdminLoading
                    ? 'Logowanie przez Firebase Auth...'
                    : rememberedAdminEmail
                      ? `Zaloguj jako Administrator (${rememberedAdminEmail})`
                      : 'Zaloguj przez Google (Administrator)'}
                </span>
              </div>
            </button>

            {rememberedAdminEmail && (
              <div className="flex items-center justify-between gap-2 text-[11px] text-[var(--vault-muted)] px-1">
                <span>
                  Konto Admina:{' '}
                  <strong className="text-[var(--vault-text)]">
                    {rememberedAdminEmail}
                  </strong>
                </span>
                <button
                  type="button"
                  onClick={() => handleAdminClick(true)}
                  disabled={isAdminLoading}
                  className="text-[var(--vault-accent)] hover:underline font-medium cursor-pointer"
                >
                  Zmień konto Google
                </button>
              </div>
            )}
          </div>

          {/* Optional password / biometric unlock or switch to member mode */}
          <div className="pt-3 border-t border-[var(--vault-border)] space-y-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 text-[var(--vault-muted)]">
              <button
                type="button"
                onClick={() =>
                  setShowAdminFallbackPasswordLogin((prev) => !prev)
                }
                className="text-[var(--vault-accent)] hover:underline font-medium cursor-pointer"
              >
                {showAdminFallbackPasswordLogin
                  ? 'Ukryj logowanie loginem i hasłem'
                  : 'Logowanie awaryjne loginem i hasłem'}
              </button>

              <div className="flex flex-wrap items-center gap-3">
                {isVaultInitialized && (
                  <button
                    type="button"
                    onClick={() => {
                      setDeviceInstanceRole('member');
                      setDeviceRole('member');
                    }}
                    className="text-[var(--vault-muted)] hover:text-[var(--vault-text)] underline cursor-pointer"
                  >
                    Widok Domownika
                  </button>
                )}

                {!isAiStudioPreview && (
                  <button
                    type="button"
                    onClick={() => {
                      setRawFirebaseJsonInput(exportActiveFirebaseConfigJson());
                      setShowChangeFirebaseConfigModal(true);
                    }}
                    className="text-[var(--vault-muted)] hover:text-[var(--vault-text)] underline cursor-pointer"
                  >
                    Sprawdź / wgraj inny plik JSON Firebase
                  </button>
                )}
              </div>
            </div>

            {showAdminFallbackPasswordLogin && (
              <form
                onSubmit={handleFamilyLoginSubmit}
                className="p-3.5 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-3"
              >
                <div>
                  <label className="block text-[11px] font-medium text-[var(--vault-muted)] mb-1">
                    Login (np. admin)
                  </label>
                  <input
                    type="text"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder="admin"
                    required
                    className="w-full px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-[var(--vault-muted)] mb-1">
                    Hasło
                  </label>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    placeholder="Hasło..."
                    required
                    className="w-full px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isFamilyLoading || lockoutSecondsLeft > 0}
                  className="w-full py-2 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] disabled:opacity-50 rounded-lg cursor-pointer tabular-nums"
                >
                  {lockoutSecondsLeft > 0
                    ? `Blokada anty-Brute-Force (${lockoutSecondsLeft}s)`
                    : 'Zaloguj loginem i hasłem'}
                </button>
              </form>
            )}

            <FirebaseSetupGuideDropdown />
          </div>
        </div>
      )}
    </div>
  );
};
