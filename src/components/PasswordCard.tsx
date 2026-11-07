import React, { useEffect, useMemo, useState } from 'react';
import {
  Copy,
  Check,
  Eye,
  EyeOff,
  ExternalLink,
  KeyRound,
  RefreshCw,
  Trash2,
  Users,
  Lock,
  ChevronDown,
  ChevronUp,
  UserPlus,
  ZoomIn,
  X,
  Star,
  QrCode,
  Tv,
  BellRing,
  AlertTriangle,
  Send,
  History,
  RotateCcw,
  Clock,
  FileText,
  Shield,
} from 'lucide-react';
import {
  DecryptedPrivatePayload,
  getEffectiveCoAdminPermissions,
  isPrimaryAdmin,
  Member,
  parsePasswordCardExtras,
  parseSubAccounts,
  PasswordHistoryEntry,
  PasswordRecord,
  PasswordSosReason,
  SubAccountEntry,
  VaultCategory,
} from '../types/vault';
import {
  generateStrongPassword,
  generateTotpCode,
  sanitizeSafeHttpUrl,
} from '../lib/crypto';
import { prepareOneClickLaunch } from '../lib/deviceAndBiometrics';
import { buildWifiQrPayload, generateQrCodeMatrix } from '../lib/qrCodeSvg';

interface PasswordCardProps {
  record: PasswordRecord;
  decryptedPrivate?: DecryptedPrivatePayload | null;
  categories: VaultCategory[];
  currentMember: Member;
  allMembers: Member[];
  clipboardClearSeconds: number;
  activeHardwareCertFingerprint?: string | null;
  activeHardwareModeLabel?: string | null;
  onQuickUpdatePassword: (record: PasswordRecord, newPassword: string) => Promise<void>;
  onUpdateAllowedMembers: (record: PasswordRecord, memberIds: string[]) => Promise<void>;
  onUpdateSubAccounts: (
    record: PasswordRecord,
    nextSubAccounts: SubAccountEntry[],
    additionalAllowedMemberId?: string
  ) => Promise<void>;
  onToggleRevealToAdmin?: (
    record: PasswordRecord,
    nextReveal: boolean
  ) => Promise<void>;
  onToggleFavorite?: (record: PasswordRecord) => Promise<void>;
  onCreateSosRequest?: (
    record: PasswordRecord,
    reason: PasswordSosReason
  ) => Promise<void>;
  onResolveSosRequest?: (
    record: PasswordRecord,
    responseCode: string,
    newPassword?: string
  ) => Promise<void>;
  onClearSosRequest?: (record: PasswordRecord) => Promise<void>;
  onUpdateCardMetadata?: (
    record: PasswordRecord,
    metadata: { profilePinOrNote?: string; totpSecret?: string }
  ) => Promise<void>;
  onDeleteRecord: (record: PasswordRecord) => Promise<void>;
  onStartClipboardCountdown: (seconds: number, label: string) => void;
}

const PasswordCardComponent: React.FC<PasswordCardProps> = ({
  record,
  decryptedPrivate,
  categories,
  currentMember,
  allMembers,
  clipboardClearSeconds,
  activeHardwareCertFingerprint,
  activeHardwareModeLabel,
  onQuickUpdatePassword,
  onUpdateAllowedMembers,
  onUpdateSubAccounts,
  onToggleRevealToAdmin,
  onToggleFavorite,
  onCreateSosRequest,
  onResolveSosRequest,
  onClearSosRequest,
  onUpdateCardMetadata,
  onDeleteRecord,
  onStartClipboardCountdown,
}) => {
  const [isDetailsOpen, setIsDetailsOpen] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);
  const [newPasswordInput, setNewPasswordInput] = useState('');
  const [isSavingPassword, setIsSavingPassword] = useState(false);
  const [isEditingAccess, setIsEditingAccess] = useState(false);
  const [selectedMemberIds, setSelectedMemberIds] = useState<string[]>(
    record.allowedMemberIds
  );
  const [isSavingAccess, setIsSavingAccess] = useState(false);
  const [isTogglingReveal, setIsTogglingReveal] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [magnifiedViewData, setMagnifiedViewData] = useState<{
    title: string;
    subtitle: string;
    login: string;
    password: string;
    tvAuthCode?: string;
  } | null>(null);

  // Favorites, Wi-Fi QR Modal & Owner-Routed SOS / TV Code state
  const [isTogglingFavorite, setIsTogglingFavorite] = useState(false);
  const [isQrModalOpen, setIsQrModalOpen] = useState(false);
  const [wifiSsidInput, setWifiSsidInput] = useState('');
  const [isSosMenuOpen, setIsSosMenuOpen] = useState(false);
  const [isSendingSos, setIsSendingSos] = useState(false);
  const [ownerSosCodeInput, setOwnerSosCodeInput] = useState('');
  const [ownerSosNewPassInput, setOwnerSosNewPassInput] = useState('');
  const [isResolvingSos, setIsResolvingSos] = useState(false);
  const [lastAutoOpenedSosTimestamp, setLastAutoOpenedSosTimestamp] = useState<
    string | null
  >(null);

  // Sub-accounts state (for Netflix +10 zł / family multi-accounts)
  const [revealedSubPassIds, setRevealedSubPassIds] = useState<string[]>([]);
  const [editingSubAccountId, setEditingSubAccountId] = useState<string | null>(
    null
  );
  const [subNewPasswordInput, setSubNewPasswordInput] = useState('');
  const [isAddingSubAccount, setIsAddingSubAccount] = useState(false);
  const [newSubMemberId, setNewSubMemberId] = useState<string>('');
  const [newSubLabel, setNewSubLabel] = useState('Subkonto dodatkowe (+10 zł)');
  const [newSubLogin, setNewSubLogin] = useState('');
  const [newSubPassword, setNewSubPassword] = useState('');
  const [isSavingSubAccount, setIsSavingSubAccount] = useState(false);

  // Pillar 1 & 2 state: Password History Rollback, TV Profile PIN/Note & Live 2FA TOTP Clock
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [revealedHistoryIndices, setRevealedHistoryIndices] = useState<
    number[]
  >([]);
  const [restoringHistoryIdx, setRestoringHistoryIdx] = useState<number | null>(
    null
  );
  const [isEditingMetadata, setIsEditingMetadata] = useState(false);
  const [pinOrNoteInput, setPinOrNoteInput] = useState('');
  const [totpSecretInput, setTotpSecretInput] = useState('');
  const [isSavingMetadata, setIsSavingMetadata] = useState(false);
  const [liveTotpData, setLiveTotpData] = useState<{
    code: string;
    secondsRemaining: number;
  } | null>(null);

  const isPrivate = record.section === 'private';
  const isOwner = record.ownerId === currentMember.id;
  const isAdmin =
    isPrimaryAdmin(currentMember) ||
    getEffectiveCoAdminPermissions(currentMember).canManagePasswordsAndVod;
  const isOwnerOrAdmin = isOwner || isAdmin;
  const canManageAccess = !isPrivate && isOwnerOrAdmin;

  const cardExtras = useMemo(() => parsePasswordCardExtras(record), [record]);
  const isFavorite = cardExtras.favoriteMemberIds.includes(currentMember.id);
  const sosTicket = !isPrivate ? cardExtras.sosTicket : null;

  const effectiveProfilePinOrNote = isPrivate
    ? decryptedPrivate?.profilePinOrNote || cardExtras.profilePinOrNote
    : cardExtras.profilePinOrNote;

  const effectiveTotpSecret = isPrivate
    ? decryptedPrivate?.totpSecret || cardExtras.totpSecret
    : cardExtras.totpSecret;

  const effectivePasswordHistory: PasswordHistoryEntry[] = isPrivate
    ? decryptedPrivate?.passwordHistory || cardExtras.passwordHistory || []
    : cardExtras.passwordHistory || [];

  const subAccounts = !isPrivate ? parseSubAccounts(record) : [];
  const myAssignedSubAccount =
    subAccounts.find((sa) => sa.assignedMemberId === currentMember.id) || null;

  // Regular member who has an assigned sub-account sees ONLY their own sub-account
  const isSubAccountOnlyView = !isOwnerOrAdmin && Boolean(myAssignedSubAccount);

  const displayServiceName = isPrivate
    ? decryptedPrivate?.serviceName ||
      (record.revealToAdmin && record.serviceName !== 'ENC[PRIVATE]'
        ? record.serviceName
        : 'Zaszyfrowany wpis prywatny')
    : record.serviceName;

  const displayServiceUrl = isPrivate
    ? decryptedPrivate?.serviceUrl ??
      (record.revealToAdmin && record.serviceUrl !== 'ENC[PRIVATE]'
        ? record.serviceUrl
        : '')
    : record.serviceUrl;

  const displayLogin = isPrivate
    ? decryptedPrivate?.login ||
      (record.revealToAdmin && record.login !== 'ENC[PRIVATE]'
        ? record.login
        : 'ENC[PRIVATE]')
    : isSubAccountOnlyView && myAssignedSubAccount
      ? myAssignedSubAccount.login
      : record.login;

  const displayPassword = isPrivate
    ? decryptedPrivate?.password ||
      (record.revealToAdmin ? record.passwordValue : '')
    : isSubAccountOnlyView && myAssignedSubAccount
      ? myAssignedSubAccount.passwordValue
      : record.passwordValue;

  const canUpdatePrimaryDisplayedPassword =
    isOwner || (!isPrivate && isAdmin) || isSubAccountOnlyView;

  const displayCategoryId = isPrivate
    ? decryptedPrivate?.categoryId ||
      (record.revealToAdmin && record.categoryId !== 'ENC[PRIVATE]'
        ? record.categoryId
        : 'other')
    : record.categoryId;

  const categoryName =
    categories.find((c) => c.id === displayCategoryId)?.name || 'Inne';

  const activeMembers = allMembers.filter((m) => m.status === 'active');
  const allowedMemberNames = activeMembers
    .filter((m) => record.allowedMemberIds.includes(m.id))
    .map((m) => m.fullName);

  const handleCopy = async (
    text: string,
    fieldKey: string,
    isSecretPassword = false
  ) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(fieldKey);
      if (isSecretPassword) {
        onStartClipboardCountdown(clipboardClearSeconds, displayServiceName);
      }
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // ignore
    }
  };

  const handleOneClickLaunch = async () => {
    await prepareOneClickLaunch({
      serviceName: displayServiceName,
      serviceUrl: displayServiceUrl,
      login: displayLogin,
      password: displayPassword,
    });
    setCopiedField('launch');
    onStartClipboardCountdown(clipboardClearSeconds, displayServiceName);
    setTimeout(() => setCopiedField(null), 2500);

    const safeTargetUrl = sanitizeSafeHttpUrl(displayServiceUrl);
    if (safeTargetUrl) {
      const anchor = document.createElement('a');
      anchor.href = safeTargetUrl;
      anchor.target = '_blank';
      anchor.rel = 'noopener noreferrer';
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
    }
  };

  const handleSaveNewPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newPasswordInput.trim();
    if (!trimmed) return;
    setIsSavingPassword(true);
    try {
      if (isSubAccountOnlyView && myAssignedSubAccount) {
        const now = new Date().toISOString();
        const updatedList = subAccounts.map((sa) =>
          sa.id === myAssignedSubAccount.id
            ? { ...sa, passwordValue: trimmed, updatedAt: now }
            : sa
        );
        await onUpdateSubAccounts(record, updatedList);
      } else {
        await onQuickUpdatePassword(record, trimmed);
      }
      setIsUpdatingPassword(false);
      setNewPasswordInput('');
    } finally {
      setIsSavingPassword(false);
    }
  };

  const handleSaveSubAccountPassword = async (
    e: React.FormEvent,
    subAccountId: string
  ) => {
    e.preventDefault();
    const trimmed = subNewPasswordInput.trim();
    if (!trimmed) return;
    setIsSavingSubAccount(true);
    try {
      const now = new Date().toISOString();
      const updatedList = subAccounts.map((sa) =>
        sa.id === subAccountId
          ? { ...sa, passwordValue: trimmed, updatedAt: now }
          : sa
      );
      await onUpdateSubAccounts(record, updatedList);
      setEditingSubAccountId(null);
      setSubNewPasswordInput('');
    } finally {
      setIsSavingSubAccount(false);
    }
  };

  const handleAddSubAccountSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSubLogin.trim() || !newSubPassword.trim()) return;
    const targetMember =
      activeMembers.find((m) => m.id === newSubMemberId) || activeMembers[0];
    if (!targetMember) return;

    setIsSavingSubAccount(true);
    try {
      const now = new Date().toISOString();
      const randomSuffix = Math.random().toString(36).slice(2, 8);
      const newEntry: SubAccountEntry = {
        id: `sub_${randomSuffix}`,
        assignedMemberId: targetMember.id,
        assignedMemberName: targetMember.fullName,
        label: newSubLabel.trim() || 'Subkonto dodatkowe (+10 zł)',
        login: newSubLogin.trim(),
        passwordValue: newSubPassword.trim(),
        updatedAt: now,
      };
      const updatedList = [...subAccounts, newEntry];
      await onUpdateSubAccounts(record, updatedList, targetMember.id);
      setIsAddingSubAccount(false);
      setNewSubLogin('');
      setNewSubPassword('');
    } finally {
      setIsSavingSubAccount(false);
    }
  };

  const handleDeleteSubAccount = async (subAccountId: string) => {
    setIsSavingSubAccount(true);
    try {
      const updatedList = subAccounts.filter((sa) => sa.id !== subAccountId);
      await onUpdateSubAccounts(record, updatedList);
    } finally {
      setIsSavingSubAccount(false);
    }
  };

  const handleToggleMemberAccess = (memberId: string) => {
    setSelectedMemberIds((prev) =>
      prev.includes(memberId)
        ? prev.filter((id) => id !== memberId)
        : [...prev, memberId]
    );
  };

  const handleSaveAccess = async () => {
    setIsSavingAccess(true);
    try {
      const ensuredOwner = selectedMemberIds.includes(record.ownerId)
        ? selectedMemberIds
        : [...selectedMemberIds, record.ownerId];
      await onUpdateAllowedMembers(record, ensuredOwner);
      setIsEditingAccess(false);
    } finally {
      setIsSavingAccess(false);
    }
  };

  const effectiveUpdatedIso =
    isSubAccountOnlyView && myAssignedSubAccount
      ? myAssignedSubAccount.updatedAt
      : record.passwordUpdatedAt;

  const formattedPasswordUpdated = effectiveUpdatedIso
    ? new Date(effectiveUpdatedIso).toLocaleString('pl-PL', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : '';

  // Automatically pop open the huge Magnifier ("Lupa") modal on the requester's device when the password owner resolves the SOS ticket!
  useEffect(() => {
    if (
      sosTicket &&
      sosTicket.status === 'resolved' &&
      sosTicket.requestedByMemberId === currentMember.id &&
      sosTicket.resolvedAt &&
      sosTicket.resolvedAt !== lastAutoOpenedSosTimestamp
    ) {
      setLastAutoOpenedSosTimestamp(sosTicket.resolvedAt);
      setShowPassword(true);
      setMagnifiedViewData({
        title: displayServiceName,
        subtitle: sosTicket.responseCode
          ? `Kod autoryzacyjny TV od właściciela (${record.ownerName})`
          : `Zaktualizowane hasło od właściciela (${record.ownerName})`,
        login: displayLogin,
        password: displayPassword,
        tvAuthCode: sosTicket.responseCode || undefined,
      });
    }
  }, [
    sosTicket,
    currentMember.id,
    lastAutoOpenedSosTimestamp,
    displayServiceName,
    record.ownerName,
    displayLogin,
    displayPassword,
  ]);

  // Pillar 2: Live 6-digit 2FA TOTP Clock (updates every 1s in browser RAM via Web Crypto HMAC-SHA1)
  useEffect(() => {
    if (!effectiveTotpSecret || (!isDetailsOpen && !magnifiedViewData)) {
      setLiveTotpData(null);
      return;
    }
    let cancelled = false;
    const updateTotp = async () => {
      const res = await generateTotpCode(effectiveTotpSecret, Date.now());
      if (!cancelled) {
        setLiveTotpData(res);
      }
    };
    void updateTotp();
    const interval = window.setInterval(() => {
      void updateTotp();
    }, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [effectiveTotpSecret, isDetailsOpen, magnifiedViewData]);

  // Pillar 3: Privacy Shield (masks revealed passwords & closes modals when app/tab goes to background without logging out)
  useEffect(() => {
    const maskSensitiveState = () => {
      setShowPassword(false);
      setRevealedSubPassIds([]);
      setRevealedHistoryIndices([]);
      setMagnifiedViewData(null);
      setIsQrModalOpen(false);
    };
    const handleVisibility = () => {
      if (document.visibilityState === 'hidden') {
        maskSensitiveState();
      }
    };
    window.addEventListener('fsv-privacy-shield-activated', maskSensitiveState);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      window.removeEventListener(
        'fsv-privacy-shield-activated',
        maskSensitiveState
      );
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, []);

  // Pillar 2: Global Escape key closes Magnifier ("Lupa") or QR Code modals
  useEffect(() => {
    if (!magnifiedViewData && !isQrModalOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setMagnifiedViewData(null);
        setIsQrModalOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [magnifiedViewData, isQrModalOpen]);

  const handleSaveCardMetadataSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onUpdateCardMetadata || isSavingMetadata) return;
    setIsSavingMetadata(true);
    try {
      await onUpdateCardMetadata(record, {
        profilePinOrNote: pinOrNoteInput.trim() || undefined,
        totpSecret: totpSecretInput.trim() || undefined,
      });
      setIsEditingMetadata(false);
    } finally {
      setIsSavingMetadata(false);
    }
  };

  const handleRestoreHistoryEntry = async (
    entry: PasswordHistoryEntry,
    idx: number
  ) => {
    if (restoringHistoryIdx !== null) return;
    setRestoringHistoryIdx(idx);
    try {
      await onQuickUpdatePassword(record, entry.passwordValue);
    } finally {
      setRestoringHistoryIdx(null);
    }
  };

  const handleToggleFavoriteClick = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!onToggleFavorite || isTogglingFavorite) return;
    setIsTogglingFavorite(true);
    try {
      await onToggleFavorite(record);
    } finally {
      setIsTogglingFavorite(false);
    }
  };

  const handleSendSosClick = async (reason: PasswordSosReason) => {
    if (!onCreateSosRequest || isSendingSos) return;
    setIsSendingSos(true);
    try {
      await onCreateSosRequest(record, reason);
      setIsSosMenuOpen(false);
    } finally {
      setIsSendingSos(false);
    }
  };

  const handleOwnerResolveSosSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onResolveSosRequest || isResolvingSos) return;
    const codeTrimmed = ownerSosCodeInput.trim();
    const newPassTrimmed = ownerSosNewPassInput.trim();
    if (!codeTrimmed && !newPassTrimmed) return;
    setIsResolvingSos(true);
    try {
      await onResolveSosRequest(
        record,
        codeTrimmed,
        newPassTrimmed || undefined
      );
      setOwnerSosCodeInput('');
      setOwnerSosNewPassInput('');
    } finally {
      setIsResolvingSos(false);
    }
  };

  const handleClearSosClick = async () => {
    if (!onClearSosRequest) return;
    await onClearSosRequest(record);
  };

  const effectiveWifiSsid =
    wifiSsidInput.trim() ||
    (displayLogin && displayLogin !== 'ENC[PRIVATE]'
      ? displayLogin
      : displayServiceName);

  const wifiQrMatrix = useMemo(() => {
    if (!isQrModalOpen) return [];
    const payload = buildWifiQrPayload(effectiveWifiSsid, displayPassword);
    return generateQrCodeMatrix(payload);
  }, [isQrModalOpen, effectiveWifiSsid, displayPassword]);

  return (
    <div
      className={`p-4 rounded-xl border bg-[var(--vault-surface)] flex flex-col gap-3 transition-colors ${
        sosTicket?.status === 'pending' && isOwner
          ? 'border-[var(--vault-warning)]'
          : isFavorite
            ? 'border-[var(--vault-accent)]/70'
            : 'border-[var(--vault-border)]'
      }`}
    >
      {/* Compact Primary Row: Star Favorite, Service Name, Record Type & Owner + Actions ("Uruchom i zaloguj" + "Pokaż detale") */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div
          onClick={() => setIsDetailsOpen((v) => !v)}
          className="min-w-0 cursor-pointer select-none"
        >
          <div className="flex flex-wrap items-center gap-1.5">
            {onToggleFavorite && (
              <button
                type="button"
                onClick={handleToggleFavoriteClick}
                disabled={isTogglingFavorite}
                title={
                  isFavorite
                    ? 'Usuń z ulubionych (odpnij z góry listy)'
                    : 'Przypnij do ulubionych na górze listy'
                }
                className={`p-1 -ml-1 rounded-md transition-colors cursor-pointer shrink-0 ${
                  isFavorite
                    ? 'text-[var(--vault-warning)] hover:opacity-80'
                    : 'text-[var(--vault-muted)] hover:text-[var(--vault-warning)]'
                }`}
              >
                <Star
                  className={`w-4 h-4 ${
                    isFavorite ? 'fill-[var(--vault-warning)]' : ''
                  }`}
                />
              </button>
            )}
            <h3 className="text-base font-semibold font-display text-[var(--vault-text)] truncate">
              {displayServiceName}
            </h3>
            {isFavorite && (
              <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border border-[var(--vault-warning)]/50 text-[var(--vault-warning)] shrink-0">
                Ulubione
              </span>
            )}
            <span className="text-xs text-[var(--vault-muted)] shrink-0">
              · {categoryName} (
              {isPrivate
                ? record.revealToAdmin
                  ? 'Prywatny · Ujawniony Adminowi'
                  : 'Prywatny'
                : isSubAccountOnlyView
                  ? 'Twoje Subkonto'
                  : 'Wspólny'}
              )
            </span>
            {isOwnerOrAdmin && subAccounts.length > 0 && (
              <span className="text-xs font-medium text-[var(--vault-accent)] shrink-0 tabular-nums">
                · Subkonta: {subAccounts.length}
              </span>
            )}
          </div>
          <div className="text-xs text-[var(--vault-muted)] mt-0.5 truncate">
            Właściciel:{' '}
            <strong className="font-medium text-[var(--vault-text)]">
              {record.ownerName}
            </strong>
            {isSubAccountOnlyView && myAssignedSubAccount && (
              <span>
                {' '}
                · Subkonto dla:{' '}
                <strong className="font-medium text-[var(--vault-accent)]">
                  {myAssignedSubAccount.assignedMemberName}
                </strong>
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleOneClickLaunch}
            className="inline-flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg transition-colors whitespace-nowrap cursor-pointer"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>
              {copiedField === 'launch'
                ? 'Skopiowano i otwarto!'
                : 'Uruchom i zaloguj'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setIsDetailsOpen((v) => !v)}
            className="inline-flex items-center justify-center gap-1 px-3 py-2 text-xs font-medium text-[var(--vault-text)] border border-[var(--vault-border)] hover:bg-[var(--vault-surface-hover)] rounded-lg transition-colors whitespace-nowrap cursor-pointer"
          >
            <span>{isDetailsOpen ? 'Ukryj detale' : 'Pokaż detale'}</span>
            {isDetailsOpen ? (
              <ChevronUp className="w-3.5 h-3.5 text-[var(--vault-muted)]" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-[var(--vault-muted)]" />
            )}
          </button>
        </div>
      </div>

      {/* LIVE OWNER-ROUTED SOS / TV CODE BANNER (Visible even when card is collapsed) */}
      {!isPrivate && sosTicket && (
        <>
          {/* 1. PASSWORD OWNER VIEW: Pending SOS request from a family member */}
          {isOwner && sosTicket.status === 'pending' && (
            <form
              onSubmit={handleOwnerResolveSosSubmit}
              className="p-3.5 rounded-xl border-2 border-[var(--vault-warning)] bg-[var(--vault-bg)] space-y-2.5 text-xs"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 text-[var(--vault-warning)] font-bold">
                  <BellRing className="w-4 h-4 animate-bounce shrink-0" />
                  <span>
                    SOS od domownika: {sosTicket.requestedByMemberName} —{' '}
                    {sosTicket.reason === 'tv_code'
                      ? 'Prosi o kod autoryzacyjny na TV / PIN'
                      : 'Zgłasza, że hasło nie działa'}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleClearSosClick}
                  className="text-[11px] text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer shrink-0"
                >
                  Odrzuć
                </button>
              </div>
              <p className="text-[11px] text-[var(--vault-muted)]">
                Jako założyciel i właściciel tego hasła ({record.ownerName}), wpisz poniżej kod z SMS/e-maila na TV lub nowe hasło. U domownika ({sosTicket.requestedByMemberName}) automatycznie otworzy się pełnoekranowe okno Lupy z Twoją odpowiedzią.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <input
                  type="text"
                  value={ownerSosCodeInput}
                  onChange={(e) => setOwnerSosCodeInput(e.target.value)}
                  placeholder="Kod na TV / PIN (np. 4829)..."
                  maxLength={32}
                  className="px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-warning)]"
                />
                <input
                  type="text"
                  value={ownerSosNewPassInput}
                  onChange={(e) => setOwnerSosNewPassInput(e.target.value)}
                  placeholder="Opcjonalnie: nowe hasło..."
                  maxLength={256}
                  className="px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-warning)]"
                />
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={
                    isResolvingSos ||
                    (!ownerSosCodeInput.trim() && !ownerSosNewPassInput.trim())
                  }
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] disabled:opacity-50 rounded-lg cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>
                    {isResolvingSos
                      ? 'Wysyłanie...'
                      : `Wyślij do ${sosTicket.requestedByMemberName} (Otwórz Lupę)`}
                  </span>
                </button>
              </div>
            </form>
          )}

          {/* 2. REQUESTING FAMILY MEMBER VIEW: Waiting for password owner */}
          {sosTicket.requestedByMemberId === currentMember.id &&
            sosTicket.status === 'pending' && (
              <div className="p-3 rounded-xl border border-[var(--vault-warning)] bg-[var(--vault-bg)] flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2 text-[var(--vault-text)]">
                  <Tv className="w-4 h-4 text-[var(--vault-warning)] animate-pulse shrink-0" />
                  <span>
                    Wysłano prośbę ({sosTicket.reason === 'tv_code' ? 'Kod na TV' : 'Problem z hasłem'}) do właściciela hasła:{' '}
                    <strong>{record.ownerName}</strong>. Gdy odpowie, okno Lupy otworzy się automatycznie.
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleClearSosClick}
                  className="px-2.5 py-1 text-[11px] font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-md cursor-pointer shrink-0"
                >
                  Odwołaj
                </button>
              </div>
            )}

          {/* 3. REQUESTING FAMILY MEMBER VIEW: Owner responded with TV Code / updated password */}
          {sosTicket.requestedByMemberId === currentMember.id &&
            sosTicket.status === 'resolved' && (
              <div className="p-3 rounded-xl border-2 border-[var(--vault-success)] bg-[var(--vault-bg)] flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2 text-[var(--vault-text)]">
                  <Check className="w-4 h-4 text-[var(--vault-success)] shrink-0" />
                  <span>
                    Właściciel (<strong>{record.ownerName}</strong>) przesłał odpowiedź!{' '}
                    {sosTicket.responseCode && (
                      <strong className="font-mono text-sm text-[var(--vault-accent)] ml-1">
                        Kod TV: {sosTicket.responseCode}
                      </strong>
                    )}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      setShowPassword(true);
                      setMagnifiedViewData({
                        title: displayServiceName,
                        subtitle: sosTicket.responseCode
                          ? `Kod autoryzacyjny TV od właściciela (${record.ownerName})`
                          : `Zaktualizowane hasło od właściciela (${record.ownerName})`,
                        login: displayLogin,
                        password: displayPassword,
                        tvAuthCode: sosTicket.responseCode || undefined,
                      });
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-md cursor-pointer"
                  >
                    <ZoomIn className="w-3.5 h-3.5" />
                    <span>Pokaż w Lupie</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleClearSosClick}
                    className="px-2.5 py-1 text-xs font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-md cursor-pointer"
                  >
                    Gotowe
                  </button>
                </div>
              </div>
            )}
        </>
      )}

      {/* Expanded Details Section — visible ONLY after clicking "Pokaż detale" */}
      {isDetailsOpen && (
        <div className="pt-3 border-t border-[var(--vault-border)] space-y-3">
          {/* Top Action Bar inside details: URL, Last Updated, Zmień hasło, Usuń */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--vault-muted)]">
            <div className="flex flex-wrap items-center gap-1.5 min-w-0">
              {displayServiceUrl && (
                <span className="font-mono truncate max-w-[220px]">
                  {displayServiceUrl}
                </span>
              )}
              {displayServiceUrl && formattedPasswordUpdated && (
                <span aria-hidden="true">·</span>
              )}
              {formattedPasswordUpdated && (
                <span className="tabular-nums">
                  Zmieniono: {formattedPasswordUpdated}
                </span>
              )}
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              {isOwnerOrAdmin && onUpdateCardMetadata && (
                <button
                  type="button"
                  onClick={() => {
                    if (!isEditingMetadata) {
                      setPinOrNoteInput(effectiveProfilePinOrNote || '');
                      setTotpSecretInput(effectiveTotpSecret || '');
                    }
                    setIsEditingMetadata((v) => !v);
                  }}
                  className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg hover:bg-[var(--vault-surface-hover)] transition-colors whitespace-nowrap cursor-pointer"
                  title="Ustaw lub edytuj PIN do profilu TV / notatkę oraz klucz 2FA TOTP"
                >
                  <FileText className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                  <span>PIN / 2FA</span>
                </button>
              )}

              {canUpdatePrimaryDisplayedPassword && (
                <button
                  type="button"
                  onClick={() => {
                    setIsUpdatingPassword((v) => !v);
                    setNewPasswordInput(displayPassword);
                  }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg hover:bg-[var(--vault-surface-hover)] transition-colors whitespace-nowrap cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                  <span>
                    {isSubAccountOnlyView
                      ? 'Zmień hasło mojego subkonta'
                      : 'Zmień hasło'}
                  </span>
                </button>
              )}

              {isOwnerOrAdmin && !confirmDelete && (
                <button
                  type="button"
                  onClick={() => setConfirmDelete(true)}
                  className="p-1 text-[var(--vault-muted)] hover:text-[var(--vault-danger)] rounded-lg hover:bg-[var(--vault-surface-hover)] transition-colors cursor-pointer"
                  title="Usuń wpis"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          {/* Delete confirmation bar */}
          {confirmDelete && (
            <div className="p-3 rounded-lg border border-[var(--vault-danger)] bg-[var(--vault-bg)] flex items-center justify-between gap-3 text-xs">
              <span className="text-[var(--vault-text)]">
                Czy na pewno usunąć wpis <strong>{displayServiceName}</strong>?
              </span>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => onDeleteRecord(record)}
                  className="px-3 py-1 font-medium text-[#FAF7F2] bg-[var(--vault-danger)] rounded-md cursor-pointer whitespace-nowrap"
                >
                  Usuń
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmDelete(false)}
                  className="px-3 py-1 font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer whitespace-nowrap"
                >
                  Anuluj
                </button>
              </div>
            </div>
          )}

          {/* Primary Credentials block (either Main Account for Owner/Admin, or Assigned Sub-Account for Family Member) */}
          <div className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-[11px] font-semibold text-[var(--vault-muted)]">
                {isSubAccountOnlyView && myAssignedSubAccount
                  ? `Twoje przypisane subkonto (${myAssignedSubAccount.label || 'Subkonto rodzinne'})`
                  : isOwnerOrAdmin && subAccounts.length > 0
                    ? 'Konto główne (Właściciel abonomentu)'
                    : 'Dane logowania'}
              </div>

              {/* Quick Tools Row: Kod QR Wi-Fi + SOS / Kod TV do właściciela hasła */}
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    if (!wifiSsidInput) {
                      setWifiSsidInput(
                        displayLogin && displayLogin !== 'ENC[PRIVATE]'
                          ? displayLogin
                          : displayServiceName
                      );
                    }
                    setIsQrModalOpen(true);
                  }}
                  className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[var(--vault-text)] border border-[var(--vault-border)] rounded-md hover:bg-[var(--vault-surface)] transition-colors cursor-pointer"
                  title="Pokaż kod QR Wi-Fi do zeskanowania aparatem telefonu"
                >
                  <QrCode className="w-3 h-3 text-[var(--vault-accent)]" />
                  <span>Kod QR Wi-Fi</span>
                </button>

                {!isPrivate && !isOwner && onCreateSosRequest && (
                  <button
                    type="button"
                    onClick={() => setIsSosMenuOpen((v) => !v)}
                    className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold text-[var(--vault-warning)] border border-[var(--vault-warning)]/60 rounded-md hover:bg-[var(--vault-surface)] transition-colors cursor-pointer"
                    title={`Wyślij prośbę o kod na TV lub zgłoś problem bezpośrednio do założyciela hasła (${record.ownerName})`}
                  >
                    <Tv className="w-3 h-3 shrink-0" />
                    <span>SOS / Kod TV (do: {record.ownerName})</span>
                  </button>
                )}
              </div>
            </div>

            {/* 1-Tap SOS Action Bar for Family Member -> Routed strictly to Password Owner */}
            {!isPrivate && !isOwner && isSosMenuOpen && (
              <div className="p-2.5 rounded-lg border border-[var(--vault-warning)]/70 bg-[var(--vault-surface)] space-y-2 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-[var(--vault-text)]">
                    Wyślij powiadomienie bezpośrednio do założyciela hasła ({record.ownerName}):
                  </span>
                  <button
                    type="button"
                    onClick={() => setIsSosMenuOpen(false)}
                    className="text-[11px] text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer"
                  >
                    Zamknij
                  </button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <button
                    type="button"
                    disabled={isSendingSos}
                    onClick={() => handleSendSosClick('tv_code')}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg cursor-pointer"
                  >
                    <Tv className="w-3.5 h-3.5 shrink-0" />
                    <span>Poproś {record.ownerName} o kod na TV</span>
                  </button>
                  <button
                    type="button"
                    disabled={isSendingSos}
                    onClick={() => handleSendSosClick('password_not_working')}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-semibold text-[var(--vault-text)] border border-[var(--vault-warning)] hover:bg-[var(--vault-bg)] rounded-lg cursor-pointer"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 text-[var(--vault-warning)] shrink-0" />
                    <span>Zgłoś: Hasło nie działa</span>
                  </button>
                </div>
              </div>
            )}

            {/* Login Row */}
            <div className="flex items-center justify-between gap-3 text-sm">
              <div className="min-w-0">
                <span className="text-xs text-[var(--vault-muted)] block">
                  Login
                </span>
                <span className="font-mono text-sm text-[var(--vault-text)] truncate block">
                  {displayLogin}
                </span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(displayLogin, 'login', false)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg hover:bg-[var(--vault-surface)] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {copiedField === 'login' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[var(--vault-success)]" />
                    <span>Skopiowano</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Kopiuj login</span>
                  </>
                )}
              </button>
            </div>

            {/* Password Row */}
            <div className="flex items-center justify-between gap-3 text-sm pt-2 border-t border-[var(--vault-border)]">
              <div className="min-w-0">
                <span className="text-xs text-[var(--vault-muted)] block">
                  Hasło
                </span>
                <span className="font-mono text-sm text-[var(--vault-text)] truncate block tabular-nums">
                  {showPassword
                    ? displayPassword
                    : '•'.repeat(
                        Math.min(Math.max(displayPassword.length, 10), 18)
                      )}
                </span>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="p-1.5 text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg hover:bg-[var(--vault-surface)] transition-colors cursor-pointer"
                  title={showPassword ? 'Ukryj hasło' : 'Pokaż hasło'}
                >
                  {showPassword ? (
                    <EyeOff className="w-3.5 h-3.5" />
                  ) : (
                    <Eye className="w-3.5 h-3.5" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowPassword(true);
                    setMagnifiedViewData({
                      title: displayServiceName,
                      subtitle:
                        isSubAccountOnlyView && myAssignedSubAccount
                          ? `Twoje subkonto (${myAssignedSubAccount.label || 'Rodzinne'})`
                          : categoryName,
                      login: displayLogin,
                      password: displayPassword,
                      tvAuthCode:
                        sosTicket?.status === 'resolved' &&
                        sosTicket.requestedByMemberId === currentMember.id &&
                        sosTicket.responseCode
                          ? sosTicket.responseCode
                          : undefined,
                    });
                  }}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold text-[var(--vault-accent)] border border-[var(--vault-accent)]/60 rounded-lg hover:bg-[var(--vault-surface)] transition-colors cursor-pointer"
                  title="Powiększ hasło na cały ekran (Lupa dla słabowidzących)"
                >
                  <ZoomIn className="w-3.5 h-3.5 shrink-0" />
                  <span>Lupa</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleCopy(displayPassword, 'password', true)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg hover:bg-[var(--vault-surface)] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedField === 'password' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--vault-success)]" />
                      <span>Skopiowano</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Kopiuj hasło</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Pillar 2: Optional PIN do profilu TV / Notatka Row */}
            {effectiveProfilePinOrNote && (
              <div className="flex items-center justify-between gap-3 text-sm pt-2 border-t border-[var(--vault-border)]">
                <div className="min-w-0">
                  <span className="text-xs text-[var(--vault-muted)] flex items-center gap-1">
                    <FileText className="w-3 h-3 text-[var(--vault-accent)]" />
                    <span>PIN do profilu TV / Notatka</span>
                  </span>
                  <span className="font-mono text-xs sm:text-sm font-semibold text-[var(--vault-text)] break-words block mt-0.5">
                    {effectiveProfilePinOrNote}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() =>
                    handleCopy(effectiveProfilePinOrNote, 'pin_note', false)
                  }
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded-lg hover:bg-[var(--vault-surface)] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedField === 'pin_note' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--vault-success)]" />
                      <span>Skopiowano</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Kopiuj PIN</span>
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Pillar 2: Live 6-Digit 2FA TOTP Clock Row */}
            {liveTotpData && (
              <div className="flex items-center justify-between gap-3 text-sm pt-2 border-t border-[var(--vault-border)]">
                <div className="min-w-0">
                  <span className="text-xs text-[var(--vault-muted)] flex items-center gap-1.5">
                    <Shield className="w-3 h-3 text-[var(--vault-success)]" />
                    <span>Kod 2FA TOTP (na żywo)</span>
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono text-[var(--vault-accent)] tabular-nums">
                      <Clock className="w-3 h-3" />
                      <span>{liveTotpData.secondsRemaining}s</span>
                    </span>
                  </span>
                  <span className="font-mono text-base font-bold tracking-wider text-[var(--vault-accent)] tabular-nums block mt-0.5">
                    {liveTotpData.code}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() =>
                    handleCopy(
                      liveTotpData.code.replace(/\s+/g, ''),
                      'totp_code',
                      false
                    )
                  }
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-[var(--vault-text)] border border-[var(--vault-accent)]/60 rounded-lg hover:bg-[var(--vault-surface)] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedField === 'totp_code' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-[var(--vault-success)]" />
                      <span>Skopiowano 2FA</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-[var(--vault-accent)]" />
                      <span>Kopiuj kod 2FA</span>
                    </>
                  )}
                </button>
              </div>
            )}
          </div>

          {/* Inline Editor for PIN do profilu TV / Notatka & Klucz 2FA TOTP */}
          {isEditingMetadata && isOwnerOrAdmin && onUpdateCardMetadata && (
            <form
              onSubmit={handleSaveCardMetadataSubmit}
              className="p-3.5 rounded-lg border border-[var(--vault-accent)] bg-[var(--vault-bg)] space-y-3 text-xs"
            >
              <div className="font-semibold text-[var(--vault-text)] flex items-center justify-between">
                <span>
                  Edycja PIN-u do profilu TV / Notatki oraz Klucza 2FA TOTP
                </span>
                <button
                  type="button"
                  onClick={() => setIsEditingMetadata(false)}
                  className="text-[11px] text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer"
                >
                  Zamknij
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[11px] text-[var(--vault-muted)] mb-1">
                    PIN do profilu TV / Notatka (widoczna także w Lupie)
                  </label>
                  <input
                    type="text"
                    value={pinOrNoteInput}
                    onChange={(e) => setPinOrNoteInput(e.target.value)}
                    placeholder="np. PIN profilu TV: 2580"
                    maxLength={120}
                    className="w-full px-2.5 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-[var(--vault-muted)] mb-1">
                    Klucz 2FA TOTP (Base32 z Google Authenticator)
                  </label>
                  <input
                    type="text"
                    value={totpSecretInput}
                    onChange={(e) => setTotpSecretInput(e.target.value)}
                    placeholder="np. JBSWY3DPEHPK3PXP"
                    maxLength={128}
                    className="w-full px-2.5 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsEditingMetadata(false)}
                  className="px-3 py-1 text-xs text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer"
                >
                  Anuluj
                </button>
                <button
                  type="submit"
                  disabled={isSavingMetadata}
                  className="px-3.5 py-1.5 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg cursor-pointer"
                >
                  {isSavingMetadata ? 'Zapisywanie...' : 'Zapisz PIN / 2FA'}
                </button>
              </div>
            </form>
          )}

          {/* Inline Quick Password Update (for primary displayed password / subaccount) */}
          {isUpdatingPassword && (
            <form
              onSubmit={handleSaveNewPassword}
              className="p-3.5 rounded-lg border border-[var(--vault-accent)] bg-[var(--vault-bg)] space-y-2.5"
            >
              <div className="flex items-center justify-between text-xs font-medium text-[var(--vault-text)]">
                <span>
                  {isSubAccountOnlyView
                    ? 'Aktualizacja hasła w Twoim subkoncie'
                    : 'Aktualizacja hasła w istniejącym rekordzie'}
                </span>
                <button
                  type="button"
                  onClick={() => setNewPasswordInput(generateStrongPassword(16))}
                  className="inline-flex items-center gap-1 text-[var(--vault-accent)] hover:underline cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Generuj silne hasło</span>
                </button>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newPasswordInput}
                  onChange={(e) => setNewPasswordInput(e.target.value)}
                  placeholder="Wpisz nowe hasło..."
                  maxLength={256}
                  required
                  className="flex-1 px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
                <button
                  type="submit"
                  disabled={isSavingPassword}
                  className="px-3 py-1.5 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {isSavingPassword ? 'Zapisywanie...' : 'Zapisz nowe hasło'}
                </button>
                <button
                  type="button"
                  onClick={() => setIsUpdatingPassword(false)}
                  className="px-2.5 py-1.5 text-xs text-[var(--vault-muted)] hover:text-[var(--vault-text)] whitespace-nowrap shrink-0 cursor-pointer"
                >
                  Anuluj
                </button>
              </div>
            </form>
          )}

          {/* Pillar 1: Collapsible Password History (Last 3 Passwords + 1-Click Rollback) */}
          {isOwnerOrAdmin && effectivePasswordHistory.length > 0 && (
            <div className="rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] overflow-hidden text-xs">
              <button
                type="button"
                onClick={() => setIsHistoryOpen((v) => !v)}
                className="w-full px-3 py-2 flex items-center justify-between gap-2 text-left hover:bg-[var(--vault-surface-hover)] transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2 text-[var(--vault-text)] font-medium">
                  <History className="w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0" />
                  <span>
                    Historia poprzednich haseł ({effectivePasswordHistory.length}/3) — Cofnij zmianę 1-Klik
                  </span>
                </div>
                <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[var(--vault-accent)] shrink-0">
                  <span>{isHistoryOpen ? 'Zwiń' : 'Pokaż historię'}</span>
                  {isHistoryOpen ? (
                    <ChevronUp className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5" />
                  )}
                </span>
              </button>

              {isHistoryOpen && (
                <div className="p-3 border-t border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-2">
                  <p className="text-[11px] text-[var(--vault-muted)]">
                    Jeśli zmiana hasła na docelowej stronie (np. Netflix, router, bank) nie powiodła się, możesz jednym kliknięciem przywrócić poprzednie hasło:
                  </p>
                  <div className="space-y-1.5">
                    {effectivePasswordHistory.map((hist, idx) => {
                      const isHistRevealed =
                        revealedHistoryIndices.includes(idx);
                      const formattedHistDate = hist.changedAt
                        ? new Date(hist.changedAt).toLocaleString('pl-PL', {
                            day: '2-digit',
                            month: '2-digit',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : '';
                      return (
                        <div
                          key={`hist_${idx}_${hist.changedAt}`}
                          className="p-2.5 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                        >
                          <div className="min-w-0 space-y-0.5">
                            <div className="font-mono text-xs text-[var(--vault-text)] truncate tabular-nums">
                              {isHistRevealed
                                ? hist.passwordValue
                                : '•'.repeat(
                                    Math.min(
                                      Math.max(hist.passwordValue.length, 8),
                                      16
                                    )
                                  )}
                            </div>
                            <div className="text-[10px] text-[var(--vault-muted)] tabular-nums">
                              Zmieniono: {formattedHistDate} · przez:{' '}
                              <strong>{hist.changedBy}</strong>
                            </div>
                          </div>

                          <div className="flex items-center gap-1.5 shrink-0">
                            <button
                              type="button"
                              onClick={() =>
                                setRevealedHistoryIndices((prev) =>
                                  prev.includes(idx)
                                    ? prev.filter((i) => i !== idx)
                                    : [...prev, idx]
                                )
                              }
                              className="p-1 text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded cursor-pointer"
                              title={
                                isHistRevealed
                                  ? 'Ukryj poprzednie hasło'
                                  : 'Pokaż poprzednie hasło'
                              }
                            >
                              {isHistRevealed ? (
                                <EyeOff className="w-3.5 h-3.5" />
                              ) : (
                                <Eye className="w-3.5 h-3.5" />
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(
                                  hist.passwordValue,
                                  `hist_${idx}`,
                                  true
                                )
                              }
                              className="px-2 py-1 text-[11px] font-medium text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded cursor-pointer"
                            >
                              {copiedField === `hist_${idx}`
                                ? 'Skopiowano'
                                : 'Kopiuj'}
                            </button>
                            <button
                              type="button"
                              disabled={restoringHistoryIdx !== null}
                              onClick={() =>
                                handleRestoreHistoryEntry(hist, idx)
                              }
                              className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] disabled:opacity-50 rounded cursor-pointer"
                            >
                              <RotateCcw className="w-3 h-3" />
                              <span>
                                {restoringHistoryIdx === idx
                                  ? 'Przywracanie...'
                                  : 'Przywróć to hasło'}
                              </span>
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* MULTIKONTA / SUBKONTA SECTION (Visible to Owner and Admin on Shared records, e.g. Netflix +10 zł) */}
          {!isPrivate && isOwnerOrAdmin && (
            <div className="pt-2 border-t border-[var(--vault-border)] space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <h4 className="text-xs font-semibold text-[var(--vault-text)]">
                    Multikonta / Subkonta domowników (np. Netflix +10 zł)
                  </h4>
                  <p className="text-[11px] text-[var(--vault-muted)]">
                    Każdy przypisany domownik widzi w tej karcie wyłącznie swoje subkonto i może aktualizować swoje hasło.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    if (!newSubMemberId && activeMembers.length > 0) {
                      const firstOther =
                        activeMembers.find((m) => m.id !== currentMember.id) ||
                        activeMembers[0];
                      setNewSubMemberId(firstOther.id);
                    }
                    setIsAddingSubAccount((v) => !v);
                  }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>+ Dodaj subkonto</span>
                </button>
              </div>

              {/* Add New Sub-Account Form */}
              {isAddingSubAccount && (
                <form
                  onSubmit={handleAddSubAccountSubmit}
                  className="p-3.5 rounded-lg border border-[var(--vault-accent)] bg-[var(--vault-bg)] space-y-3 text-xs"
                >
                  <div className="font-semibold text-[var(--vault-text)]">
                    Nowe subkonto w ramach konta {displayServiceName}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-[11px] text-[var(--vault-muted)] mb-1">
                        Przypisz do domownika
                      </label>
                      <select
                        value={newSubMemberId}
                        onChange={(e) => setNewSubMemberId(e.target.value)}
                        className="w-full px-2.5 py-1.5 text-xs rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                      >
                        {activeMembers.map((m) => (
                          <option key={m.id} value={m.id}>
                            {m.fullName} ({m.username})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-[11px] text-[var(--vault-muted)] mb-1">
                        Opis / pakiet subkonta
                      </label>
                      <input
                        type="text"
                        value={newSubLabel}
                        onChange={(e) => setNewSubLabel(e.target.value)}
                        placeholder="np. Subkonto dodatkowe (+10 zł)"
                        maxLength={80}
                        className="w-full px-2.5 py-1.5 text-xs rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-[11px] text-[var(--vault-muted)] mb-1">
                        Indywidualny login subkonta
                      </label>
                      <input
                        type="text"
                        value={newSubLogin}
                        onChange={(e) => setNewSubLogin(e.target.value)}
                        placeholder="np. anna@dom.pl"
                        required
                        maxLength={120}
                        className="w-full px-2.5 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                      />
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="block text-[11px] text-[var(--vault-muted)]">
                          Indywidualne hasło subkonta
                        </label>
                        <button
                          type="button"
                          onClick={() =>
                            setNewSubPassword(generateStrongPassword(14))
                          }
                          className="text-[11px] text-[var(--vault-accent)] hover:underline cursor-pointer"
                        >
                          Generuj
                        </button>
                      </div>
                      <input
                        type="text"
                        value={newSubPassword}
                        onChange={(e) => setNewSubPassword(e.target.value)}
                        placeholder="Hasło subkonta..."
                        required
                        maxLength={256}
                        className="w-full px-2.5 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                      />
                    </div>
                  </div>

                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={() => setIsAddingSubAccount(false)}
                      className="px-3 py-1 text-xs text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer"
                    >
                      Anuluj
                    </button>
                    <button
                      type="submit"
                      disabled={isSavingSubAccount}
                      className="px-3.5 py-1.5 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-lg cursor-pointer"
                    >
                      {isSavingSubAccount
                        ? 'Zapisywanie...'
                        : 'Zapisz subkonto'}
                    </button>
                  </div>
                </form>
              )}

              {/* Existing Sub-Accounts List */}
              {subAccounts.length > 0 && (
                <div className="space-y-2">
                  {subAccounts.map((sa) => {
                    const isSubPassRevealed = revealedSubPassIds.includes(
                      sa.id
                    );
                    const isEditingThisSub = editingSubAccountId === sa.id;
                    return (
                      <div
                        key={sa.id}
                        className="p-3 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-2 text-xs"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="min-w-0">
                            <strong className="font-semibold text-[var(--vault-text)]">
                              Osoba: {sa.assignedMemberName}
                            </strong>
                            <span className="text-[var(--vault-muted)]">
                              {' '}
                              · {sa.label}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <button
                              type="button"
                              onClick={() => {
                                if (isEditingThisSub) {
                                  setEditingSubAccountId(null);
                                } else {
                                  setEditingSubAccountId(sa.id);
                                  setSubNewPasswordInput(sa.passwordValue);
                                }
                              }}
                              className="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-[var(--vault-text)] border border-[var(--vault-border)] rounded hover:bg-[var(--vault-surface)] cursor-pointer"
                            >
                              <KeyRound className="w-3 h-3 text-[var(--vault-accent)]" />
                              <span>Zmień hasło</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteSubAccount(sa.id)}
                              disabled={isSavingSubAccount}
                              className="p-1 text-[var(--vault-muted)] hover:text-[var(--vault-danger)] rounded cursor-pointer"
                              title="Usuń subkonto"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 border-t border-[var(--vault-border)]">
                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0">
                              <span className="text-[11px] text-[var(--vault-muted)] block">
                                Login subkonta
                              </span>
                              <span className="font-mono text-xs text-[var(--vault-text)] truncate block">
                                {sa.login}
                              </span>
                            </div>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(sa.login, `sub_login_${sa.id}`, false)
                              }
                              className="px-2 py-1 text-[11px] text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded cursor-pointer shrink-0"
                            >
                              {copiedField === `sub_login_${sa.id}`
                                ? 'Skopiowano'
                                : 'Kopiuj'}
                            </button>
                          </div>

                          <div className="flex items-center justify-between gap-2">
                            <div className="min-w-0">
                              <span className="text-[11px] text-[var(--vault-muted)] block">
                                Hasło subkonta
                              </span>
                              <span className="font-mono text-xs text-[var(--vault-text)] truncate block tabular-nums">
                                {isSubPassRevealed
                                  ? sa.passwordValue
                                  : '•'.repeat(12)}
                              </span>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              <button
                                type="button"
                                onClick={() =>
                                  setRevealedSubPassIds((prev) =>
                                    prev.includes(sa.id)
                                      ? prev.filter((id) => id !== sa.id)
                                      : [...prev, sa.id]
                                  )
                                }
                                className="p-1 text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded cursor-pointer"
                                title={
                                  isSubPassRevealed
                                    ? 'Ukryj hasło subkonta'
                                    : 'Pokaż hasło subkonta'
                                }
                              >
                                {isSubPassRevealed ? (
                                  <EyeOff className="w-3 h-3" />
                                ) : (
                                  <Eye className="w-3 h-3" />
                                )}
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  if (!revealedSubPassIds.includes(sa.id)) {
                                    setRevealedSubPassIds((prev) => [
                                      ...prev,
                                      sa.id,
                                    ]);
                                  }
                                  setMagnifiedViewData({
                                    title: `${displayServiceName} — ${sa.assignedMemberName}`,
                                    subtitle: sa.label || 'Subkonto rodzinne',
                                    login: sa.login,
                                    password: sa.passwordValue,
                                  });
                                }}
                                className="inline-flex items-center gap-1 px-1.5 py-1 text-[11px] font-semibold text-[var(--vault-accent)] border border-[var(--vault-accent)]/60 rounded hover:bg-[var(--vault-surface)] cursor-pointer"
                                title="Powiększ hasło subkonta (Lupa)"
                              >
                                <ZoomIn className="w-3 h-3" />
                                <span>Lupa</span>
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  handleCopy(
                                    sa.passwordValue,
                                    `sub_pass_${sa.id}`,
                                    true
                                  )
                                }
                                className="px-2 py-1 text-[11px] text-[var(--vault-muted)] hover:text-[var(--vault-text)] border border-[var(--vault-border)] rounded cursor-pointer"
                              >
                                {copiedField === `sub_pass_${sa.id}`
                                  ? 'Skopiowano'
                                  : 'Kopiuj'}
                              </button>
                            </div>
                          </div>
                        </div>

                        {isEditingThisSub && (
                          <form
                            onSubmit={(e) =>
                              handleSaveSubAccountPassword(e, sa.id)
                            }
                            className="pt-2 border-t border-[var(--vault-border)] flex items-center gap-2"
                          >
                            <input
                              type="text"
                              value={subNewPasswordInput}
                              onChange={(e) =>
                                setSubNewPasswordInput(e.target.value)
                              }
                              placeholder="Nowe hasło subkonta..."
                              required
                              maxLength={256}
                              className="flex-1 px-2.5 py-1 text-xs font-mono rounded border border-[var(--vault-border)] bg-[var(--vault-surface)] text-[var(--vault-text)]"
                            />
                            <button
                              type="submit"
                              disabled={isSavingSubAccount}
                              className="px-3 py-1 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded cursor-pointer shrink-0"
                            >
                              Zapisz
                            </button>
                          </form>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Shared Access Multi-Select Dropdown (visible to Owner/Admin) */}
          {!isPrivate && isOwnerOrAdmin ? (
            <div className="pt-2 border-t border-[var(--vault-border)] space-y-2">
              <div className="rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] overflow-hidden">
                <button
                  type="button"
                  onClick={() => {
                    if (!isEditingAccess) {
                      setSelectedMemberIds(record.allowedMemberIds);
                    }
                    setIsEditingAccess((v) => !v);
                  }}
                  className="w-full px-3 py-2 flex items-center justify-between gap-2 text-left text-xs hover:bg-[var(--vault-surface-hover)] transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <Users className="w-3.5 h-3.5 text-[var(--vault-accent)] shrink-0" />
                    <span className="text-[var(--vault-muted)] truncate">
                      Uprawnieni ({allowedMemberNames.length}):{' '}
                      <strong className="font-medium text-[var(--vault-text)]">
                        {allowedMemberNames.length <= 1
                          ? `Tylko ${allowedMemberNames[0] || record.ownerName}`
                          : allowedMemberNames.join(', ')}
                      </strong>
                    </span>
                  </div>
                  {canManageAccess && (
                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[var(--vault-accent)] shrink-0">
                      <span>{isEditingAccess ? 'Zwiń listę' : 'Wybierz osoby'}</span>
                      {isEditingAccess ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </span>
                  )}
                </button>

                {isEditingAccess && canManageAccess && (
                  <div className="p-3 border-t border-[var(--vault-border)] bg-[var(--vault-surface)] space-y-2.5">
                    <div className="flex items-center justify-between text-[11px] text-[var(--vault-muted)] pb-1.5 border-b border-[var(--vault-border)]">
                      <span>Wybierz domowników uprawnionych do tej karty:</span>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() =>
                            setSelectedMemberIds(activeMembers.map((m) => m.id))
                          }
                          className="text-[var(--vault-accent)] hover:underline font-semibold cursor-pointer"
                        >
                          Wszyscy ({activeMembers.length})
                        </button>
                        <span>·</span>
                        <button
                          type="button"
                          onClick={() => setSelectedMemberIds([record.ownerId])}
                          className="text-[var(--vault-muted)] hover:text-[var(--vault-text)] font-semibold cursor-pointer"
                        >
                          Tylko właściciel
                        </button>
                      </div>
                    </div>

                    <div className="space-y-1 max-h-44 overflow-y-auto pr-1">
                      {activeMembers.map((member) => {
                        const isCreator = member.id === record.ownerId;
                        const isChecked =
                          isCreator || selectedMemberIds.includes(member.id);
                        return (
                          <label
                            key={member.id}
                            className={`flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg text-xs cursor-pointer select-none transition-colors ${
                              isChecked
                                ? 'bg-[var(--vault-bg)] text-[var(--vault-text)] font-medium'
                                : 'text-[var(--vault-muted)] hover:bg-[var(--vault-bg)] hover:text-[var(--vault-text)]'
                            }`}
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <input
                                type="checkbox"
                                checked={isChecked}
                                disabled={isCreator}
                                onChange={() =>
                                  handleToggleMemberAccess(member.id)
                                }
                                className="rounded border-[var(--vault-border)] cursor-pointer"
                              />
                              <span className="truncate">
                                {member.fullName} ({member.username})
                              </span>
                            </div>
                            {isCreator ? (
                              <span className="text-[10px] font-semibold text-[var(--vault-accent)] shrink-0">
                                Właściciel
                              </span>
                            ) : isChecked ? (
                              <Check className="w-3.5 h-3.5 text-[var(--vault-success)] shrink-0" />
                            ) : null}
                          </label>
                        );
                      })}
                    </div>

                    <div className="flex justify-end gap-2 pt-1 border-t border-[var(--vault-border)]">
                      <button
                        type="button"
                        onClick={() => setIsEditingAccess(false)}
                        className="px-3 py-1 text-xs text-[var(--vault-muted)] hover:text-[var(--vault-text)] cursor-pointer"
                      >
                        Anuluj
                      </button>
                      <button
                        type="button"
                        onClick={handleSaveAccess}
                        disabled={isSavingAccess}
                        className="px-3.5 py-1 text-xs font-semibold text-[#FAF7F2] bg-[var(--vault-accent)] rounded-md cursor-pointer"
                      >
                        {isSavingAccess ? 'Zapisywanie...' : 'Zapisz uprawnienia'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : isPrivate ? (
            <div className="pt-2 border-t border-[var(--vault-border)] space-y-2.5">
              {isOwner && onToggleRevealToAdmin && (
                <label className="flex items-start gap-2.5 p-2.5 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] hover:border-[var(--vault-accent)] transition-colors cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={Boolean(record.revealToAdmin)}
                    disabled={isTogglingReveal}
                    onChange={async (e) => {
                      const nextVal = e.target.checked;
                      setIsTogglingReveal(true);
                      try {
                        await onToggleRevealToAdmin(record, nextVal);
                      } finally {
                        setIsTogglingReveal(false);
                      }
                    }}
                    className="mt-0.5 rounded border-[var(--vault-border)] cursor-pointer"
                  />
                  <div className="text-xs">
                    <span className="font-semibold text-[var(--vault-text)] block">
                      Ujawnij hasło administratorowi
                    </span>
                    <span className="text-[11px] text-[var(--vault-muted)]">
                      {record.revealToAdmin
                        ? 'Włączone: Główny Administrator oraz Zaufani Opiekunowie (Co-Admini) widzą ten wpis jawnie. Odznacz, aby ukryć wpis w trybie Zero-Knowledge.'
                        : 'Wyłączone (Zero-Knowledge): Wpis jest całkowicie zaszyfrowany i niewidoczny dla Administratora. Zaznacz, jeśli chcesz udostępnić mu podgląd.'}
                    </span>
                  </div>
                </label>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--vault-muted)]">
                <span className="inline-flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-[var(--vault-success)] shrink-0" />
                  <span>
                    {isOwner
                      ? 'Odszyfrowano kluczem sprzętowym urządzenia (Hasło + Profil Sprzętowy + Certyfikat)'
                      : 'Wpis prywatny dobrowolnie ujawniony Administratorowi przez właściciela konta'}
                  </span>
                </span>
                <span className="font-mono text-[11px] text-[var(--vault-text)]">
                  {activeHardwareCertFingerprint || 'CERT-HW-BOUND'} ·{' '}
                  {activeHardwareModeLabel || 'AES-256-GCM'}
                </span>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* CENTRAL HIGH-CONTRAST MAGNIFIER MODAL ("LUPA") FOR EASY READING & LIVE TV CODE */}
      {magnifiedViewData && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
          onClick={() => setMagnifiedViewData(null)}
        >
          <div
            className="w-full max-w-2xl rounded-2xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] p-5 sm:p-7 space-y-5 max-h-[92vh] overflow-y-auto shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-4 border-b border-[var(--vault-border)] pb-4">
              <div>
                <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--vault-accent)]">
                  <ZoomIn className="w-4 h-4" />
                  <span>Powiększony podgląd hasła (Tryb Lupy) · {magnifiedViewData.subtitle}</span>
                </div>
                <h2 className="text-xl sm:text-2xl font-bold font-display text-[var(--vault-text)] mt-0.5">
                  {magnifiedViewData.title}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setMagnifiedViewData(null)}
                className="p-2 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] hover:bg-[var(--vault-surface-hover)] cursor-pointer shrink-0"
                title="Zamknij lupę"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* LIVE TV AUTHORIZATION CODE BOX (Appears automatically when Password Owner responds to SOS) */}
            {magnifiedViewData.tvAuthCode && (
              <div className="p-4 sm:p-5 rounded-xl border-2 border-[var(--vault-success)] bg-[var(--vault-bg)] space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--vault-success)]">
                    <Tv className="w-4 h-4" />
                    <span>
                      Kod autoryzacyjny na TV (od właściciela: {record.ownerName})
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopy(
                        magnifiedViewData.tvAuthCode!,
                        'magnified_tv_code',
                        false
                      )
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg cursor-pointer"
                  >
                    {copiedField === 'magnified_tv_code' ? (
                      <>
                        <Check className="w-4 h-4" />
                        <span>Skopiowano kod TV!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-4 h-4" />
                        <span>Kopiuj kod TV</span>
                      </>
                    )}
                  </button>
                </div>

                <div className="font-mono text-3xl sm:text-5xl font-bold tracking-widest text-[var(--vault-accent)] break-all select-all py-1">
                  {magnifiedViewData.tvAuthCode}
                </div>

                <div className="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 gap-2 pt-1">
                  {Array.from(magnifiedViewData.tvAuthCode).map((ch, idx) => {
                    const isDigit = /^[0-9]$/.test(ch);
                    return (
                      <div
                        key={`tv_${idx}_${ch}`}
                        className="p-2.5 rounded-xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] flex flex-col items-center justify-center text-center"
                      >
                        <span className="text-[10px] font-mono text-[var(--vault-muted)] tabular-nums">
                          #{idx + 1}
                        </span>
                        <span className="font-mono text-2xl sm:text-3xl font-bold my-0.5 text-[var(--vault-accent)]">
                          {ch === ' ' ? '␣' : ch}
                        </span>
                        <span className="text-[10px] font-semibold text-[var(--vault-text)]">
                          {isDigit ? 'CYFRA' : 'ZNAK'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Large Login Box */}
            <div className="p-4 rounded-xl border border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-[var(--vault-muted)]">
                  Login / E-mail
                </span>
                <button
                  type="button"
                  onClick={() =>
                    handleCopy(magnifiedViewData.login, 'magnified_login', false)
                  }
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-surface)] hover:bg-[var(--vault-surface-hover)] rounded-lg cursor-pointer"
                >
                  {copiedField === 'magnified_login' ? (
                    <>
                      <Check className="w-4 h-4 text-[var(--vault-success)]" />
                      <span>Skopiowano login!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4 text-[var(--vault-accent)]" />
                      <span>Kopiuj login</span>
                    </>
                  )}
                </button>
              </div>
              <div className="font-mono text-xl sm:text-2xl font-bold text-[var(--vault-text)] break-all select-all">
                {magnifiedViewData.login}
              </div>
            </div>

            {/* Huge Password Box */}
            <div className="p-4 sm:p-5 rounded-xl border-2 border-[var(--vault-accent)] bg-[var(--vault-bg)] space-y-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-[var(--vault-accent)]">
                  Hasło (powiększone)
                </span>
                <button
                  type="button"
                  onClick={() =>
                    handleCopy(
                      magnifiedViewData.password,
                      'magnified_password',
                      true
                    )
                  }
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs sm:text-sm font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-lg cursor-pointer"
                >
                  {copiedField === 'magnified_password' ? (
                    <>
                      <Check className="w-4 h-4" />
                      <span>Skopiowano hasło!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      <span>Kopiuj hasło</span>
                    </>
                  )}
                </button>
              </div>
              <div className="font-mono text-2xl sm:text-4xl font-bold tracking-wider text-[var(--vault-text)] break-all select-all py-1">
                {magnifiedViewData.password}
              </div>
            </div>

            {/* Pillar 2: Large TV Profile PIN / Note & Live 2FA TOTP inside Magnifier ("Lupa") */}
            {(effectiveProfilePinOrNote || liveTotpData) && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {effectiveProfilePinOrNote && (
                  <div className="p-4 rounded-xl border-2 border-[var(--vault-border)] bg-[var(--vault-bg)] space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold uppercase tracking-wider text-[var(--vault-muted)] flex items-center gap-1.5">
                        <FileText className="w-4 h-4 text-[var(--vault-accent)]" />
                        <span>PIN profilu TV / Notatka</span>
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          handleCopy(
                            effectiveProfilePinOrNote,
                            'magnified_pin_note',
                            false
                          )
                        }
                        className="px-2.5 py-1 text-xs font-semibold text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-surface)] rounded-lg cursor-pointer"
                      >
                        {copiedField === 'magnified_pin_note'
                          ? 'Skopiowano!'
                          : 'Kopiuj'}
                      </button>
                    </div>
                    <div className="font-mono text-2xl sm:text-3xl font-bold text-[var(--vault-accent)] break-words select-all">
                      {effectiveProfilePinOrNote}
                    </div>
                  </div>
                )}

                {liveTotpData && (
                  <div className="p-4 rounded-xl border-2 border-[var(--vault-success)] bg-[var(--vault-bg)] space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold uppercase tracking-wider text-[var(--vault-success)] flex items-center gap-1.5">
                        <Shield className="w-4 h-4" />
                        <span>Kod 2FA TOTP ({liveTotpData.secondsRemaining}s)</span>
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          handleCopy(
                            liveTotpData.code.replace(/\s+/g, ''),
                            'magnified_totp',
                            false
                          )
                        }
                        className="px-2.5 py-1 text-xs font-semibold text-[var(--vault-text)] border border-[var(--vault-border)] bg-[var(--vault-surface)] rounded-lg cursor-pointer"
                      >
                        {copiedField === 'magnified_totp'
                          ? 'Skopiowano!'
                          : 'Kopiuj 2FA'}
                      </button>
                    </div>
                    <div className="font-mono text-2xl sm:text-4xl font-bold tracking-widest text-[var(--vault-success)] tabular-nums select-all">
                      {liveTotpData.code}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Character-by-Character Breakdown Grid */}
            <div className="space-y-2.5">
              <div className="text-xs font-medium text-[var(--vault-muted)]">
                Podział znak po znaku (rozróżnia cyfry np. <strong className="text-[var(--vault-accent)]">0</strong> od wielkiej litery <strong className="text-[var(--vault-text)]">O</strong> oraz <strong className="text-[var(--vault-accent)]">1</strong> od <strong className="text-[var(--vault-text)]">l</strong>):
              </div>
              <div className="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 gap-2">
                {Array.from(magnifiedViewData.password).map((ch, idx) => {
                  const isDigit = /^[0-9]$/.test(ch);
                  const isUpper = /^[A-ZĄĆĘŁŃÓŚŹŻ]$/.test(ch);
                  const isLower = /^[a-ząćęłńóśźż]$/.test(ch);
                  const charTypeLabel = isDigit
                    ? 'CYFRA'
                    : isUpper
                      ? 'WIELKA'
                      : isLower
                        ? 'mała'
                        : ch === ' '
                          ? 'SPACJA'
                          : 'ZNAK';
                  return (
                    <div
                      key={`${idx}_${ch}`}
                      className={`p-2.5 rounded-xl border flex flex-col items-center justify-center text-center ${
                        isDigit
                          ? 'border-[var(--vault-accent)] bg-[var(--vault-surface)]'
                          : 'border-[var(--vault-border)] bg-[var(--vault-bg)]'
                      }`}
                    >
                      <span className="text-[10px] font-mono text-[var(--vault-muted)] tabular-nums">
                        #{idx + 1}
                      </span>
                      <span
                        className={`font-mono text-2xl sm:text-3xl font-bold my-0.5 ${
                          isDigit
                            ? 'text-[var(--vault-accent)]'
                            : 'text-[var(--vault-text)]'
                        }`}
                      >
                        {ch === ' ' ? '␣' : ch}
                      </span>
                      <span
                        className={`text-[10px] font-semibold ${
                          isDigit
                            ? 'text-[var(--vault-accent)]'
                            : 'text-[var(--vault-muted)]'
                        }`}
                      >
                        {charTypeLabel}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-2.5">
              {sosTicket?.status === 'resolved' &&
                sosTicket.requestedByMemberId === currentMember.id &&
                onClearSosRequest && (
                  <button
                    type="button"
                    onClick={async () => {
                      await handleClearSosClick();
                      setMagnifiedViewData(null);
                    }}
                    className="w-full py-3 text-sm font-bold text-[#FAF7F2] bg-[var(--vault-success)] hover:opacity-90 rounded-xl cursor-pointer"
                  >
                    Gotowe — wpisałem na TV (Wyczyść zgłoszenie)
                  </button>
                )}
              <button
                type="button"
                onClick={() => setMagnifiedViewData(null)}
                className="w-full py-3 text-sm font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl cursor-pointer"
              >
                Zamknij powiększenie
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 100% CLIENT-SIDE WI-FI QR CODE GENERATOR MODAL */}
      {isQrModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
          onClick={() => setIsQrModalOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-2xl border-2 border-[var(--vault-accent)] bg-[var(--vault-surface)] p-5 sm:p-6 space-y-4 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3 border-b border-[var(--vault-border)] pb-3">
              <div>
                <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--vault-accent)]">
                  <QrCode className="w-4 h-4" />
                  <span>Kod QR Wi-Fi (100% lokalnie w przeglądarce)</span>
                </div>
                <h3 className="text-lg font-bold font-display text-[var(--vault-text)] mt-0.5">
                  {displayServiceName}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setIsQrModalOpen(false)}
                className="p-1.5 rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] hover:bg-[var(--vault-surface-hover)] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-[var(--vault-muted)]">
              Skieruj aparat telefonu (iPhone / Android) na poniższy kod QR, aby automatycznie połączyć się z siecią Wi-Fi bez przepisywania hasła.
            </p>

            {/* SVG QR Code Canvas */}
            <div className="flex flex-col items-center justify-center p-4 rounded-xl bg-white border border-[var(--vault-border)]">
              {wifiQrMatrix.length > 0 ? (
                <svg
                  viewBox={`-4 -4 ${wifiQrMatrix.length + 8} ${wifiQrMatrix.length + 8}`}
                  className="w-56 h-56 sm:w-64 sm:h-64"
                  shapeRendering="crispEdges"
                >
                  <rect
                    x="-4"
                    y="-4"
                    width={wifiQrMatrix.length + 8}
                    height={wifiQrMatrix.length + 8}
                    fill="#FFFFFF"
                  />
                  {wifiQrMatrix.map((row, rIdx) =>
                    row.map((cell, cIdx) =>
                      cell ? (
                        <rect
                          key={`${rIdx}_${cIdx}`}
                          x={cIdx}
                          y={rIdx}
                          width={1}
                          height={1}
                          fill="#111111"
                        />
                      ) : null
                    )
                  )}
                </svg>
              ) : (
                <div className="py-12 text-xs text-neutral-600 text-center">
                  Tekst jest zbyt długi dla lokalnego kodu QR.
                </div>
              )}
            </div>

            <div className="space-y-2 text-xs">
              <div>
                <label className="block text-[11px] font-medium text-[var(--vault-muted)] mb-1">
                  Nazwa sieci Wi-Fi (SSID) w kodzie QR:
                </label>
                <input
                  type="text"
                  value={wifiSsidInput}
                  onChange={(e) => setWifiSsidInput(e.target.value)}
                  placeholder="Nazwa sieci Wi-Fi (SSID)..."
                  maxLength={64}
                  className="w-full px-3 py-1.5 text-xs font-mono rounded-lg border border-[var(--vault-border)] bg-[var(--vault-bg)] text-[var(--vault-text)] focus:outline-none focus:border-[var(--vault-accent)]"
                />
              </div>
              <div className="flex items-center justify-between text-[11px] text-[var(--vault-muted)] pt-1">
                <span>
                  Hasło: <strong className="font-mono text-[var(--vault-text)]">{displayPassword}</strong>
                </span>
                <span>Szyfrowanie: WPA/WPA2</span>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setIsQrModalOpen(false)}
              className="w-full py-2.5 text-xs font-bold text-[#FAF7F2] bg-[var(--vault-accent)] hover:bg-[var(--vault-accent-hover)] rounded-xl cursor-pointer"
            >
              Zamknij kod QR
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export const PasswordCard = React.memo(PasswordCardComponent);

