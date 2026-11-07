export type ThemeMode = 'dusk' | 'linen';

export type ClientLaunchMode = 'pwa' | 'browser';

export type MemberRole = 'admin' | 'co_admin' | 'member';

export interface CoAdminPermissions {
  canResetMemberCredentials: boolean;
  canApproveDevicesAndMembers: boolean;
  canCreateInvites: boolean;
  canManagePasswordsAndVod: boolean;
}

export const DEFAULT_CO_ADMIN_PERMISSIONS: CoAdminPermissions = {
  canResetMemberCredentials: true,
  canApproveDevicesAndMembers: true,
  canCreateInvites: true,
  canManagePasswordsAndVod: true,
};

export type InvitationMode = 'single_use' | 'time_limited';

export type InvitationPurpose = 'new_member' | 'account_recovery';

export interface VaultInvitation {
  id: string;
  token: string;
  purpose: InvitationPurpose;
  mode: InvitationMode;
  invitedLabel: string;
  targetMemberId?: string;
  targetMemberName?: string;
  targetUsername?: string;
  createdByMemberId: string;
  createdByMemberName: string;
  expiresAt: string | null;
  maxUses: number;
  usedCount: number;
  status: 'active' | 'used' | 'revoked' | 'expired';
  createdAt: string;
  lastUsedAt?: string;
}

export interface GitHubSyncConfig {
  repoOwner: string;
  repoName: string;
  branch: string;
  lastCommitSha?: string;
  lastCommitUrl?: string;
  lastPushedAt?: string;
  pagesUrl?: string;
  pagesEnabled?: boolean;
  isPrivateRepo?: boolean;
  hasServerSecretPat?: boolean;
  secretPatSource?: 'GITHUB_PAT_ENV' | 'SAVED_SERVER_TOKEN' | 'NONE';
}

export interface GitHubPushResult {
  ok: boolean;
  commitSha: string;
  commitUrl: string;
  repoUrl: string;
  pagesUrl?: string;
  pagesEnabled?: boolean;
  ghPagesPublished?: boolean;
  isPrivateRepo?: boolean;
  branch: string;
  filesCount: number;
  updatedBlobsCount?: number;
  pushedAt: string;
  createdNewRepo?: boolean;
  repoOwner?: string;
  repoName?: string;
}

export interface VaultCategory {
  id: string;
  name: string;
  order: number;
}

export interface VaultConfig {
  initialized: boolean;
  adminUid: string;
  adminEmail: string;
  adminMemberId: string;
  templatesLoaded: boolean;
  categoriesJson: string;
  defaultTheme: ThemeMode;
  clipboardClearSeconds: number;
  autoLockMinutes: number;
  createdAt: string;
  updatedAt: string;
}

export interface Member {
  id: string;
  fullName: string;
  username: string;
  passwordHash: string;
  pbkdf2Salt: string;
  wrappedMasterKey: string;
  vaultEscrowKey: string;
  mergedVaultKeysJson: string;
  role: MemberRole;
  coAdminPermissions?: CoAdminPermissions;
  status: 'active' | 'pending' | 'merged';
  googleUid: string;
  invitedByToken?: string;
  createdAt: string;
  updatedAt: string;
}

export function isPrimaryAdmin(member?: Member | null): boolean {
  if (!member) return false;
  return (
    member.role === 'admin' || member.username.toLowerCase() === 'admin'
  );
}

export function isCoAdmin(member?: Member | null): boolean {
  if (!member) return false;
  return member.role === 'co_admin';
}

export function isAdminOrCoAdmin(member?: Member | null): boolean {
  return isPrimaryAdmin(member) || isCoAdmin(member);
}

export function getEffectiveCoAdminPermissions(
  member?: Member | null
): CoAdminPermissions {
  if (!member) {
    return {
      canResetMemberCredentials: false,
      canApproveDevicesAndMembers: false,
      canCreateInvites: false,
      canManagePasswordsAndVod: false,
    };
  }
  if (isPrimaryAdmin(member)) {
    return {
      canResetMemberCredentials: true,
      canApproveDevicesAndMembers: true,
      canCreateInvites: true,
      canManagePasswordsAndVod: true,
    };
  }
  if (member.role === 'co_admin') {
    return {
      ...DEFAULT_CO_ADMIN_PERMISSIONS,
      ...(member.coAdminPermissions || {}),
    };
  }
  return {
    canResetMemberCredentials: false,
    canApproveDevicesAndMembers: false,
    canCreateInvites: false,
    canManagePasswordsAndVod: false,
  };
}

export type HardwareDeviceType = 'phone' | 'tablet' | 'laptop_desktop';

export interface Device {
  id: string;
  memberId: string;
  memberName: string;
  username: string;
  deviceFingerprint: string;
  deviceName: string;
  customLabel: string;
  clientMode: ClientLaunchMode;
  hardwareModelOs?: string;
  hardwareDeviceType?: HardwareDeviceType;
  hardwareSignatureHash?: string;
  deviceApprovalToken?: string;
  deviceCertificateFingerprint?: string;
  hardwareWrappedDek?: string;
  certificateIssuedAt?: string;
  status: 'approved' | 'pending' | 'revoked';
  webAuthnCredentialId: string;
  requestedAt: string;
  lastSeenAt: string;
}

export interface SubAccountEntry {
  id: string;
  assignedMemberId: string;
  assignedMemberName: string;
  label: string;
  login: string;
  passwordValue: string;
  updatedAt: string;
}

export interface PasswordRecord {
  id: string;
  section: 'shared' | 'private';
  categoryId: string;
  serviceName: string;
  serviceUrl: string;
  login: string;
  passwordValue: string;
  encryptedPayload: string;
  keySalt: string;
  ownerId: string;
  ownerName: string;
  allowedMemberIds: string[];
  revealToAdmin?: boolean;
  subAccountsJson?: string;
  createdAt: string;
  updatedAt: string;
  passwordUpdatedAt: string;
}

export type PasswordSosReason = 'tv_code' | 'password_not_working';

export interface PasswordSosTicket {
  id: string;
  requestedByMemberId: string;
  requestedByMemberName: string;
  targetOwnerId: string;
  targetOwnerName: string;
  reason: PasswordSosReason;
  status: 'pending' | 'resolved';
  responseCode?: string;
  resolvedByName?: string;
  createdAt: string;
  resolvedAt?: string;
}

export interface PasswordHistoryEntry {
  passwordValue: string;
  changedAt: string;
  changedBy: string;
}

export interface PasswordCardExtras {
  subAccounts: SubAccountEntry[];
  sosTicket: PasswordSosTicket | null;
  favoriteMemberIds: string[];
  passwordHistory: PasswordHistoryEntry[];
  profilePinOrNote?: string;
  totpSecret?: string;
}

export function parsePasswordCardExtras(
  record: PasswordRecord
): PasswordCardExtras {
  if (!record.subAccountsJson) {
    return {
      subAccounts: [],
      sosTicket: null,
      favoriteMemberIds: [],
      passwordHistory: [],
    };
  }
  try {
    const parsed = JSON.parse(record.subAccountsJson);
    if (Array.isArray(parsed)) {
      return {
        subAccounts: parsed as SubAccountEntry[],
        sosTicket: null,
        favoriteMemberIds: [],
        passwordHistory: [],
      };
    }
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Partial<PasswordCardExtras>;
      return {
        subAccounts: Array.isArray(obj.subAccounts) ? obj.subAccounts : [],
        sosTicket:
          obj.sosTicket && typeof obj.sosTicket === 'object'
            ? (obj.sosTicket as PasswordSosTicket)
            : null,
        favoriteMemberIds: Array.isArray(obj.favoriteMemberIds)
          ? obj.favoriteMemberIds.filter(
              (id): id is string => typeof id === 'string'
            )
          : [],
        passwordHistory: Array.isArray(obj.passwordHistory)
          ? obj.passwordHistory
              .filter(
                (entry): entry is PasswordHistoryEntry =>
                  Boolean(
                    entry &&
                      typeof entry === 'object' &&
                      typeof entry.passwordValue === 'string'
                  )
              )
              .slice(0, 3)
          : [],
        profilePinOrNote:
          typeof obj.profilePinOrNote === 'string' &&
          obj.profilePinOrNote.trim()
            ? obj.profilePinOrNote.trim()
            : undefined,
        totpSecret:
          typeof obj.totpSecret === 'string' && obj.totpSecret.trim()
            ? obj.totpSecret.trim()
            : undefined,
      };
    }
    return {
      subAccounts: [],
      sosTicket: null,
      favoriteMemberIds: [],
      passwordHistory: [],
    };
  } catch {
    return {
      subAccounts: [],
      sosTicket: null,
      favoriteMemberIds: [],
      passwordHistory: [],
    };
  }
}

export function serializePasswordCardExtras(
  extras: PasswordCardExtras
): string {
  const cleanFavs = Array.from(
    new Set((extras.favoriteMemberIds || []).filter(Boolean))
  );
  const cleanHistory = (extras.passwordHistory || []).slice(0, 3);
  const cleanPinNote = extras.profilePinOrNote?.trim() || undefined;
  const cleanTotp = extras.totpSecret?.trim() || undefined;

  // If there are no extra metadata fields, store as plain array for 100% backward compatibility
  if (
    !extras.sosTicket &&
    cleanFavs.length === 0 &&
    cleanHistory.length === 0 &&
    !cleanPinNote &&
    !cleanTotp
  ) {
    return JSON.stringify(extras.subAccounts || []);
  }
  return JSON.stringify({
    subAccounts: extras.subAccounts || [],
    sosTicket: extras.sosTicket || null,
    favoriteMemberIds: cleanFavs,
    passwordHistory: cleanHistory,
    ...(cleanPinNote ? { profilePinOrNote: cleanPinNote } : {}),
    ...(cleanTotp ? { totpSecret: cleanTotp } : {}),
  });
}

export function parseSubAccounts(record: PasswordRecord): SubAccountEntry[] {
  return parsePasswordCardExtras(record).subAccounts;
}

export interface DecryptedPrivatePayload {
  categoryId: string;
  serviceName: string;
  serviceUrl: string;
  login: string;
  password: string;
  passwordHistory?: PasswordHistoryEntry[];
  profilePinOrNote?: string;
  totpSecret?: string;
}

export interface ActivityLog {
  id: string;
  actorId: string;
  actorName: string;
  actionType: string;
  details: string;
  deviceInfo: string;
  timestamp: string;
}

export interface BackupFileStructure {
  version: string;
  exportedAt: string;
  exportedBy: string;
  vaultConfig: VaultConfig | null;
  members: Member[];
  devices: Device[];
  passwords: PasswordRecord[];
  invitations?: VaultInvitation[];
  activityLogs: ActivityLog[];
}

export const DEFAULT_CATEGORIES: VaultCategory[] = [
  { id: 'vod', name: 'VOD / Streaming', order: 1 },
  { id: 'email', name: 'Email / Poczta', order: 2 },
  { id: 'shop', name: 'Sklep / Zakupy', order: 3 },
  { id: 'services', name: 'Usługi / Rachunki', order: 4 },
  { id: 'gaming', name: 'Gaming / Rozrywka', order: 5 },
  { id: 'wifi', name: 'Wi-Fi / Sieć Domowa', order: 6 },
  { id: 'other', name: 'Inne', order: 7 },
];


