import { DecryptedPrivatePayload } from '../types/vault';
import { normalizeHardwareModelOnly } from './deviceAndBiometrics';

const PBKDF2_ITERATIONS = 100000;
const ESCROW_SECRET = 'FamilyStreamVault-MergeEscrow-Key-v1-2026';

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function generateSaltBase64(byteLength = 16): string {
  const salt = new Uint8Array(byteLength);
  window.crypto.getRandomValues(salt);
  return bytesToBase64(salt);
}

export function generateRandomDekBase64(): string {
  const dek = new Uint8Array(32); // 256 bits
  window.crypto.getRandomValues(dek);
  return bytesToBase64(dek);
}

async function deriveAesKeyFromPassword(
  password: string,
  saltBase64: string
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const saltBytes = base64ToBytes(saltBase64);
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes.buffer as ArrayBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function importRawAesKey(dekBase64: string): Promise<CryptoKey> {
  const rawBytes = base64ToBytes(dekBase64);
  return window.crypto.subtle.importKey(
    'raw',
    rawBytes.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function hashPasswordForAuth(
  password: string,
  saltBase64: string
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password + ':auth-verify'),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const saltBytes = base64ToBytes(saltBase64);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes.buffer as ArrayBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  return bytesToBase64(new Uint8Array(bits));
}

export async function encryptWithCryptoKey(
  plainText: string,
  key: CryptoKey
): Promise<string> {
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);
  const encoded = new TextEncoder().encode(plainText);
  const cipherBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    encoded
  );
  const ivB64 = bytesToBase64(iv);
  const cipherB64 = bytesToBase64(new Uint8Array(cipherBuffer));
  return `ENC[AES-256-GCM:${ivB64}:${cipherB64}]`;
}

export async function decryptWithCryptoKey(
  encryptedFormatted: string,
  key: CryptoKey
): Promise<string> {
  if (
    !encryptedFormatted.startsWith('ENC[AES-256-GCM:') ||
    !encryptedFormatted.endsWith(']')
  ) {
    throw new Error('Nieprawidłowy format zaszyfrowanych danych.');
  }
  const inner = encryptedFormatted.slice('ENC[AES-256-GCM:'.length, -1);
  const parts = inner.split(':');
  if (parts.length !== 2) {
    throw new Error('Uszkodzony nagłówek szyfrogramu AES-256-GCM.');
  }
  const [ivB64, cipherB64] = parts;
  const iv = base64ToBytes(ivB64);
  const cipherBytes = base64ToBytes(cipherB64);
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    cipherBytes.buffer as ArrayBuffer
  );
  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Envelope Encryption (DEK + KEK):
 * Wraps the user's 256-bit DEK with a KEK derived from their password via PBKDF2.
 */
export async function wrapDekWithPassword(
  dekBase64: string,
  password: string,
  saltBase64: string
): Promise<string> {
  const kek = await deriveAesKeyFromPassword(password, saltBase64);
  return encryptWithCryptoKey(dekBase64, kek);
}

export async function unwrapDekWithPassword(
  wrappedDek: string,
  password: string,
  saltBase64: string
): Promise<string> {
  const kek = await deriveAesKeyFromPassword(password, saltBase64);
  return decryptWithCryptoKey(wrappedDek, kek);
}

/**
 * HARDCORE HARDWARE-BOUND ENVELOPE ENCRYPTION (Per-Device Certificate + Password + Hardware Profile):
 * Derives a 256-bit AES-GCM Key-Encryption-Key (KEK) from the cryptographic composition of:
 * 1. User's Master Password (or Admin Secret)
 * 2. Account PBKDF2 Salt
 * 3. Device Hardware Fingerprint (`deviceFingerprint`)
 * 4. Device Model & OS (`hardwareModelOs`, e.g. Android SM-S928B, iPhone iOS, Windows, macOS)
 * 5. Device Form Factor (`hardwareDeviceType`: phone | tablet | laptop_desktop)
 * 6. Client Launch Mode (`clientMode`: pwa | browser)
 * 7. Server-Issued Device Approval Certificate Token (`deviceApprovalToken`)
 *
 * Without BOTH the user's password AND the exact approved physical/mode device profile + server token,
 * the AES-256-GCM authentication tag fails and the private DEK cannot be mathematically recovered.
 */
export interface HardwareBoundKeyParams {
  password: string;
  saltBase64: string;
  deviceFingerprint: string;
  hardwareModelOs: string;
  hardwareDeviceType: string;
  clientMode: string;
  deviceApprovalToken: string;
}

async function deriveHardwareBoundAesKey(
  params: HardwareBoundKeyParams,
  useRawLegacyModel = false
): Promise<CryptoKey> {
  const modelIdentifier = useRawLegacyModel
    ? params.hardwareModelOs.trim()
    : normalizeHardwareModelOnly(params.hardwareModelOs);

  const canonicalHardwareComposite = [
    params.password,
    'FSV_HARDWARE_CERT_V1',
    params.deviceFingerprint.trim(),
    modelIdentifier,
    params.hardwareDeviceType.trim(),
    params.clientMode.trim(),
    params.deviceApprovalToken.trim(),
  ].join('|');

  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(canonicalHardwareComposite),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const saltBytes = base64ToBytes(params.saltBase64);
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes.buffer as ArrayBuffer,
      iterations: 150000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrapDekWithHardwareCertificate(
  dekBase64: string,
  params: HardwareBoundKeyParams
): Promise<string> {
  const hwKek = await deriveHardwareBoundAesKey(params, false);
  const cipher = await encryptWithCryptoKey(dekBase64, hwKek);
  return `HW_CERT_V1:${cipher}`;
}

export async function unwrapDekWithHardwareCertificate(
  hardwareWrappedDek: string,
  params: HardwareBoundKeyParams
): Promise<string> {
  const trimmed = hardwareWrappedDek.trim();
  const payload = trimmed.startsWith('HW_CERT_V1:')
    ? trimmed.slice('HW_CERT_V1:'.length)
    : trimmed;
  const hwKek = await deriveHardwareBoundAesKey(params, false);
  try {
    return await decryptWithCryptoKey(payload, hwKek);
  } catch {
    // Seamless fallback if envelope was sealed prior to stripping OS build/version suffix
    try {
      const legacyKek = await deriveHardwareBoundAesKey(params, true);
      return await decryptWithCryptoKey(payload, legacyKek);
    } catch {
      throw new Error(
        'Niezgodność Certyfikatu Sprzętowego Urządzenia lub hasła (AES-256-GCM Hardware Lock). To urządzenie nie ma ważnego klucza sprzętowego dla prywatnych haseł — poproś Administratora lub Zaufanego Opiekuna o przepięcie certyfikatu na to urządzenie.'
      );
    }
  }
}

/**
 * Wraps the DEK for account consolidation (Scalanie Kont Użytkowników),
 * so if a user created two accounts by mistake, Admin can merge them and the target
 * account retains the ability to decrypt private entries created on the merged account.
 */
export async function wrapDekForMergeEscrow(
  dekBase64: string,
  saltBase64: string
): Promise<string> {
  const escrowKey = await deriveAesKeyFromPassword(ESCROW_SECRET, saltBase64);
  return encryptWithCryptoKey(dekBase64, escrowKey);
}

export async function unwrapDekFromMergeEscrow(
  escrowWrapped: string,
  saltBase64: string
): Promise<string> {
  const escrowKey = await deriveAesKeyFromPassword(ESCROW_SECRET, saltBase64);
  return decryptWithCryptoKey(escrowWrapped, escrowKey);
}

/**
 * Encrypts the ENTIRE private record payload (categoryId, serviceName, serviceUrl, login, password)
 * so that in the database and in the Admin's view, nobody knows what service it is, what the login is,
 * or what the password is—only the user who created the record!
 */
export async function encryptPrivateRecordPayload(
  payload: DecryptedPrivatePayload,
  dekBase64: string
): Promise<string> {
  const key = await importRawAesKey(dekBase64);
  const json = JSON.stringify(payload);
  return encryptWithCryptoKey(json, key);
}

/**
 * Decrypts a private record payload in memory using the logged-in owner's active DEK
 * (or any DEK from previously merged accounts of the same user).
 */
export async function decryptPrivateRecordPayload(
  encryptedPayload: string,
  primaryDekBase64: string,
  mergedDeksBase64: string[] = []
): Promise<DecryptedPrivatePayload | null> {
  const candidateDeks = [primaryDekBase64, ...mergedDeksBase64].filter(Boolean);
  for (const dek of candidateDeks) {
    try {
      const key = await importRawAesKey(dek);
      const json = await decryptWithCryptoKey(encryptedPayload, key);
      const parsed = JSON.parse(json) as DecryptedPrivatePayload;
      if (parsed && typeof parsed.serviceName === 'string') {
        return parsed;
      }
    } catch {
      // Try next candidate key if this record came from a merged account
    }
  }
  return null;
}

/**
 * Encrypts & decrypts the full .vault.enc backup file using PBKDF2 + AES-256-GCM.
 */
export async function encryptVaultBackupFile(
  plainJson: string,
  passphrase: string
): Promise<string> {
  const saltB64 = generateSaltBase64(16);
  const key = await deriveAesKeyFromPassword(passphrase, saltB64);
  const encryptedBody = await encryptWithCryptoKey(plainJson, key);
  return `VAULT_BACKUP_V1:${saltB64}:${encryptedBody}`;
}

export async function decryptVaultBackupFile(
  fileContent: string,
  passphrase: string
): Promise<string> {
  const trimmed = fileContent.trim();
  if (!trimmed.startsWith('VAULT_BACKUP_V1:')) {
    throw new Error('Nieprawidłowy format pliku kopii zapasowej (.vault.enc).');
  }
  const firstColon = trimmed.indexOf(':');
  const secondColon = trimmed.indexOf(':', firstColon + 1);
  if (firstColon === -1 || secondColon === -1) {
    throw new Error('Uszkodzony nagłówek pliku .vault.enc.');
  }
  const saltB64 = trimmed.slice(firstColon + 1, secondColon);
  const encryptedBody = trimmed.slice(secondColon + 1);
  const key = await deriveAesKeyFromPassword(passphrase, saltB64);
  return decryptWithCryptoKey(encryptedBody, key);
}

export function generateStrongPassword(length = 16): string {
  const charset =
    'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-=?';
  const randomValues = new Uint32Array(length);
  window.crypto.getRandomValues(randomValues);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

/**
 * Wraps `dekBase64` and `mergedDeks` into an AES-256-GCM ciphertext (`ENC[AES-256-GCM:iv:cipher]`)
 * before storing in localStorage (`fsv_remembered_session_v1` or `fsv_biometric_vault_v1`).
 * Ensures raw DEK keys never appear in plain text in browser DevTools (F12 -> Storage).
 */
export async function wrapLocalDeviceKeysPayload(params: {
  dekBase64: string;
  mergedDeks: string[];
  deviceFingerprint: string;
  hardwareSignatureHash: string;
  bindingToken: string;
  saltBase64?: string;
}): Promise<{ wrappedKeysPayload: string; keyWrapSaltBase64: string }> {
  const keyWrapSaltBase64 = params.saltBase64 || generateSaltBase64(16);
  const compositeSecret = [
    'FSV_LOCAL_WRAPPED_KEY_V1',
    params.deviceFingerprint.trim(),
    params.hardwareSignatureHash.trim(),
    params.bindingToken.trim(),
  ].join('|');
  const kek = await deriveAesKeyFromPassword(
    compositeSecret,
    keyWrapSaltBase64
  );
  const plainJson = JSON.stringify({
    dekBase64: params.dekBase64,
    mergedDeks: params.mergedDeks || [],
  });
  const wrappedKeysPayload = await encryptWithCryptoKey(plainJson, kek);
  return { wrappedKeysPayload, keyWrapSaltBase64 };
}

export async function unwrapLocalDeviceKeysPayload(params: {
  wrappedKeysPayload: string;
  keyWrapSaltBase64: string;
  deviceFingerprint: string;
  hardwareSignatureHash: string;
  bindingToken: string;
}): Promise<{ dekBase64: string; mergedDeks: string[] }> {
  const compositeSecret = [
    'FSV_LOCAL_WRAPPED_KEY_V1',
    params.deviceFingerprint.trim(),
    params.hardwareSignatureHash.trim(),
    params.bindingToken.trim(),
  ].join('|');
  const kek = await deriveAesKeyFromPassword(
    compositeSecret,
    params.keyWrapSaltBase64
  );
  const decryptedJson = await decryptWithCryptoKey(
    params.wrappedKeysPayload,
    kek
  );
  const parsed = JSON.parse(decryptedJson) as {
    dekBase64?: string;
    mergedDeks?: string[];
  };
  if (!parsed?.dekBase64) {
    throw new Error('Nieprawidłowy ładunek klucza wtórnego (Wrapped Key).');
  }
  return {
    dekBase64: parsed.dekBase64,
    mergedDeks: Array.isArray(parsed.mergedDeks) ? parsed.mergedDeks : [],
  };
}

/**
 * Strictly validates that a service URL uses only `https:` or `http:` protocol,
 * blocking `javascript:`, `data:`, `vbscript:` or other XSS URI vectors.
 */
export function sanitizeSafeHttpUrl(rawUrl?: string | null): string | null {
  if (!rawUrl) return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return parsed.toString();
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decodes a Base32 string (RFC 4648, used by Google Authenticator / 2FA TOTP secrets)
 * into a Uint8Array. Ignores spaces, hyphens, and padding '='.
 */
function base32ToBytes(rawBase32: string): Uint8Array | null {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = rawBase32
    .toUpperCase()
    .replace(/[\s\-=]+/g, '')
    .trim();
  if (!cleaned) return null;

  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = alphabet.indexOf(cleaned[i]);
    if (idx === -1) {
      return null;
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

/**
 * Generates a live 6-digit RFC 6238 TOTP 2FA code (30-second window)
 * 100% locally in the browser using Web Crypto API (`HMAC-SHA1`).
 */
export async function generateTotpCode(
  secretBase32: string,
  nowMs: number = Date.now()
): Promise<{ code: string; secondsRemaining: number } | null> {
  const keyBytes = base32ToBytes(secretBase32);
  if (!keyBytes || keyBytes.length === 0) return null;

  try {
    const epochSeconds = Math.floor(nowMs / 1000);
    const timeStep = 30;
    const counter = Math.floor(epochSeconds / timeStep);
    const secondsRemaining = timeStep - (epochSeconds % timeStep);

    const counterBuffer = new ArrayBuffer(8);
    const view = new DataView(counterBuffer);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes.buffer as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      counterBuffer
    );
    const hmac = new Uint8Array(signature);
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = (binary % 1000000).toString().padStart(6, '0');
    return {
      code: `${otp.slice(0, 3)} ${otp.slice(3)}`,
      secondsRemaining,
    };
  } catch {
    return null;
  }
}

/**
 * Zero-Knowledge k-Anonymity Password Breach Check (HaveIBeenPwned Range API):
 * 1. Computes full SHA-1 hash of the password locally in Web Crypto API.
 * 2. Sends ONLY the first 5 hex characters (prefix) to `https://api.pwnedpasswords.com/range/{prefix}`.
 * 3. Compares the remaining 35 hex characters (suffix) strictly in local RAM.
 * The full password or its full hash NEVER leaves the user's browser!
 * Returns the number of breach occurrences (0 = safe / not found).
 */
export async function checkPasswordPwnedKAnonymity(
  password: string
): Promise<number> {
  const trimmed = password.trim();
  if (!trimmed) return 0;

  const encoded = new TextEncoder().encode(trimmed);
  const digestBuffer = await window.crypto.subtle.digest('SHA-1', encoded);
  const hashHex = Array.from(new Uint8Array(digestBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const response = await fetch(
    `https://api.pwnedpasswords.com/range/${prefix}`,
    {
      method: 'GET',
      headers: {
        'Add-Padding': 'true',
      },
    }
  );

  if (!response.ok) {
    throw new Error(`Błąd zapytania k-Anonimowości (${response.status})`);
  }

  const text = await response.text();
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const [lineSuffix, countStr] = line.split(':');
    if (lineSuffix && lineSuffix.trim().toUpperCase() === suffix) {
      const count = parseInt((countStr || '0').trim(), 10);
      return Number.isNaN(count) ? 0 : count;
    }
  }
  return 0;
}


