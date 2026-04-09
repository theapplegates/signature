/**
 * Post-Quantum Cryptographic Service
 *
 * Implements OpenPGP v6-oriented operations with:
 *   - Primary signature algorithm: SLH-DSA-SHAKE-256s
 *   - Subkey encryption algorithm: ML-KEM-1024 + X448 (hybrid)
 *   - Signature hash algorithm: SHA3-512 (ID 14)
 */

import { slh_dsa_shake_256s } from '@noble/post-quantum/slh-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x448 } from '@noble/curves/ed448.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ALGORITHM, CRYPTO_PROFILE } from '../constants';
import type { KeyPair } from '../types';

// ── SLH-DSA-SHAKE-256s key / signature sizes (FIPS 205) ───────────
const SLH_DSA_PK_BYTES = slh_dsa_shake_256s.lengths.publicKey;
const SLH_DSA_SK_BYTES = slh_dsa_shake_256s.lengths.secretKey;

// ── ML-KEM-1024 + X448 sizes ───────────────────────────────────────
const ML_KEM_PK_BYTES = ml_kem1024.lengths.publicKey;
const ML_KEM_SK_BYTES = ml_kem1024.lengths.secretKey;
const ML_KEM_CT_BYTES = ml_kem1024.lengths.cipherText;
const X448_SECRET_BYTES = 56;
const X448_PUBLIC_BYTES = 56;
const AES_GCM_IV_BYTES = 12;
const ENCRYPTED_PACKET_VERSION = 1;

// ── RFC 9580 v6 constants ──────────────────────────────────────────
const V6_VERSION = 6;
const V6_SALT_SIZE = 32; // SHA3-512 salt size (RFC 9580 Table 23)
// Algorithm ID for SLH-DSA-SHAKE-256s — currently private/experimental.
const PK_ALGO_SLH_DSA_SHAKE_256S = 0x66;

// ── Passphrase-based key encryption ────────────────────────────────
const PBKDF2_ITERATIONS = 100000;
const ENCRYPTION_AAD = new TextEncoder().encode(
  `${CRYPTO_PROFILE.keyVersion}|${CRYPTO_PROFILE.subkeyAlgorithm}|${CRYPTO_PROFILE.hashAlgorithm}`
);

// ═══════════════════════════════════════════════════════════════════
//  Byte helpers
// ═══════════════════════════════════════════════════════════════════

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index++) {
    diff |= a[index] ^ b[index];
  }
  return diff === 0;
}

function assertLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.length !== expected) {
    throw new Error(`${label} has invalid length: expected ${expected}, got ${bytes.length}`);
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return out;
}

function uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

function uint32FromBE(bytes: Uint8Array): number {
  if (bytes.length !== 4) throw new Error('uint32FromBE requires 4 bytes');
  return (
    ((bytes[0] << 24) >>> 0) |
    ((bytes[1] << 16) >>> 0) |
    ((bytes[2] << 8) >>> 0) |
    (bytes[3] >>> 0)
  );
}

function encodeNewPacketLength(length: number): Uint8Array {
  if (length < 192) {
    return new Uint8Array([length]);
  }
  if (length <= 8383) {
    const n = length - 192;
    return new Uint8Array([((n >> 8) & 0xff) + 192, n & 0xff]);
  }
  return new Uint8Array([255, (length >>> 24) & 0xff, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff]);
}

function wrapOpenPgpNewPacket(tag: number, body: Uint8Array): Uint8Array {
  const headerByte = 0xc0 | (tag & 0x3f);
  const lengthBytes = encodeNewPacketLength(body.length);
  return concat(new Uint8Array([headerByte]), lengthBytes, body);
}

function unwrapOpenPgpNewPacket(packetBytes: Uint8Array): { tag: number; body: Uint8Array } {
  if (packetBytes.length < 2) {
    throw new Error('OpenPGP packet is too short.');
  }
  const ctb = packetBytes[0];
  if ((ctb & 0x80) === 0) {
    throw new Error('Invalid OpenPGP packet header.');
  }
  if ((ctb & 0x40) === 0) {
    throw new Error('Old-format OpenPGP headers are not supported by this parser.');
  }

  const tag = ctb & 0x3f;
  const firstLength = packetBytes[1];

  let bodyLength: number;
  let bodyOffset: number;

  if (firstLength < 192) {
    bodyLength = firstLength;
    bodyOffset = 2;
  } else if (firstLength >= 192 && firstLength <= 223) {
    if (packetBytes.length < 3) {
      throw new Error('OpenPGP packet length is truncated.');
    }
    bodyLength = ((firstLength - 192) << 8) + packetBytes[2] + 192;
    bodyOffset = 3;
  } else if (firstLength === 255) {
    if (packetBytes.length < 6) {
      throw new Error('OpenPGP packet length is truncated.');
    }
    bodyLength = uint32FromBE(packetBytes.slice(2, 6));
    bodyOffset = 6;
  } else {
    throw new Error('Partial-length OpenPGP packets are not supported by this parser.');
  }

  const bodyEnd = bodyOffset + bodyLength;
  if (packetBytes.length < bodyEnd) {
    throw new Error('OpenPGP packet body is truncated.');
  }

  return { tag, body: packetBytes.slice(bodyOffset, bodyEnd) };
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function base64WithLineBreaks(bytes: Uint8Array): string {
  const raw = base64Encode(bytes);
  return raw.match(/.{1,64}/g)?.join('\n') || '';
}

function extractBase64FromPgpBlock(pgpBlock: string): string {
  const lines = pgpBlock.split('\n');
  const base64Lines = lines.filter(line =>
    !line.startsWith('-----') &&
    !line.startsWith('Comment:') &&
    !line.startsWith('Version:') &&
    !line.startsWith('Hash:') &&
    line.trim() !== ''
  );
  return base64Lines.join('');
}

// ═══════════════════════════════════════════════════════════════════
//  v6 OpenPGP Packet Construction (RFC 9580)
// ═══════════════════════════════════════════════════════════════════

function buildV6PublicKeyPacketBody(
  creationTimestamp: number,
  publicKey: Uint8Array
): Uint8Array {
  return concat(
    new Uint8Array([V6_VERSION]),
    uint32BE(creationTimestamp),
    new Uint8Array([PK_ALGO_SLH_DSA_SHAKE_256S]),
    uint32BE(publicKey.length),
    publicKey
  );
}

function computeV6Fingerprint(packetBody: Uint8Array): Uint8Array {
  const material = concat(
    new Uint8Array([0x9B]),
    uint32BE(packetBody.length),
    packetBody
  );
  return sha256(material);
}

function formatFingerprint(fpBytes: Uint8Array): string {
  return bytesToHex(fpBytes.slice(0, 20))
    .toUpperCase()
    .match(/.{4}/g)
    ?.join(' ') || '';
}

// ═══════════════════════════════════════════════════════════════════
//  v6 Signature Hashing (RFC 9580 Section 5.2.4)
// ═══════════════════════════════════════════════════════════════════

function computeV6MessageDigest(salt: Uint8Array, messageBytes: Uint8Array): Uint8Array {
  const hashInput = concat(salt, messageBytes);
  return sha3_512(hashInput);
}

// ═══════════════════════════════════════════════════════════════════
//  Passphrase Encryption (AES-256-GCM via Web Crypto)
// ═══════════════════════════════════════════════════════════════════

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function encryptBytes(data: Uint8Array, key: CryptoKey): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext: new Uint8Array(ct), iv };
}

async function decryptBytes(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(pt);
}

async function deriveHybridAesKey(mlKemSharedSecret: Uint8Array, x448SharedSecret: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = sha3_512(concat(mlKemSharedSecret, x448SharedSecret));
  const aesKeyBytes = keyMaterial.slice(0, 32);
  return crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function runKeySelfTests(
  slhPk: Uint8Array,
  slhSk: Uint8Array,
  kemPk: Uint8Array,
  kemSk: Uint8Array,
  x448Pk: Uint8Array,
  x448Sk: Uint8Array
): Promise<void> {
  assertLength(slhPk, SLH_DSA_PK_BYTES, 'SLH-DSA public key');
  assertLength(slhSk, SLH_DSA_SK_BYTES, 'SLH-DSA secret key');
  assertLength(kemPk, ML_KEM_PK_BYTES, 'ML-KEM public key');
  assertLength(kemSk, ML_KEM_SK_BYTES, 'ML-KEM secret key');
  assertLength(x448Pk, X448_PUBLIC_BYTES, 'X448 public key');
  assertLength(x448Sk, X448_SECRET_BYTES, 'X448 secret key');

  const derivedSphincsPk = slh_dsa_shake_256s.getPublicKey(slhSk);
  if (!bytesEqual(derivedSphincsPk, slhPk)) {
    throw new Error('SLH-DSA key pair self-test failed: derived public key mismatch.');
  }

  const signTestDigest = computeV6MessageDigest(
    crypto.getRandomValues(new Uint8Array(V6_SALT_SIZE)),
    new TextEncoder().encode('slh-dsa-shake-256s-key-self-test')
  );
  const signTestSig = slh_dsa_shake_256s.sign(signTestDigest, slhSk);
  if (!slh_dsa_shake_256s.verify(signTestSig, signTestDigest, slhPk)) {
    throw new Error('SLH-DSA key pair self-test failed: sign/verify mismatch.');
  }

  const { cipherText: kemCt, sharedSecret: kemSharedSecret } = ml_kem1024.encapsulate(kemPk);
  const kemRecoveredSecret = ml_kem1024.decapsulate(kemCt, kemSk);
  if (!bytesEqual(kemSharedSecret, kemRecoveredSecret)) {
    throw new Error('ML-KEM key pair self-test failed: encapsulation mismatch.');
  }

  const derivedX448Pk = x448.getPublicKey(x448Sk);
  if (!bytesEqual(derivedX448Pk, x448Pk)) {
    throw new Error('X448 key pair self-test failed: derived public key mismatch.');
  }

  const ephemeralX448Sk = crypto.getRandomValues(new Uint8Array(X448_SECRET_BYTES));
  const ephemeralX448Pk = x448.getPublicKey(ephemeralX448Sk);
  const x448Shared1 = x448.getSharedSecret(ephemeralX448Sk, x448Pk);
  const x448Shared2 = x448.getSharedSecret(x448Sk, ephemeralX448Pk);
  if (!bytesEqual(x448Shared1, x448Shared2)) {
    throw new Error('X448 key pair self-test failed: shared secret mismatch.');
  }

  const hybridKey = await deriveHybridAesKey(kemSharedSecret, x448Shared1);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const plaintext = new TextEncoder().encode('hybrid-encryption-self-test');
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: ENCRYPTION_AAD },
    hybridKey,
    plaintext
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: ENCRYPTION_AAD },
    hybridKey,
    encrypted
  );
  if (!bytesEqual(new Uint8Array(decrypted), plaintext)) {
    throw new Error('Hybrid encryption self-test failed: decrypt mismatch.');
  }
}

// ═══════════════════════════════════════════════════════════════════
//  User-ID Parsing & PGP Armor Comment Blocks
// ═══════════════════════════════════════════════════════════════════

function parseUserId(userId: string): { name: string; email: string } {
  const m = userId.match(/(.*)<(.*)>/);
  return m ? { name: m[1].trim(), email: m[2].trim() } : { name: userId, email: '' };
}

export function buildKeyCommentBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  validFrom: string,
  hasSecretKey: boolean
): string {
  const keyPresence = hasSecretKey ? 'secret key available' : 'public key only';
  const typeDesc = `${CRYPTO_PROFILE.primaryAlgorithm} (${CRYPTO_PROFILE.primaryCategory}, ${keyPresence})`;

  return [
    `Comment: User ID:\t${userInfo.name} <${userInfo.email}>`,
    `Comment: Valid from:\t${validFrom}`,
    `Comment: Type:\t${typeDesc}`,
    `Comment: Subkey:\t${CRYPTO_PROFILE.subkeyAlgorithm} (${CRYPTO_PROFILE.subkeyCategory})`,
    `Comment: Key Version:\t${CRYPTO_PROFILE.keyVersion}`,
    `Comment: Hash:\t${CRYPTO_PROFILE.hashAlgorithm} (ID ${CRYPTO_PROFILE.hashId})`,
    `Comment: Fingerprint:\t${fingerprint} (SHA-256 v6)`,
  ].join('\n');
}

// ═══════════════════════════════════════════════════════════════════
//  PGP Armor Block Builders
// ═══════════════════════════════════════════════════════════════════

function createPgpPublicKeyBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  validFrom: string,
  v6PacketBody: Uint8Array
): string {
  // Armor full OpenPGP packet bytes, not just the packet body.
  const publicKeyPacket = wrapOpenPgpNewPacket(6, v6PacketBody);
  const header = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP v6 (RFC 9580)
Hash: ${CRYPTO_PROFILE.hashAlgorithm}
${buildKeyCommentBlock(userInfo, fingerprint, validFrom, false)}
`;
  const footer = `-----END PGP PUBLIC KEY BLOCK-----`;
  return `${header}\n${base64WithLineBreaks(publicKeyPacket)}\n${footer}`;
}

function createPgpPrivateKeyBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  validFrom: string,
  secretKeyBytes: Uint8Array,
  isEncrypted: boolean
): string {
  const commentBlock = buildKeyCommentBlock(userInfo, fingerprint, validFrom, true);
  const encLine = isEncrypted ? '\nComment: Key is encrypted.' : '';
  const header = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP v6 (RFC 9580)
Hash: ${CRYPTO_PROFILE.hashAlgorithm}
${commentBlock}${encLine}
`;
  const footer = `-----END PGP PRIVATE KEY BLOCK-----`;
  return `${header}\n${base64WithLineBreaks(secretKeyBytes)}\n${footer}`;
}

function createPgpEncryptedMessageBlock(payload: Uint8Array, recipientFingerprint: string): string {
  const header = `-----BEGIN PGP MESSAGE-----
Version: OpenPGP v6 (RFC 9580)
Comment: Primary Algorithm:\t${CRYPTO_PROFILE.primaryAlgorithm} (${CRYPTO_PROFILE.primaryCategory})
Comment: Subkey Algorithm:\t${CRYPTO_PROFILE.subkeyAlgorithm} (${CRYPTO_PROFILE.subkeyCategory})
Comment: Hash:\t${CRYPTO_PROFILE.hashAlgorithm} (ID ${CRYPTO_PROFILE.hashId})
Comment: Recipient Fingerprint:\t${recipientFingerprint}
`;
  const footer = `-----END PGP MESSAGE-----`;
  return `${header}\n${base64WithLineBreaks(payload)}\n${footer}`;
}

// ═══════════════════════════════════════════════════════════════════
//  Key Generation
// ═══════════════════════════════════════════════════════════════════

export async function generateKeyPair(userId: string, passphrase?: string): Promise<KeyPair> {
  const { publicKey: slhPk, secretKey: slhSk } = slh_dsa_shake_256s.keygen();
  assertLength(slhPk, SLH_DSA_PK_BYTES, 'SLH-DSA public key');
  assertLength(slhSk, SLH_DSA_SK_BYTES, 'SLH-DSA secret key');

  const { publicKey: kemPk, secretKey: kemSk } = ml_kem1024.keygen();
  assertLength(kemPk, ML_KEM_PK_BYTES, 'ML-KEM public key');
  assertLength(kemSk, ML_KEM_SK_BYTES, 'ML-KEM secret key');

  const x448Sk = crypto.getRandomValues(new Uint8Array(X448_SECRET_BYTES));
  const x448Pk = x448.getPublicKey(x448Sk);
  assertLength(x448Pk, X448_PUBLIC_BYTES, 'X448 public key');

  // Run deterministic self-tests so generated material is cryptographically usable.
  await runKeySelfTests(slhPk, slhSk, kemPk, kemSk, x448Pk, x448Sk);

  const createdAt = new Date();
  const creationTimestamp = Math.floor(createdAt.getTime() / 1000);
  const v6PkBody = buildV6PublicKeyPacketBody(creationTimestamp, slhPk);

  const fpBytes = computeV6Fingerprint(v6PkBody);
  const fingerprint = formatFingerprint(fpBytes);

  const validFrom = createdAt.toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const userInfo = parseUserId(userId);

  const publicKeyPgp = createPgpPublicKeyBlock(userInfo, fingerprint, validFrom, v6PkBody);

  let privateKeyRaw: string;
  let privateKeyPgp: string;
  let kemPrivateKeyRaw: string;
  let x448PrivateKeyRaw: string;
  let salt: string | undefined;
  let iv: string | undefined;
  let kemIv: string | undefined;
  let x448Iv: string | undefined;

  if (passphrase) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKey(passphrase, saltBytes);

    const { ciphertext: signingCiphertext, iv: signingIvBytes } = await encryptBytes(slhSk, derivedKey);
    const { ciphertext: kemCiphertext, iv: kemIvBytes } = await encryptBytes(kemSk, derivedKey);
    const { ciphertext: x448Ciphertext, iv: x448IvBytes } = await encryptBytes(x448Sk, derivedKey);

    privateKeyRaw = bytesToHex(signingCiphertext);
    kemPrivateKeyRaw = bytesToHex(kemCiphertext);
    x448PrivateKeyRaw = bytesToHex(x448Ciphertext);

    salt = bytesToHex(saltBytes);
    iv = bytesToHex(signingIvBytes);
    kemIv = bytesToHex(kemIvBytes);
    x448Iv = bytesToHex(x448IvBytes);

    privateKeyPgp = createPgpPrivateKeyBlock(userInfo, fingerprint, validFrom, signingCiphertext, true);
  } else {
    privateKeyRaw = bytesToHex(slhSk);
    kemPrivateKeyRaw = bytesToHex(kemSk);
    x448PrivateKeyRaw = bytesToHex(x448Sk);
    privateKeyPgp = createPgpPrivateKeyBlock(userInfo, fingerprint, validFrom, slhSk, false);
  }

  return {
    id: `pq_${Date.now()}`,
    userId,
    algorithm: ALGORITHM.name,
    fingerprint,
    createdAt: createdAt.toISOString(),
    publicKeyPgp,
    privateKeyPgp,
    publicKeyRaw: bytesToHex(slhPk),
    privateKeyRaw,
    kemPublicKeyRaw: bytesToHex(kemPk),
    kemPrivateKeyRaw,
    x448PublicKeyRaw: bytesToHex(x448Pk),
    x448PrivateKeyRaw,
    salt,
    iv,
    kemIv,
    x448Iv,
  };
}

// ═══════════════════════════════════════════════════════════════════
//  Key Decryption
// ═══════════════════════════════════════════════════════════════════

export async function decryptPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  if (!key.salt || !key.iv) throw new Error('Key is not encrypted.');
  const saltBytes = hexToBytes(key.salt);
  const ivBytes = hexToBytes(key.iv);
  const ciphertext = hexToBytes(key.privateKeyRaw);
  try {
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const decrypted = await decryptBytes(ciphertext, derivedKey, ivBytes);
    assertLength(decrypted, SLH_DSA_SK_BYTES, 'Decrypted SLH-DSA secret key');
    return bytesToHex(decrypted);
  } catch (error) {
    console.error('Decryption failed', error);
    throw new Error('Decryption failed. Invalid passphrase?');
  }
}

export async function decryptKemPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  if (!key.kemPrivateKeyRaw) throw new Error('Key does not include ML-KEM private material. Regenerate the key pair.');
  if (!key.salt) {
    const rawBytes = hexToBytes(key.kemPrivateKeyRaw);
    assertLength(rawBytes, ML_KEM_SK_BYTES, 'ML-KEM secret key');
    return key.kemPrivateKeyRaw;
  }
  if (!key.kemIv) throw new Error('Key is missing ML-KEM IV. Regenerate the key pair.');

  const saltBytes = hexToBytes(key.salt);
  const ivBytes = hexToBytes(key.kemIv);
  const ciphertext = hexToBytes(key.kemPrivateKeyRaw);

  try {
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const decrypted = await decryptBytes(ciphertext, derivedKey, ivBytes);
    assertLength(decrypted, ML_KEM_SK_BYTES, 'Decrypted ML-KEM secret key');
    return bytesToHex(decrypted);
  } catch (error) {
    console.error('ML-KEM key decryption failed', error);
    throw new Error('Decryption failed. Invalid passphrase?');
  }
}

export async function decryptX448PrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  if (!key.x448PrivateKeyRaw) throw new Error('Key does not include X448 private material. Regenerate the key pair.');
  if (!key.salt) {
    const rawBytes = hexToBytes(key.x448PrivateKeyRaw);
    assertLength(rawBytes, X448_SECRET_BYTES, 'X448 secret key');
    return key.x448PrivateKeyRaw;
  }
  if (!key.x448Iv) throw new Error('Key is missing X448 IV. Regenerate the key pair.');

  const saltBytes = hexToBytes(key.salt);
  const ivBytes = hexToBytes(key.x448Iv);
  const ciphertext = hexToBytes(key.x448PrivateKeyRaw);

  try {
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const decrypted = await decryptBytes(ciphertext, derivedKey, ivBytes);
    assertLength(decrypted, X448_SECRET_BYTES, 'Decrypted X448 secret key');
    return bytesToHex(decrypted);
  } catch (error) {
    console.error('X448 key decryption failed', error);
    throw new Error('Decryption failed. Invalid passphrase?');
  }
}

// ═══════════════════════════════════════════════════════════════════
//  Message Encryption / Decryption (ML-KEM-1024 + X448 hybrid)
// ═══════════════════════════════════════════════════════════════════

type EncryptedPacket = {
  mlKemCipherText: Uint8Array;
  ephemeralX448Public: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
};

function parseEncryptedPacket(packet: Uint8Array): EncryptedPacket {
  const minimumSize = 1 + ML_KEM_CT_BYTES + X448_PUBLIC_BYTES + AES_GCM_IV_BYTES + 4;
  if (packet.length < minimumSize) {
    throw new Error('Encrypted payload is too short.');
  }

  let offset = 0;
  const version = packet[offset];
  offset += 1;
  if (version !== ENCRYPTED_PACKET_VERSION) {
    throw new Error(`Unsupported encrypted packet version: ${version}`);
  }

  const mlKemCipherText = packet.slice(offset, offset + ML_KEM_CT_BYTES);
  offset += ML_KEM_CT_BYTES;

  const ephemeralX448Public = packet.slice(offset, offset + X448_PUBLIC_BYTES);
  offset += X448_PUBLIC_BYTES;

  const iv = packet.slice(offset, offset + AES_GCM_IV_BYTES);
  offset += AES_GCM_IV_BYTES;

  const ciphertextLength = uint32FromBE(packet.slice(offset, offset + 4));
  offset += 4;

  const ciphertext = packet.slice(offset);
  if (ciphertext.length !== ciphertextLength) {
    throw new Error('Encrypted payload length mismatch.');
  }

  return { mlKemCipherText, ephemeralX448Public, iv, ciphertext };
}

export async function encryptMessage(
  recipientKemPublicKeyHex: string,
  recipientX448PublicKeyHex: string,
  message: string,
  recipientFingerprint: string
): Promise<string> {
  const recipientKemPublicKey = hexToBytes(recipientKemPublicKeyHex);
  const recipientX448PublicKey = hexToBytes(recipientX448PublicKeyHex);

  if (recipientKemPublicKey.length !== ML_KEM_PK_BYTES) {
    throw new Error('Recipient ML-KEM public key has an invalid length.');
  }
  if (recipientX448PublicKey.length !== X448_PUBLIC_BYTES) {
    throw new Error('Recipient X448 public key has an invalid length.');
  }

  const { cipherText: mlKemCipherText, sharedSecret: mlKemSharedSecret } = ml_kem1024.encapsulate(recipientKemPublicKey);
  assertLength(mlKemCipherText, ML_KEM_CT_BYTES, 'ML-KEM ciphertext');

  const ephemeralX448Secret = crypto.getRandomValues(new Uint8Array(X448_SECRET_BYTES));
  const ephemeralX448Public = x448.getPublicKey(ephemeralX448Secret);
  assertLength(ephemeralX448Public, X448_PUBLIC_BYTES, 'Ephemeral X448 public key');
  const x448SharedSecret = x448.getSharedSecret(ephemeralX448Secret, recipientX448PublicKey);
  assertLength(x448SharedSecret, X448_SECRET_BYTES, 'X448 shared secret');

  const aesKey = await deriveHybridAesKey(mlKemSharedSecret, x448SharedSecret);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));

  const plaintextBytes = new TextEncoder().encode(message);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: ENCRYPTION_AAD },
    aesKey,
    plaintextBytes
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);

  const packet = concat(
    new Uint8Array([ENCRYPTED_PACKET_VERSION]),
    mlKemCipherText,
    ephemeralX448Public,
    iv,
    uint32BE(ciphertext.length),
    ciphertext
  );

  return createPgpEncryptedMessageBlock(packet, recipientFingerprint);
}

export async function decryptMessage(
  recipientKemPrivateKeyHex: string,
  recipientX448PrivateKeyHex: string,
  pgpMessage: string
): Promise<string> {
  const recipientKemPrivateKey = hexToBytes(recipientKemPrivateKeyHex);
  const recipientX448PrivateKey = hexToBytes(recipientX448PrivateKeyHex);

  if (recipientKemPrivateKey.length !== ML_KEM_SK_BYTES) {
    throw new Error('Recipient ML-KEM private key has an invalid length.');
  }
  if (recipientX448PrivateKey.length !== X448_SECRET_BYTES) {
    throw new Error('Recipient X448 private key has an invalid length.');
  }

  const base64Payload = extractBase64FromPgpBlock(pgpMessage);
  const packet = base64Decode(base64Payload);
  const { mlKemCipherText, ephemeralX448Public, iv, ciphertext } = parseEncryptedPacket(packet);
  assertLength(mlKemCipherText, ML_KEM_CT_BYTES, 'ML-KEM ciphertext');
  assertLength(ephemeralX448Public, X448_PUBLIC_BYTES, 'Ephemeral X448 public key');
  assertLength(iv, AES_GCM_IV_BYTES, 'AES-GCM IV');

  const mlKemSharedSecret = ml_kem1024.decapsulate(mlKemCipherText, recipientKemPrivateKey);
  assertLength(mlKemSharedSecret, 32, 'ML-KEM shared secret');
  const x448SharedSecret = x448.getSharedSecret(recipientX448PrivateKey, ephemeralX448Public);
  assertLength(x448SharedSecret, X448_SECRET_BYTES, 'X448 shared secret');

  const aesKey = await deriveHybridAesKey(mlKemSharedSecret, x448SharedSecret);

  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: ENCRYPTION_AAD },
    aesKey,
    ciphertext
  );

  return new TextDecoder().decode(new Uint8Array(plaintextBuffer));
}

// ═══════════════════════════════════════════════════════════════════
//  Message Signing (RFC 9580 v6 + FIPS 205 SLH-DSA)
// ═══════════════════════════════════════════════════════════════════

export function buildSignedMessageContent(
  message: string,
  keyInfo: { userId: string; fingerprint: string; createdAt: string }
): string {
  const userInfo = parseUserId(keyInfo.userId);
  const validFrom = new Date(keyInfo.createdAt).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const commentBlock = buildKeyCommentBlock(userInfo, keyInfo.fingerprint, validFrom, true);
  return `${commentBlock}\n\n${message}`;
}

function createPgpSignatureBlock(
  signatureBytes: Uint8Array,
  salt: Uint8Array,
  keyInfo: { userId: string; fingerprint: string; createdAt: string }
): string {
  const userInfo = parseUserId(keyInfo.userId);
  const signedOn = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const header = `-----BEGIN PGP SIGNATURE-----`;
  const armorHeaders = [
    `Version: OpenPGP v6 (RFC 9580)`,
    `Hash: ${CRYPTO_PROFILE.hashAlgorithm}`,
    `Comment: User ID:\t${userInfo.name} <${userInfo.email}>`,
    `Comment: Signed on:\t${signedOn}`,
    `Comment: Algorithm:\t${CRYPTO_PROFILE.primaryAlgorithm} (${CRYPTO_PROFILE.primaryCategory})`,
    `Comment: Subkey:\t${CRYPTO_PROFILE.subkeyAlgorithm} (${CRYPTO_PROFILE.subkeyCategory})`,
    `Comment: Fingerprint:\t${keyInfo.fingerprint} (SHA-256 v6)`,
  ].join('\n');
  const footer = `-----END PGP SIGNATURE-----`;

  const armorPayload = concat(salt, signatureBytes);
  return `${header}\n${armorHeaders}\n\n${base64WithLineBreaks(armorPayload)}\n${footer}`;
}

function createClearSignedMessage(signedMessageContent: string, signatureBlock: string): string {
  return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: ${CRYPTO_PROFILE.hashAlgorithm}\n\n${signedMessageContent}\n${signatureBlock}`;
}

export function sign(
  privateKeyHex: string,
  message: string,
  keyInfo: { userId: string; fingerprint: string; createdAt: string; publicKeyRaw?: string }
): { signature: string; signedMessage: string; clearSignedMessage: string } {
  const secretKey = hexToBytes(privateKeyHex);
  assertLength(secretKey, SLH_DSA_SK_BYTES, 'SLH-DSA secret key');

  const derivedPublicKey = slh_dsa_shake_256s.getPublicKey(secretKey);
  assertLength(derivedPublicKey, SLH_DSA_PK_BYTES, 'Derived SLH-DSA public key');

  if (keyInfo.publicKeyRaw) {
    const expectedPublicKey = hexToBytes(keyInfo.publicKeyRaw);
    assertLength(expectedPublicKey, SLH_DSA_PK_BYTES, 'Expected SLH-DSA public key');
    if (!bytesEqual(derivedPublicKey, expectedPublicKey)) {
      throw new Error('Signing key mismatch: private key does not match selected public key.');
    }
  }

  const signedMessage = buildSignedMessageContent(message, keyInfo);
  const messageBytes = new TextEncoder().encode(signedMessage);

  const salt = crypto.getRandomValues(new Uint8Array(V6_SALT_SIZE));
  const digest = computeV6MessageDigest(salt, messageBytes);

  const signatureBytes = slh_dsa_shake_256s.sign(digest, secretKey);
  const signatureBlock = createPgpSignatureBlock(signatureBytes, salt, keyInfo);
  const clearSignedMessage = createClearSignedMessage(signedMessage, signatureBlock);

  return { signature: signatureBlock, signedMessage, clearSignedMessage };
}

// ═══════════════════════════════════════════════════════════════════
//  Signature Verification (RFC 9580 v6 + FIPS 205 SLH-DSA)
// ═══════════════════════════════════════════════════════════════════

/**
 * Extract the raw SLH-DSA public key from a v6 Public Key packet body.
 * Layout: version(1) || creation_time(4) || algorithm(1) || key_len(4) || key_material
 */
export function extractRawPublicKeyFromV6Packet(packetBytes: Uint8Array): Uint8Array {
  let packetBody = packetBytes;

  // Backward compatibility: older app versions armored only packet body bytes.
  if ((packetBytes[0] & 0x80) !== 0) {
    const parsed = unwrapOpenPgpNewPacket(packetBytes);
    if (parsed.tag !== 6) {
      throw new Error(`Unexpected OpenPGP packet tag ${parsed.tag}; expected public-key packet tag 6.`);
    }
    packetBody = parsed.body;
  }

  if (packetBody.length < 10) {
    throw new Error('v6 public key packet is too short.');
  }

  const keyLength = uint32FromBE(packetBody.slice(6, 10));
  const keyStart = 10;
  const keyEnd = keyStart + keyLength;

  if (packetBody.length < keyEnd) {
    throw new Error('v6 public key packet key length is truncated.');
  }

  const rawKey = packetBody.slice(keyStart, keyEnd);
  assertLength(rawKey, SLH_DSA_PK_BYTES, 'Extracted SLH-DSA public key');
  return rawKey;
}

export function verify(
  publicKeyHex: string,
  message: string,
  signatureBase64: string
): boolean {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    assertLength(publicKey, SLH_DSA_PK_BYTES, 'SLH-DSA public key');
    const messageBytes = new TextEncoder().encode(message);

    const payload = base64Decode(signatureBase64);
    if (payload.length < V6_SALT_SIZE + 1) {
      console.error('Signature payload too short');
      return false;
    }

    const salt = payload.slice(0, V6_SALT_SIZE);
    const signatureBytes = payload.slice(V6_SALT_SIZE);
    if (signatureBytes.length !== slh_dsa_shake_256s.lengths.signature) {
      console.error(`Signature payload length mismatch: expected ${slh_dsa_shake_256s.lengths.signature}, got ${signatureBytes.length}`);
      return false;
    }
    const digest = computeV6MessageDigest(salt, messageBytes);

    return slh_dsa_shake_256s.verify(signatureBytes, digest, publicKey);
  } catch (error) {
    console.error('Verification failed:', error);
    return false;
  }
}
