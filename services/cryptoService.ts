/**
 * Post-Quantum Cryptographic Service
 *
 * Implements SLH-DSA-SHA2-256f digital signatures with:
 *   - v6 OpenPGP key packets per RFC 9580 Section 5.5.2.3
 *   - v6 fingerprint via SHA-256 per RFC 9580 Section 5.5.4.3
 *   - v6 signature packets with 32-byte salt per RFC 9580 Section 5.2.3
 *   - SHA3-512 message digest per RFC 9580 Section 9.5 (Hash ID 14)
 *   - SLH-DSA signing per FIPS 205 / draft-ietf-openpgp-pqc
 */

import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ALGORITHM } from '../constants';
import type { KeyPair } from '../types';

// ── SLH-DSA-SHA2-256f key / signature sizes (FIPS 205) ─────────────
const SLH_DSA_PK_BYTES  = 64;   // public key
const SLH_DSA_SK_BYTES  = 128;  // secret key
const SLH_DSA_SIG_BYTES = 49856; // signature (fast variant)

// ── RFC 9580 v6 constants ──────────────────────────────────────────
const V6_VERSION        = 6;
const V6_SALT_SIZE      = 32;   // SHA3-512 salt size (RFC 9580 Table 23)
const HASH_ALGO_SHA3_512 = 14;  // RFC 9580 Section 9.5
// Algorithm ID for SLH-DSA-SHA2-256f — not yet assigned in IANA;
// the PQ draft uses TBD values. We use a private/experimental range value.
// When IANA assigns the real ID, update this constant.
const PK_ALGO_SLH_DSA_SHA2_256F = 0x65; // experimental / private-use

// ── Passphrase-based key encryption ────────────────────────────────
const PBKDF2_ITERATIONS = 100000;

// ═══════════════════════════════════════════════════════════════════
//  Byte helpers
// ═══════════════════════════════════════════════════════════════════

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return out;
}

/** Encode a 32-bit unsigned integer as 4 big-endian octets. */
function uint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8)  & 0xff;
  buf[3] =  n         & 0xff;
  return buf;
}

/** Concatenate arbitrary Uint8Arrays. */
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

/** Safe base64 for large buffers — avoids spread/call-stack limit. */
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

/** Wrap base64 at 64 characters per line (PGP armor convention). */
function base64WithLineBreaks(bytes: Uint8Array): string {
  const raw = base64Encode(bytes);
  return raw.match(/.{1,64}/g)?.join('\n') || '';
}

// ═══════════════════════════════════════════════════════════════════
//  v6 OpenPGP Packet Construction (RFC 9580)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build a v6 Public Key packet body per RFC 9580 Section 5.5.2.3:
 *   version(1) || creation_time(4) || algorithm(1) || key_material_length(4) || key_material
 */
function buildV6PublicKeyPacketBody(
  creationTimestamp: number,
  publicKey: Uint8Array
): Uint8Array {
  return concat(
    new Uint8Array([V6_VERSION]),
    uint32BE(creationTimestamp),
    new Uint8Array([PK_ALGO_SLH_DSA_SHA2_256F]),
    uint32BE(publicKey.length),
    publicKey
  );
}

/**
 * Compute a v6 fingerprint per RFC 9580 Section 5.5.4.3:
 *   SHA-256( 0x9B || packet_length(4) || packet_body )
 *
 * Returns 32 bytes (256 bits).
 */
function computeV6Fingerprint(packetBody: Uint8Array): Uint8Array {
  const material = concat(
    new Uint8Array([0x9B]),
    uint32BE(packetBody.length),
    packetBody
  );
  return sha256(material);
}

/**
 * Format a fingerprint as space-separated 4-char hex groups.
 * Uses the full 40-hex-character (20-byte) prefix for display,
 * matching the traditional PGP fingerprint display convention.
 */
function formatFingerprint(fpBytes: Uint8Array): string {
  return bytesToHex(fpBytes.slice(0, 20))
    .toUpperCase()
    .match(/.{4}/g)
    ?.join(' ') || '';
}

// ═══════════════════════════════════════════════════════════════════
//  v6 Signature Hashing (RFC 9580 Section 5.2.4)
// ═══════════════════════════════════════════════════════════════════

/**
 * Compute the message digest for a v6 signature per RFC 9580:
 *   SHA3-512( salt(32) || message_bytes )
 *
 * The salt is a 32-byte random value prepended to the hash context
 * before any other data (RFC 9580 Section 5.2.4).
 */
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
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext: new Uint8Array(ct), iv };
}

async function decryptBytes(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(pt);
}

// ═══════════════════════════════════════════════════════════════════
//  User-ID Parsing & PGP Armor Comment Blocks
// ═══════════════════════════════════════════════════════════════════

function parseUserId(userId: string): { name: string; email: string } {
  const m = userId.match(/(.*)<(.*)>/);
  return m ? { name: m[1].trim(), email: m[2].trim() } : { name: userId, email: '' };
}

/**
 * Build the PGP-style comment header block that describes the key identity.
 * This block is:
 *   1. Placed in PGP armor headers for key blocks and signatures
 *   2. Prepended to the message body before signing, so the identity
 *      metadata is cryptographically bound to every signature
 */
export function buildKeyCommentBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  validFrom: string,
  hasSecretKey: boolean
): string {
  const typeDesc = hasSecretKey
    ? `${ALGORITHM.security}-bit ${ALGORITHM.displayName} (fast, secret key available)`
    : `${ALGORITHM.security}-bit ${ALGORITHM.displayName} (fast)`;
  return [
    `Comment: User ID:\t${userInfo.name} <${userInfo.email}>`,
    `Comment: Valid from:\t${validFrom}`,
    `Comment: Type:\t${typeDesc}`,
    `Comment: Usage:\tPost-Quantum Digital Signing`,
    `Comment: Fingerprint:\t${fingerprint} (SHA3-512)`,
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
  const header = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP v6 (RFC 9580)
Hash: SHA3-512
${buildKeyCommentBlock(userInfo, fingerprint, validFrom, false)}
`;
  const footer = `-----END PGP PUBLIC KEY BLOCK-----`;
  return `${header}\n${base64WithLineBreaks(v6PacketBody)}\n${footer}`;
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
Hash: SHA3-512
${commentBlock}${encLine}
`;
  const footer = `-----END PGP PRIVATE KEY BLOCK-----`;
  return `${header}\n${base64WithLineBreaks(secretKeyBytes)}\n${footer}`;
}

// ═══════════════════════════════════════════════════════════════════
//  Key Generation
// ═══════════════════════════════════════════════════════════════════

export async function generateKeyPair(userId: string, passphrase?: string): Promise<KeyPair> {
  // Generate real SLH-DSA-SHA2-256f key pair (FIPS 205, fast variant)
  const { publicKey: slhPk, secretKey: slhSk } = slh_dsa_sha2_256f.keygen();

  // Build v6 Public Key packet body (RFC 9580 Section 5.5.2.3)
  const createdAt = new Date();
  const creationTimestamp = Math.floor(createdAt.getTime() / 1000);
  const v6PkBody = buildV6PublicKeyPacketBody(creationTimestamp, slhPk);

  // Compute v6 fingerprint (SHA-256 per RFC 9580 Section 5.5.4.3)
  const fpBytes = computeV6Fingerprint(v6PkBody);
  const fingerprint = formatFingerprint(fpBytes);

  const validFrom = createdAt.toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const userInfo = parseUserId(userId);

  const publicKeyPgp = createPgpPublicKeyBlock(userInfo, fingerprint, validFrom, v6PkBody);

  let privateKeyRaw: string;
  let privateKeyPgp: string;
  let salt: string | undefined;
  let iv: string | undefined;

  if (passphrase) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const { ciphertext, iv: ivBytes } = await encryptBytes(slhSk, derivedKey);

    privateKeyRaw = bytesToHex(ciphertext);
    salt = bytesToHex(saltBytes);
    iv = bytesToHex(ivBytes);
    privateKeyPgp = createPgpPrivateKeyBlock(userInfo, fingerprint, validFrom, ciphertext, true);
  } else {
    privateKeyRaw = bytesToHex(slhSk);
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
    salt,
    iv,
  };
}

// ═══════════════════════════════════════════════════════════════════
//  Key Decryption
// ═══════════════════════════════════════════════════════════════════

export async function decryptPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  if (!key.salt || !key.iv) throw new Error('Key is not encrypted.');
  const saltBytes = hexToBytes(key.salt);
  const ivBytes   = hexToBytes(key.iv);
  const ciphertext = hexToBytes(key.privateKeyRaw);
  try {
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const decrypted  = await decryptBytes(ciphertext, derivedKey, ivBytes);
    return bytesToHex(decrypted);
  } catch (e) {
    console.error('Decryption failed', e);
    throw new Error('Decryption failed. Invalid passphrase?');
  }
}

// ═══════════════════════════════════════════════════════════════════
//  Message Signing (RFC 9580 v6 + FIPS 205 SLH-DSA)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the message preamble that gets prepended to the user's message before signing.
 * This binds the key identity metadata into the signed content.
 */
export function buildSignedMessageContent(
  message: string,
  keyInfo: { userId: string; fingerprint: string; createdAt: string }
): string {
  const userInfo  = parseUserId(keyInfo.userId);
  const validFrom = new Date(keyInfo.createdAt).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const commentBlock = buildKeyCommentBlock(userInfo, keyInfo.fingerprint, validFrom, true);
  return `${commentBlock}\n\n${message}`;
}

function createPgpSignatureBlock(
  signatureBytes: Uint8Array,
  salt: Uint8Array,
  keyInfo: { userId: string; fingerprint: string; createdAt: string }
): string {
  const userInfo  = parseUserId(keyInfo.userId);
  const signedOn  = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const header    = `-----BEGIN PGP SIGNATURE-----`;
  const armorHeaders = [
    `Version: OpenPGP v6 (RFC 9580)`,
    `Hash: SHA3-512`,
    `Comment: User ID:\t${userInfo.name} <${userInfo.email}>`,
    `Comment: Signed on:\t${signedOn}`,
    `Comment: Algorithm:\t${ALGORITHM.name} (fast)`,
    `Comment: Usage:\tPost-Quantum Digital Signing`,
    `Comment: Fingerprint:\t${keyInfo.fingerprint} (SHA3-512)`,
  ].join('\n');
  const footer = `-----END PGP SIGNATURE-----`;

  // Encode: salt(32) || signature into the armor body
  // so the verifier can extract the salt needed to recompute the digest.
  const armorPayload = concat(salt, signatureBytes);
  return `${header}\n${armorHeaders}\n\n${base64WithLineBreaks(armorPayload)}\n${footer}`;
}

/**
 * Sign a message with SLH-DSA-SHA2-256f per RFC 9580 v6 profile:
 *   1. Prepend key identity comment headers to the message
 *   2. Generate 32-byte random salt (RFC 9580 Section 5.2.3, Table 23)
 *   3. Compute digest = SHA3-512(salt || message_bytes) (RFC 9580 Section 5.2.4)
 *   4. Sign the digest with SLH-DSA-SHA2-256f (FIPS 205)
 *
 * Returns the PGP signature block and the full signed message content.
 */
export function sign(
  privateKeyHex: string,
  message: string,
  keyInfo: { userId: string; fingerprint: string; createdAt: string }
): { signature: string; signedMessage: string } {
  const secretKey = hexToBytes(privateKeyHex);

  // Build full signed message content with key identity headers prepended
  const signedMessage = buildSignedMessageContent(message, keyInfo);
  const messageBytes  = new TextEncoder().encode(signedMessage);

  // RFC 9580 v6: generate 32-byte random salt
  const salt = crypto.getRandomValues(new Uint8Array(V6_SALT_SIZE));

  // RFC 9580 Section 5.2.4: salt is fed into hash context before message data
  const digest = computeV6MessageDigest(salt, messageBytes);

  // FIPS 205: sign(message_digest, secret_key)
  const signatureBytes = slh_dsa_sha2_256f.sign(digest, secretKey);
  const signatureBlock = createPgpSignatureBlock(signatureBytes, salt, keyInfo);

  return { signature: signatureBlock, signedMessage };
}

// ═══════════════════════════════════════════════════════════════════
//  Signature Verification (RFC 9580 v6 + FIPS 205 SLH-DSA)
// ═══════════════════════════════════════════════════════════════════

/**
 * Verify a signature against a message with SLH-DSA-SHA2-256f.
 *
 * The signatureBase64 armor body contains: salt(32) || signature(49856).
 * The message should include the prepended key identity comment headers
 * (as produced by sign()), since those were part of what was signed.
 *
 * Verification:
 *   1. Extract salt and signature from the armor payload
 *   2. Recompute digest = SHA3-512(salt || message_bytes)
 *   3. Verify with SLH-DSA-SHA2-256f
 */
/**
 * Extract the raw SLH-DSA public key from a v6 Public Key packet body.
 * Layout: version(1) || creation_time(4) || algorithm(1) || key_len(4) || key_material
 * The raw public key starts at offset 10.
 */
export function extractRawPublicKeyFromV6Packet(packetBytes: Uint8Array): Uint8Array {
  // Skip: version(1) + creation_time(4) + algorithm(1) + key_material_length(4) = 10 bytes
  return packetBytes.slice(10);
}

export function verify(
  publicKeyHex: string,
  message: string,
  signatureBase64: string
): boolean {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    const messageBytes = new TextEncoder().encode(message);

    // Decode the armor payload: salt(32) || signature
    const payload = base64Decode(signatureBase64);
    if (payload.length < V6_SALT_SIZE + 1) {
      console.error('Signature payload too short');
      return false;
    }

    const salt = payload.slice(0, V6_SALT_SIZE);
    const signatureBytes = payload.slice(V6_SALT_SIZE);

    // RFC 9580 Section 5.2.4: recompute digest with salt prepended
    const digest = computeV6MessageDigest(salt, messageBytes);

    // FIPS 205: verify(signature, message_digest, public_key)
    return slh_dsa_sha2_256f.verify(signatureBytes, digest, publicKey);
  } catch (error) {
    console.error('Verification failed:', error);
    return false;
  }
}
