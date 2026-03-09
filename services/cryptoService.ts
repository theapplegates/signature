import { slh_dsa_sha2_256s } from '@noble/post-quantum/slh-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x448 } from '@noble/curves/ed448';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { ALGORITHM } from '../constants';
import type { KeyPair } from '../types';

// Key component byte sizes (fixed by each algorithm's specification)
const SLH_DSA_PK_BYTES = 64;
const SLH_DSA_SK_BYTES = 128;
const ML_KEM_PK_BYTES = 1568;
const ML_KEM_SK_BYTES = 3168;
const X448_SK_BYTES = 56;

// Combined key layout (all components concatenated):
//   publicKey  = slhPk (64)  || kemPk (1568) || x448Pk (56)  = 1688 bytes
//   secretKey  = slhSk (128) || kemSk (3168) || x448Sk (56)  = 3352 bytes
//
// sign()   reads slhSk  = secretKey.slice(0, 128)
// verify() reads slhPk  = publicKey.slice(0, 64)

const PBKDF2_ITERATIONS = 100000;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Safe base64 for large buffers — avoids spread/call-stack limit
function base64EncodeWithLineBreaks(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.match(/.{1,64}/g)?.join('\n') || '';
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
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
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { ciphertext: new Uint8Array(ciphertext), iv };
}

async function decryptBytes(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new Uint8Array(decrypted);
}

function generateFingerprint(combinedPublicKey: Uint8Array): string {
  const textEncoder = new TextEncoder();
  const data = textEncoder.encode(`${ALGORITHM.name}:${bytesToHex(combinedPublicKey)}`);
  const hashBytes = sha3_512(data);
  return bytesToHex(hashBytes.slice(0, 20)).toUpperCase().match(/.{4}/g)?.join(' ') || '';
}

function parseUserId(userId: string): { name: string; email: string } {
  const match = userId.match(/(.*)<(.*)>/);
  if (match) {
    return { name: match[1].trim(), email: match[2].trim() };
  }
  return { name: userId, email: '' };
}

function createPgpPublicKeyBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  validFrom: string,
  combinedPublicKeyBytes: Uint8Array
): string {
  const header = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP (RFC 9580)
Hash: SHA3-512
Comment: User ID:\t${userInfo.name} <${userInfo.email}>
Comment: Valid from:\t${validFrom}
Comment: Type:\t256-bit ${ALGORITHM.name} (post-quantum hybrid)
Comment: Components:\tSLH-DSA-SHA2-256s (signing) | ML-KEM-1024 (KEM) | X448 (ECDH)
Comment: Usage:\tPost-Quantum Digital Signing + Hybrid Key Encapsulation
Comment: Fingerprint:\t${fingerprint} (SHA3-512)
`;
  const footer = `-----END PGP PUBLIC KEY BLOCK-----`;
  return `${header}\n${base64EncodeWithLineBreaks(combinedPublicKeyBytes)}\n${footer}`;
}

function createPgpPrivateKeyBlock(
  userInfo: { name: string; email: string },
  fingerprint: string,
  combinedSecretKeyBytes: Uint8Array
): string {
  const header = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP (RFC 9580)
Hash: SHA3-512
Comment: User ID:\t${userInfo.name} <${userInfo.email}>
Comment: Type:\t256-bit ${ALGORITHM.name} (post-quantum hybrid)
Comment: Fingerprint:\t${fingerprint} (SHA3-512)
`;
  const footer = `-----END PGP PRIVATE KEY BLOCK-----`;
  return `${header}\n${base64EncodeWithLineBreaks(combinedSecretKeyBytes)}\n${footer}`;
}

export async function generateKeyPair(userId: string, passphrase?: string): Promise<KeyPair> {
  // Generate all three real key pairs
  const { publicKey: slhPk, secretKey: slhSk } = slh_dsa_sha2_256s.keygen();
  const { publicKey: kemPk, secretKey: kemSk } = ml_kem1024.keygen();
  const x448Sk = crypto.getRandomValues(new Uint8Array(X448_SK_BYTES));
  const x448Pk = x448.getPublicKey(x448Sk);

  // Combined key material
  const combinedPublicKey = new Uint8Array(SLH_DSA_PK_BYTES + ML_KEM_PK_BYTES + x448Pk.length);
  combinedPublicKey.set(slhPk, 0);
  combinedPublicKey.set(kemPk, SLH_DSA_PK_BYTES);
  combinedPublicKey.set(x448Pk, SLH_DSA_PK_BYTES + ML_KEM_PK_BYTES);

  const combinedSecretKey = new Uint8Array(SLH_DSA_SK_BYTES + ML_KEM_SK_BYTES + X448_SK_BYTES);
  combinedSecretKey.set(slhSk, 0);
  combinedSecretKey.set(kemSk, SLH_DSA_SK_BYTES);
  combinedSecretKey.set(x448Sk, SLH_DSA_SK_BYTES + ML_KEM_SK_BYTES);

  const fingerprint = generateFingerprint(combinedPublicKey);
  const createdAt = new Date();
  const validFrom = createdAt.toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const userInfo = parseUserId(userId);

  const publicKeyPgp = createPgpPublicKeyBlock(userInfo, fingerprint, validFrom, combinedPublicKey);

  let privateKeyRaw: string;
  let privateKeyPgp: string;
  let salt, iv;

  if (passphrase) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const { ciphertext, iv: ivBytes } = await encryptBytes(combinedSecretKey, derivedKey);

    privateKeyRaw = bytesToHex(ciphertext);
    salt = bytesToHex(saltBytes);
    iv = bytesToHex(ivBytes);

    const header = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP (RFC 9580)
Hash: SHA3-512
Comment: User ID:\t${userInfo.name} <${userInfo.email}>
Comment: Type:\t256-bit ${ALGORITHM.name} (post-quantum hybrid)
Comment: Fingerprint:\t${fingerprint} (SHA3-512)
Comment: Key is encrypted.
`;
    const footer = `-----END PGP PRIVATE KEY BLOCK-----`;
    privateKeyPgp = `${header}\n${base64EncodeWithLineBreaks(ciphertext)}\n${footer}`;
  } else {
    privateKeyRaw = bytesToHex(combinedSecretKey);
    privateKeyPgp = createPgpPrivateKeyBlock(userInfo, fingerprint, combinedSecretKey);
  }

  return {
    id: `pq_${Date.now()}`,
    userId,
    algorithm: ALGORITHM.name,
    fingerprint,
    createdAt: createdAt.toISOString(),
    publicKeyPgp,
    privateKeyPgp,
    publicKeyRaw: bytesToHex(combinedPublicKey),
    privateKeyRaw,
    salt,
    iv,
  };
}

export async function decryptPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
  if (!key.salt || !key.iv) {
    throw new Error('Key is not encrypted.');
  }
  const salt = hexToBytes(key.salt);
  const iv = hexToBytes(key.iv);
  const ciphertext = hexToBytes(key.privateKeyRaw);
  try {
    const derivedKey = await deriveKey(passphrase, salt);
    const decrypted = await decryptBytes(ciphertext, derivedKey, iv);
    return bytesToHex(decrypted);
  } catch (e) {
    console.error('Decryption failed', e);
    throw new Error('Decryption failed. Invalid passphrase?');
  }
}

function createPgpSignatureBlock(
  signatureBytes: Uint8Array,
  keyInfo: { userId: string; fingerprint: string }
): string {
  const userInfo = parseUserId(keyInfo.userId);
  const signedOn = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const header = `-----BEGIN PGP SIGNATURE-----`;
  const armorHeaders = [
    `Version: OpenPGP (RFC 9580)`,
    `Hash: SHA3-512`,
    `Comment: User ID:\t${userInfo.name} <${userInfo.email}>`,
    `Comment: Signed on:\t${signedOn}`,
    `Comment: Algorithm:\t${ALGORITHM.name}`,
    `Comment: Signing key:\tSLH-DSA-SHA2-256s`,
    `Comment: Fingerprint:\t${keyInfo.fingerprint} (SHA3-512)`,
  ].join('\n');
  const footer = `-----END PGP SIGNATURE-----`;
  return `${header}\n${armorHeaders}\n\n${base64EncodeWithLineBreaks(signatureBytes)}\n${footer}`;
}

// combinedPrivKeyHex holds: slhSk (128 B) || kemSk (3168 B) || x448Sk (56 B)
// Per RFC 9580 profile: the message is pre-hashed with SHA3-512 before signing.
export function sign(
  combinedPrivKeyHex: string,
  message: string,
  keyInfo: { userId: string; fingerprint: string }
): string {
  const allBytes = hexToBytes(combinedPrivKeyHex);
  const slhSecretKey = allBytes.slice(0, SLH_DSA_SK_BYTES);
  const messageBytes = new TextEncoder().encode(message);
  // RFC 9580 profile: SHA3-512 pre-hash, then sign the digest
  const digest = sha3_512(messageBytes);
  // noble API: sign(msg, secretKey)
  const signature = slh_dsa_sha2_256s.sign(digest, slhSecretKey);
  return createPgpSignatureBlock(signature, keyInfo);
}

// combinedPubKeyHex holds: slhPk (64 B) || kemPk (1568 B) || x448Pk (56 B)
// Per RFC 9580 profile: the message is pre-hashed with SHA3-512 before verification.
export function verify(
  combinedPubKeyHex: string,
  message: string,
  signatureBase64: string
): boolean {
  try {
    const allBytes = hexToBytes(combinedPubKeyHex);
    const slhPublicKey = allBytes.slice(0, SLH_DSA_PK_BYTES);
    const messageBytes = new TextEncoder().encode(message);
    // RFC 9580 profile: SHA3-512 pre-hash must match what was used in sign()
    const digest = sha3_512(messageBytes);
    const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
    // noble API: verify(sig, msg, publicKey)
    return slh_dsa_sha2_256s.verify(signatureBytes, digest, slhPublicKey);
  } catch (error) {
    console.error('Verification failed:', error);
    return false;
  }
}
