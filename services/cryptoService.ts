import { slh_dsa_sha2_256f } from '@noble/post-quantum/slh-dsa.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { ALGORITHM } from '../constants';
import type { KeyPair } from '../types';

const { alg, name, security } = { alg: slh_dsa_sha2_256f, ...ALGORITHM };

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
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

async function encrypt(data: Uint8Array, key: CryptoKey): Promise<{ ciphertext: Uint8Array, iv: Uint8Array }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
        },
        key,
        data
    );
    return { ciphertext: new Uint8Array(ciphertext), iv };
}

async function decrypt(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array): Promise<Uint8Array> {
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
        },
        key,
        ciphertext
    );
    return new Uint8Array(decrypted);
}

function generateFingerprint(publicKey: Uint8Array): string {
  const textEncoder = new TextEncoder();
  const data = textEncoder.encode(`${name}:${bytesToHex(publicKey)}`);
  const hashBytes = sha3_512(data);
  return bytesToHex(hashBytes.slice(0, 20)).toUpperCase().match(/.{4}/g)?.join(' ') || '';
}

function base64EncodeWithLineBreaks(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.match(/.{1,64}/g)?.join('\n') || '';
}

function parseUserId(userId: string): { name: string, email: string } {
    const match = userId.match(/(.*)<(.*)>/);
    if (match) {
        return { name: match[1].trim(), email: match[2].trim() };
    }
    return { name: userId, email: '' };
}

function createPgpPublicKeyBlock(userInfo: { name: string, email: string }, fingerprint: string, validFrom: string, publicKeyBytes: Uint8Array): string {
  const speedType = ALGORITHM.type === 'f' ? 'fast' : 'small';
  const header = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: User ID:\t${userInfo.name} <${userInfo.email}>
Comment: Valid from:\t${validFrom}
Comment: Type:\t${security}-bit SLH-DSA-SHA2 (${speedType}, secret key available)
Comment: Usage:\tPost-Quantum Digital Signing
Comment: Fingerprint:\t${fingerprint} (SHA3-512)
`;
  const footer = `-----END PGP PUBLIC KEY BLOCK-----`;
  return `${header}\n${base64EncodeWithLineBreaks(publicKeyBytes)}\n${footer}`;
}

function createPgpPrivateKeyBlock(userInfo: { name: string, email: string }, fingerprint: string, privateKeyBytes: Uint8Array): string {
    const header = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: User ID:\t${userInfo.name} <${userInfo.email}>
Comment: Type:\t${security}-bit SLH-DSA-SHA2
Comment: Fingerprint:\t${fingerprint} (SHA3-512)
`;
    const footer = `-----END PGP PRIVATE KEY BLOCK-----`;
    return `${header}\n${base64EncodeWithLineBreaks(privateKeyBytes)}\n${footer}`;
}


export async function generateKeyPair(userId: string, passphrase?: string): Promise<KeyPair> {
  const { publicKey, secretKey } = alg.keygen();
  
  const fingerprint = generateFingerprint(publicKey);
  const createdAt = new Date();
  const validFrom = createdAt.toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  const userInfo = parseUserId(userId);

  const publicKeyPgp = createPgpPublicKeyBlock(userInfo, fingerprint, validFrom, publicKey);
  
  let privateKeyRaw: string;
  let privateKeyPgp: string;
  let salt, iv;

  if (passphrase) {
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKey(passphrase, saltBytes);
    const { ciphertext, iv: ivBytes } = await encrypt(secretKey, derivedKey);
    
    privateKeyRaw = bytesToHex(ciphertext);
    salt = bytesToHex(saltBytes);
    iv = bytesToHex(ivBytes);

    const header = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: User ID:\t${userInfo.name} <${userInfo.email}>
Comment: Type:\t${security}-bit SLH-DSA-SHA2
Comment: Fingerprint:\t${fingerprint} (SHA3-512)
Comment: Key is encrypted.
`;
    const footer = `-----END PGP PRIVATE KEY BLOCK-----`;
    privateKeyPgp = `${header}\n${base64EncodeWithLineBreaks(ciphertext)}\n${footer}`;

  } else {
    privateKeyRaw = bytesToHex(secretKey);
    privateKeyPgp = createPgpPrivateKeyBlock(userInfo, fingerprint, secretKey);
  }

  return {
    id: `pq_${Date.now()}`,
    userId,
    algorithm: name,
    fingerprint,
    createdAt: createdAt.toISOString(),
    publicKeyPgp,
    privateKeyPgp,
    publicKeyRaw: bytesToHex(publicKey),
    privateKeyRaw,
    salt,
    iv,
  };
}

export async function decryptPrivateKey(key: KeyPair, passphrase: string): Promise<string> {
    if (!key.salt || !key.iv) {
        throw new Error("Key is not encrypted.");
    }
    const salt = hexToBytes(key.salt);
    const iv = hexToBytes(key.iv);
    const ciphertext = hexToBytes(key.privateKeyRaw);

    try {
        const derivedKey = await deriveKey(passphrase, salt);
        const decrypted = await decrypt(ciphertext, derivedKey, iv);
        return bytesToHex(decrypted);
    } catch (e) {
        console.error("Decryption failed", e);
        throw new Error("Decryption failed. Invalid passphrase?");
    }
}

function createPgpSignatureBlock(signatureBytes: Uint8Array, keyInfo: { userId: string, fingerprint: string }): string {
    const userInfo = parseUserId(keyInfo.userId);
    const signedOn = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
    const header = `-----BEGIN PGP SIGNATURE-----`;
    const comments = [
        `Comment: User ID:\t${userInfo.name} <${userInfo.email}>`,
        `Comment: Signed on:\t${signedOn}`,
        `Comment: Algorithm:\t${ALGORITHM.name}`,
        `Comment: Fingerprint:\t${keyInfo.fingerprint} (SHA3-512)`
    ].join('\n');
    const footer = `-----END PGP SIGNATURE-----`;
    const base64Signature = base64EncodeWithLineBreaks(signatureBytes);
    return `${header}\n${comments}\n\n${base64Signature}\n${footer}`;
}

export function sign(privateKeyHex: string, message: string, keyInfo: { userId: string, fingerprint: string }): string {
    const privateKey = hexToBytes(privateKeyHex);
    const messageBytes = new TextEncoder().encode(message);
    const signature = alg.sign(privateKey, messageBytes);
    return createPgpSignatureBlock(signature, keyInfo);
}

export function verify(publicKeyHex: string, message: string, signatureBase64: string): boolean {
    try {
        const publicKey = hexToBytes(publicKeyHex);
        const messageBytes = new TextEncoder().encode(message);
        const signatureBytes = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));
        return alg.verify(publicKey, messageBytes, signatureBytes);
    } catch (error) {
        console.error("Verification failed:", error);
        return false;
    }
}