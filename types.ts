import { TABS } from './constants';

export type Tab = typeof TABS[keyof typeof TABS];

export interface KeyPair {
  id: string;
  userId: string;
  algorithm: string;
  fingerprint: string;
  createdAt: string;
  publicKeyPgp: string;
  privateKeyPgp: string;
  publicKeyRaw: string; // SLH-DSA-SHAKE-256s public key stored as hex (64 bytes)
  privateKeyRaw: string; // SLH-DSA-SHAKE-256s secret key stored as hex (128 bytes, plaintext or ciphertext)
  kemPublicKeyRaw?: string; // ML-KEM-1024 public key stored as hex (1568 bytes)
  kemPrivateKeyRaw?: string; // ML-KEM-1024 secret key stored as hex (3168 bytes, plaintext or ciphertext)
  x448PublicKeyRaw?: string; // X448 public key stored as hex (56 bytes)
  x448PrivateKeyRaw?: string; // X448 private key stored as hex (56 bytes, plaintext or ciphertext)
  salt?: string; // Stored as hex, present if private key is encrypted
  iv?: string; // Signing key IV, stored as hex when private key is encrypted
  kemIv?: string; // ML-KEM private key IV, stored as hex when private key is encrypted
  x448Iv?: string; // X448 private key IV, stored as hex when private key is encrypted
}
