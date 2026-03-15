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
  publicKeyRaw: string; // SLH-DSA-SHA2-256f public key stored as hex (64 bytes)
  privateKeyRaw: string; // SLH-DSA-SHA2-256f secret key stored as hex (128 bytes, plaintext or ciphertext)
  salt?: string; // Stored as hex, present if private key is encrypted
  iv?: string; // Stored as hex, present if private key is encrypted
}
