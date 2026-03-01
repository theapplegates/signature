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
  publicKeyRaw: string; // Stored as hex
  privateKeyRaw: string; // Stored as hex (plaintext or ciphertext)
  salt?: string; // Stored as hex, present if private key is encrypted
  iv?: string; // Stored as hex, present if private key is encrypted
}
