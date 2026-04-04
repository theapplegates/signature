export const TABS = {
  KEY_MANAGEMENT: 'Key Management',
  SIGN: 'Sign',
  VERIFY: 'Verify',
} as const;

export const ALGORITHM = {
  name: 'SLH-DSA-SHAKE-256f',
  displayName: 'Winternitz / SLH-DSA-SHAKE',
  marketingName: 'Winternitz Signatures',
  security: 256,
  type: 'f',
};
