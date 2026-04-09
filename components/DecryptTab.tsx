import React, { useState } from 'react';
import type { KeyPair } from '../types';
import { decryptKemPrivateKey, decryptMessage, decryptX448PrivateKey } from '../services/cryptoService';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { CopyIcon, CheckIcon } from './icons/Icons';

interface Props {
  keys: KeyPair[];
}

export const DecryptTab: React.FC<Props> = ({ keys }) => {
  const [selectedKeyId, setSelectedKeyId] = useState('');
  const [pgpMessage, setPgpMessage] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isCopied, copy] = useCopyToClipboard();

  const selectedKey = keys.find(k => k.id === selectedKeyId);
  const isKeyEncrypted = !!selectedKey?.salt;
  const hasEncryptionMaterial = !!selectedKey?.kemPrivateKeyRaw && !!selectedKey?.x448PrivateKeyRaw;

  const handleDecrypt = async () => {
    if (!selectedKey || !pgpMessage) return;

    if (!selectedKey.kemPrivateKeyRaw || !selectedKey.x448PrivateKeyRaw) {
      setError('Selected key does not include ML-KEM/X448 private subkeys. Generate a new key pair.');
      return;
    }

    setIsDecrypting(true);
    setDecryptedMessage('');
    setError(null);

    setTimeout(async () => {
      try {
        let kemPrivateKeyHex = selectedKey.kemPrivateKeyRaw;
        let x448PrivateKeyHex = selectedKey.x448PrivateKeyRaw;

        if (isKeyEncrypted) {
          if (!passphrase) {
            setError('Passphrase is required for this key.');
            setIsDecrypting(false);
            return;
          }

          kemPrivateKeyHex = await decryptKemPrivateKey(selectedKey, passphrase);
          x448PrivateKeyHex = await decryptX448PrivateKey(selectedKey, passphrase);
        }

        const plaintext = await decryptMessage(kemPrivateKeyHex, x448PrivateKeyHex, pgpMessage);
        setDecryptedMessage(plaintext);
      } catch (decryptError) {
        console.error('Decryption failed:', decryptError);
        setError('Decryption failed. Check the key, passphrase, and message block.');
      } finally {
        setIsDecrypting(false);
      }
    }, 50);
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200 space-y-6">
      <h2 className="text-2xl font-semibold text-gray-800">Decrypt Message</h2>

      <div>
        <label htmlFor="decrypt-key-select" className="block text-sm font-medium text-gray-700 mb-1">Select Your Private Key</label>
        <select
          id="decrypt-key-select"
          value={selectedKeyId}
          onChange={(e) => {
            setSelectedKeyId(e.target.value);
            setPassphrase('');
            setDecryptedMessage('');
            setError(null);
          }}
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition disabled:bg-gray-100"
          disabled={keys.length === 0}
        >
          <option value="">{keys.length > 0 ? 'Select your key...' : 'No keys available'}</option>
          {keys.map(key => (
            <option key={key.id} value={key.id}>
              {key.userId} ({key.fingerprint.substring(0, 19)}...){key.salt ? ' 🔒' : ''}
            </option>
          ))}
        </select>
        {selectedKey && !hasEncryptionMaterial && (
          <p className="text-sm text-red-600 mt-1">This key was created before encryption subkeys were added.</p>
        )}
      </div>

      {isKeyEncrypted && (
        <div>
          <label htmlFor="passphrase-decrypt" className="block text-sm font-medium text-gray-700 mb-1">Passphrase</label>
          <input
            type="password"
            id="passphrase-decrypt"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter passphrase to decrypt key material"
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
          />
        </div>
      )}

      <div>
        <label htmlFor="pgp-message-input" className="block text-sm font-medium text-gray-700 mb-1">Encrypted PGP Message</label>
        <textarea
          id="pgp-message-input"
          rows={14}
          value={pgpMessage}
          onChange={(e) => {
            setPgpMessage(e.target.value);
            setDecryptedMessage('');
            setError(null);
          }}
          placeholder={`-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----`}
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
        />
      </div>

      <button
        onClick={handleDecrypt}
        disabled={isDecrypting || !selectedKeyId || !pgpMessage || (isKeyEncrypted && !passphrase) || !hasEncryptionMaterial}
        className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {isDecrypting ? 'Decrypting...' : 'Decrypt'}
      </button>

      {error && (
        <p className="text-sm text-red-600">{error}</p>
      )}

      {decryptedMessage && (
        <div>
          <label htmlFor="decrypted-message-output" className="block text-sm font-medium text-gray-700 mb-1">
            Decrypted Message
          </label>
          <div className="relative">
            <textarea
              id="decrypted-message-output"
              readOnly
              rows={8}
              value={decryptedMessage}
              className="w-full px-3 py-2 border border-gray-300 bg-gray-50 rounded-md shadow-sm font-mono text-sm"
            />
            <button
              onClick={() => copy(decryptedMessage)}
              className="absolute top-2 right-2 p-1.5 bg-gray-200 rounded-md hover:bg-gray-300 transition"
              aria-label="Copy decrypted message"
            >
              {isCopied ? <CheckIcon /> : <CopyIcon />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
