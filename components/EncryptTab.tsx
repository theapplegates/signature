import React, { useState } from 'react';
import type { KeyPair } from '../types';
import { encryptMessage } from '../services/cryptoService';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { CopyIcon, CheckIcon } from './icons/Icons';

interface Props {
  keys: KeyPair[];
}

export const EncryptTab: React.FC<Props> = ({ keys }) => {
  const [selectedKeyId, setSelectedKeyId] = useState('');
  const [message, setMessage] = useState('');
  const [encryptedMessage, setEncryptedMessage] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isCopied, copy] = useCopyToClipboard();

  const selectedKey = keys.find(k => k.id === selectedKeyId);
  const hasEncryptionMaterial = !!selectedKey?.kemPublicKeyRaw && !!selectedKey?.x448PublicKeyRaw;

  const handleEncrypt = async () => {
    if (!selectedKey || !message) return;

    if (!selectedKey.kemPublicKeyRaw || !selectedKey.x448PublicKeyRaw) {
      setError('Selected key does not include ML-KEM/X448 public subkeys. Generate a new key pair.');
      return;
    }

    setIsEncrypting(true);
    setError(null);
    setEncryptedMessage('');

    setTimeout(async () => {
      try {
        const pgpMessage = await encryptMessage(
          selectedKey.kemPublicKeyRaw,
          selectedKey.x448PublicKeyRaw,
          message,
          selectedKey.fingerprint
        );
        setEncryptedMessage(pgpMessage);
      } catch (encryptError) {
        console.error('Encryption failed:', encryptError);
        setError('Encryption failed. Check the selected key and try again.');
      } finally {
        setIsEncrypting(false);
      }
    }, 50);
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200 space-y-6">
      <h2 className="text-2xl font-semibold text-gray-800">Encrypt Message</h2>

      <div>
        <label htmlFor="encrypt-key-select" className="block text-sm font-medium text-gray-700 mb-1">Select Recipient Key</label>
        <select
          id="encrypt-key-select"
          value={selectedKeyId}
          onChange={(e) => {
            setSelectedKeyId(e.target.value);
            setEncryptedMessage('');
            setError(null);
          }}
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition disabled:bg-gray-100"
          disabled={keys.length === 0}
        >
          <option value="">{keys.length > 0 ? 'Select a recipient key...' : 'No keys available'}</option>
          {keys.map(key => (
            <option key={key.id} value={key.id}>
              {key.userId} ({key.fingerprint.substring(0, 19)}...)
            </option>
          ))}
        </select>
        {selectedKey && !hasEncryptionMaterial && (
          <p className="text-sm text-red-600 mt-1">This key was created before encryption subkeys were added.</p>
        )}
      </div>

      <div>
        <label htmlFor="message-to-encrypt" className="block text-sm font-medium text-gray-700 mb-1">Message</label>
        <textarea
          id="message-to-encrypt"
          rows={8}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter the message you want to encrypt..."
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
        />
      </div>

      <button
        onClick={handleEncrypt}
        disabled={isEncrypting || !selectedKeyId || !message || !hasEncryptionMaterial}
        className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {isEncrypting ? 'Encrypting...' : 'Encrypt'}
      </button>

      {error && (
        <p className="text-sm text-red-600">{error}</p>
      )}

      {encryptedMessage && (
        <div>
          <label htmlFor="encrypted-message-output" className="block text-sm font-medium text-gray-700 mb-1">
            Encrypted PGP Message
          </label>
          <div className="relative">
            <textarea
              id="encrypted-message-output"
              readOnly
              rows={14}
              value={encryptedMessage}
              className="w-full px-3 py-2 border border-gray-300 bg-gray-50 rounded-md shadow-sm font-mono text-sm"
            />
            <button
              onClick={() => copy(encryptedMessage)}
              className="absolute top-2 right-2 p-1.5 bg-gray-200 rounded-md hover:bg-gray-300 transition"
              aria-label="Copy encrypted message"
            >
              {isCopied ? <CheckIcon /> : <CopyIcon />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
