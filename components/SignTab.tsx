import React, { useState } from 'react';
import type { KeyPair } from '../types';
import { sign, decryptPrivateKey } from '../services/cryptoService';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { CopyIcon, CheckIcon } from './icons/Icons';

interface Props {
  keys: KeyPair[];
}

export const SignTab: React.FC<Props> = ({ keys }) => {
  const [selectedKeyId, setSelectedKeyId] = useState<string>('');
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState('');
  const [isSigning, setIsSigning] = useState(false);
  const [isCopied, copy] = useCopyToClipboard();
  const [passphrase, setPassphrase] = useState('');
  const [decryptionError, setDecryptionError] = useState<string | null>(null);

  const selectedKey = keys.find(k => k.id === selectedKeyId);
  const isKeyEncrypted = !!selectedKey?.salt;

  const handleSign = async () => {
    if (!selectedKey || !message) return;

    setIsSigning(true);
    setSignature('');
    setDecryptionError(null);
    
    // Use setTimeout to allow UI to update before potentially blocking operation
    setTimeout(async () => {
        try {
            let privateKeyHex = selectedKey.privateKeyRaw;
            if (isKeyEncrypted) {
                if (!passphrase) {
                    setDecryptionError('Passphrase is required for this key.');
                    setIsSigning(false);
                    return;
                }
                try {
                    privateKeyHex = await decryptPrivateKey(selectedKey, passphrase);
                } catch (e) {
                    setDecryptionError('Decryption failed. Invalid passphrase?');
                    setIsSigning(false);
                    return;
                }
            }
            const sig = sign(privateKeyHex, message, {
                userId: selectedKey.userId,
                fingerprint: selectedKey.fingerprint,
            });
            setSignature(sig);
        } catch (error) {
            console.error("Signing failed:", error);
            alert("An error occurred during signing.");
        } finally {
            setIsSigning(false);
        }
    }, 50);
  };
  
  const handleKeySelectionChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setSelectedKeyId(e.target.value);
    setPassphrase('');
    setSignature('');
    setDecryptionError(null);
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200 space-y-6">
      <h2 className="text-2xl font-semibold text-gray-800">Sign Message</h2>
      
      <div>
        <label htmlFor="key-select" className="block text-sm font-medium text-gray-700 mb-1">Select Key to Sign With</label>
        <select
          id="key-select"
          value={selectedKeyId}
          onChange={handleKeySelectionChange}
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition disabled:bg-gray-100"
          disabled={keys.length === 0}
        >
          <option value="">{keys.length > 0 ? 'Select a key...' : 'No keys available'}</option>
          {keys.map(key => (
            <option key={key.id} value={key.id}>
              {key.userId} ({key.fingerprint.substring(0, 19)}...){key.salt ? ' 🔒' : ''}
            </option>
          ))}
        </select>
      </div>

      {isKeyEncrypted && (
        <div>
          <label htmlFor="passphrase-sign" className="block text-sm font-medium text-gray-700 mb-1">Passphrase</label>
          <input
            type="password"
            id="passphrase-sign"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter passphrase to decrypt key"
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
            required
          />
          {decryptionError && <p className="text-sm text-red-600 mt-1">{decryptionError}</p>}
        </div>
      )}

      <div>
        <label htmlFor="message-to-sign" className="block text-sm font-medium text-gray-700 mb-1">Message</label>
        <textarea
          id="message-to-sign"
          rows={6}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter the message you want to sign..."
          className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono"
        />
      </div>

      <button
        onClick={handleSign}
        disabled={isSigning || !selectedKeyId || !message || (isKeyEncrypted && !passphrase)}
        className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
      >
        {isSigning ? 'Signing...' : 'Generate Signature'}
      </button>

      {signature && (
        <div>
          <label htmlFor="signature-output" className="block text-sm font-medium text-gray-700 mb-1">Generated Signature (.asc format)</label>
          <div className="relative">
             <textarea
              id="signature-output"
              readOnly
              rows={12}
              value={signature}
              className="w-full px-3 py-2 border border-gray-300 bg-gray-50 rounded-md shadow-sm font-mono"
            />
            <button
              onClick={() => copy(signature)}
              className="absolute top-2 right-2 p-1.5 bg-gray-200 rounded-md hover:bg-gray-300 transition"
              aria-label="Copy signature"
            >
              {isCopied ? <CheckIcon /> : <CopyIcon />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};