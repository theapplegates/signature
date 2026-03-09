import React, { useState } from 'react';
import type { KeyPair } from '../types';
import { KeyIcon, InformationCircleIcon } from './icons/Icons';

interface Props {
  onGenerate: (userId: string, passphrase?: string) => void;
  keys: KeyPair[];
  isGenerating: boolean;
  onViewKey: (key: KeyPair) => void;
}

export const KeyManagementTab: React.FC<Props> = ({ onGenerate, keys, isGenerating, onViewKey }) => {
  const [userId, setUserId] = useState('');
  const [passphrase, setPassphrase] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (userId.trim()) {
      onGenerate(userId, passphrase.trim() ? passphrase : undefined);
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200">
        <h2 className="text-2xl font-semibold text-gray-800 mb-1">Generate New Key Pair</h2>
        <p className="text-gray-500 mb-6">Algorithm: <span className="font-mono bg-gray-100 px-1.5 py-0.5 rounded">SLHDSA256s_MLKEM1024_X448</span></p>

        <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label htmlFor="userId" className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
            <input
              type="text"
              id="userId"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="Your Name <you@example.com>"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
              required
            />
          </div>
          <div>
            <label htmlFor="passphrase" className="block text-sm font-medium text-gray-700 mb-1">Passphrase (Optional)</label>
            <input
              type="password"
              id="passphrase"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="If provided, will encrypt the private key"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition"
            />
             <p className="text-xs text-gray-500 mt-1">Uses PBKDF2 and AES-GCM to secure your key in browser storage.</p>
          </div>
          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={isGenerating || !userId.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
            >
              {isGenerating ? (
                <>
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Generating...
                </>
              ) : 'Generate Key'}
            </button>
          </div>
        </form>
      </div>

      <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200">
        <h2 className="text-2xl font-semibold text-gray-800 mb-4">Available Keys ({keys.length})</h2>
        {keys.length === 0 ? (
          <div className="text-center py-6 px-4 bg-gray-50 rounded-lg border border-dashed border-gray-300">
            <InformationCircleIcon />
            <p className="mt-2 text-sm text-gray-600">No keys generated or imported yet. Generate a key above to get started.</p>
          </div>
        ) : (
          <ul className="space-y-3">
            {keys.map(key => (
              <li key={key.id} className="p-4 bg-gray-50 rounded-lg border border-gray-200 hover:bg-gray-100 hover:border-blue-400 transition-all duration-200 flex items-center justify-between">
                <div className="flex items-center">
                  <KeyIcon />
                  <div className="ml-4">
                    <p className="font-semibold text-gray-800">{key.userId}</p>
                    <p className="text-sm text-gray-500 font-mono">{key.fingerprint}</p>
                  </div>
                </div>
                <button 
                  onClick={() => onViewKey(key)}
                  className="px-4 py-1.5 text-sm font-medium text-blue-600 bg-blue-100 rounded-md hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  View Details
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};
