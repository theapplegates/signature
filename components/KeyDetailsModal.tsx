import React from 'react';
import type { KeyPair } from '../types';
import { useCopyToClipboard } from '../hooks/useCopyToClipboard';
import { CheckIcon, CopyIcon, ExclamationTriangleIcon, CheckCircleIcon, DownloadIcon } from './icons/Icons';

interface Props {
  keyPair: KeyPair;
  onClose: () => void;
}

const KeyBlock: React.FC<{ title: string; content: string; filename: string }> = ({ title, content, filename }) => {
  const [isCopied, copy] = useCopyToClipboard();

  const handleDownload = () => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain;charset=utf-8' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div>
      <h3 className="text-lg font-medium text-gray-800 mb-2">{title}</h3>
      <div className="relative">
        <textarea
          readOnly
          value={content}
          rows={8}
          className="w-full p-3 bg-gray-100 border border-gray-300 rounded-md font-mono text-xs text-gray-700 focus:outline-none"
        />
        <div className="absolute top-2 right-2 flex space-x-2">
            <button
                onClick={handleDownload}
                className="flex items-center px-3 py-1.5 text-sm font-medium rounded-md bg-gray-200 hover:bg-gray-300 text-gray-700 transition"
                aria-label="Download as .asc file"
            >
                <DownloadIcon />
                <span className="ml-2">Download</span>
            </button>
            <button
              onClick={() => copy(content)}
              className="flex items-center px-3 py-1.5 text-sm font-medium rounded-md bg-gray-200 hover:bg-gray-300 text-gray-700 transition"
              aria-label={isCopied ? 'Copied to clipboard' : 'Copy to clipboard'}
            >
                <div className="flex items-center">
                  {isCopied ? <CheckIcon /> : <CopyIcon />}
                  <span className="ml-2">{isCopied ? 'Copied!' : 'Copy'}</span>
                </div>
            </button>
        </div>
      </div>
    </div>
  );
};

export const KeyDetailsModal: React.FC<Props> = ({ keyPair, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="p-6 sm:p-8">
            <div className="flex justify-between items-start mb-6">
              <h2 className="text-2xl sm:text-3xl font-bold text-gray-900">Key Pair Details</h2>
              <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition">&times;</button>
            </div>

            <div className="bg-green-50 border-l-4 border-green-400 p-4 rounded-md mb-6">
                <div className="flex">
                    <div className="flex-shrink-0">
                        <CheckCircleIcon />
                    </div>
                    <div className="ml-3">
                        <h3 className="text-sm font-medium text-green-800">Key Pair Generated Successfully</h3>
                        <div className="mt-2 text-sm text-green-700">
                            <p>Key ID: <span className="font-mono">{keyPair.fingerprint.replace(/\s/g, '').slice(-16)}</span>. Remember your passphrase if you set one!</p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-600 mb-1">User ID:</label>
                <input
                    type="text"
                    readOnly
                    value={keyPair.userId}
                    className="w-full p-2 bg-gray-100 border border-gray-300 rounded-md text-gray-800"
                />
              </div>

              <KeyBlock 
                title="Public Key" 
                content={keyPair.publicKeyPgp}
                filename={`public-key-${keyPair.fingerprint.replace(/\s/g, '').slice(-16)}.asc`} 
              />
              
              <div className="bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800 p-4 rounded-md">
                <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <ExclamationTriangleIcon />
                    </div>
                    <div className="ml-3">
                      <p className="font-bold">Private Key - DO NOT SHARE</p>
                      <p className="text-sm">This is your secret key. Keep it safe and do not share it with anyone.</p>
                      {keyPair.salt && <p className="text-sm mt-1">This key is protected by a passphrase.</p>}
                    </div>
                </div>
              </div>

              <KeyBlock 
                title="Private Key" 
                content={keyPair.privateKeyPgp}
                filename={`private-key-${keyPair.fingerprint.replace(/\s/g, '').slice(-16)}.asc`}
              />
            </div>
        </div>
        <div className="bg-gray-50 px-6 py-4 flex justify-end rounded-b-xl border-t border-gray-200">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-gray-200 text-gray-800 font-semibold rounded-lg hover:bg-gray-300 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};