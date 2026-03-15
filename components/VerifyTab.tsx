import React, { useState } from 'react';
import { verify, extractRawPublicKeyFromV6Packet } from '../services/cryptoService';

// A simple PGP block parser to extract base64 data
function extractBase64FromPgp(pgpBlock: string): string {
    const lines = pgpBlock.split('\n');
    const base64Lines = lines.filter(line => 
        !line.startsWith('-----') &&
        !line.startsWith('Comment:') &&
        !line.startsWith('Version:') &&
        !line.startsWith('Hash:') &&
        line.trim() !== ''
    );
    return base64Lines.join('');
}

function base64ToBytes(b64: string): Uint8Array {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        out[i] = binary.charCodeAt(i);
    }
    return out;
}

export const VerifyTab: React.FC = () => {
    const [publicKeyPgp, setPublicKeyPgp] = useState('');
    const [message, setMessage] = useState('');
    const [signature, setSignature] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const [verificationResult, setVerificationResult] = useState<boolean | null>(null);

    const handleVerify = () => {
        if (!publicKeyPgp || !message || !signature) return;

        setIsVerifying(true);
        setVerificationResult(null);

        setTimeout(() => {
            try {
                // Decode the v6 Public Key packet body from PGP armor
                const base64PublicKey = extractBase64FromPgp(publicKeyPgp);
                const v6PacketBytes = base64ToBytes(base64PublicKey);

                // Extract the raw SLH-DSA public key from the v6 packet
                const rawPk = extractRawPublicKeyFromV6Packet(v6PacketBytes);
                const publicKeyHex = Array.from(rawPk, byte => byte.toString(16).padStart(2, '0')).join('');

                // Extract the base64 signature payload (contains salt || signature)
                const base64Signature = extractBase64FromPgp(signature);

                const result = verify(publicKeyHex, message, base64Signature);
                setVerificationResult(result);
            } catch (error) {
                console.error("Verification failed:", error);
                setVerificationResult(false);
            } finally {
                setIsVerifying(false);
            }
        }, 50);
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200 space-y-6">
            <h2 className="text-2xl font-semibold text-gray-800">Verify Signature</h2>
            
            <div>
                <label htmlFor="public-key-verify" className="block text-sm font-medium text-gray-700 mb-1">Public Key</label>
                <textarea
                    id="public-key-verify"
                    rows={7}
                    value={publicKeyPgp}
                    onChange={(e) => setPublicKeyPgp(e.target.value)}
                    placeholder={`-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----`}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
                />
            </div>

            <div>
                <label htmlFor="message-to-verify" className="block text-sm font-medium text-gray-700 mb-1">Signed Message (with key identity headers)</label>
                <textarea
                    id="message-to-verify"
                    rows={8}
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder={"Comment: User ID:\t...\nComment: Valid from:\t...\nComment: Type:\t...\nComment: Usage:\t...\nComment: Fingerprint:\t...\n\nYour original message here..."}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
                />
            </div>

            <div>
                <label htmlFor="signature-to-verify" className="block text-sm font-medium text-gray-700 mb-1">Signature (.asc format)</label>
                <textarea
                    id="signature-to-verify"
                    rows={7}
                    value={signature}
                    onChange={(e) => setSignature(e.target.value)}
                    placeholder={`-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----`}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
                />
            </div>
            
            <div className="flex items-center space-x-4">
                <button
                    onClick={handleVerify}
                    disabled={isVerifying || !publicKeyPgp || !message || !signature}
                    className="w-full sm:w-auto inline-flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
                >
                    {isVerifying ? 'Verifying...' : 'Verify'}
                </button>
                {verificationResult !== null && (
                    <div className={`px-4 py-2 rounded-md text-sm font-semibold ${verificationResult ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                        {verificationResult ? '✅ Signature is valid' : '❌ Signature is invalid'}
                    </div>
                )}
            </div>
        </div>
    );
};
