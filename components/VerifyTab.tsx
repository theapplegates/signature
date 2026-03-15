import React, { useState } from 'react';
import { verify, extractRawPublicKeyFromV6Packet } from '../services/cryptoService';

// Extract base64 payload from a PGP armor block, skipping all header lines.
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

/**
 * Parse a PGP clearsigned message block into its message content and
 * detached signature block.  Returns null if the input is not a valid
 * clearsigned block.
 *
 * Format:
 *   -----BEGIN PGP SIGNED MESSAGE-----
 *   Hash: ...
 *
 *   [message content including Comment: lines]
 *   -----BEGIN PGP SIGNATURE-----
 *   ...
 *   -----END PGP SIGNATURE-----
 */
function parseClearSignedMessage(input: string): { message: string; signatureBlock: string } | null {
    const SIGNED_MSG_HEADER = '-----BEGIN PGP SIGNED MESSAGE-----';
    const SIG_START = '-----BEGIN PGP SIGNATURE-----';

    if (!input.includes(SIGNED_MSG_HEADER) || !input.includes(SIG_START)) {
        return null;
    }

    // The message content starts after the first blank line following the header block.
    const headerEnd = input.indexOf('\n\n', input.indexOf(SIGNED_MSG_HEADER));
    const sigStartIdx = input.indexOf(SIG_START);

    if (headerEnd === -1 || sigStartIdx === -1 || headerEnd >= sigStartIdx) {
        return null;
    }

    const message = input.slice(headerEnd + 2, sigStartIdx).trimEnd();
    const signatureBlock = input.slice(sigStartIdx);
    return { message, signatureBlock };
}

export const VerifyTab: React.FC = () => {
    const [mode, setMode] = useState<'clearsign' | 'manual'>('clearsign');
    const [clearSignedInput, setClearSignedInput] = useState('');
    const [publicKeyPgp, setPublicKeyPgp] = useState('');
    const [message, setMessage] = useState('');
    const [signature, setSignature] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const [verificationResult, setVerificationResult] = useState<boolean | null>(null);
    const [parseError, setParseError] = useState<string | null>(null);

    const resetResult = () => {
        setVerificationResult(null);
        setParseError(null);
    };

    const handleVerify = () => {
        resetResult();

        let msgToVerify = message;
        let sigToVerify = signature;

        if (mode === 'clearsign') {
            const parsed = parseClearSignedMessage(clearSignedInput);
            if (!parsed) {
                setParseError('Could not parse the clearsigned message. Make sure you pasted the full block including the -----BEGIN PGP SIGNED MESSAGE----- header.');
                return;
            }
            msgToVerify = parsed.message;
            sigToVerify = parsed.signatureBlock;
        }

        if (!publicKeyPgp || !msgToVerify || !sigToVerify) return;

        setIsVerifying(true);

        setTimeout(() => {
            try {
                // Decode the v6 Public Key packet body from PGP armor
                const base64PublicKey = extractBase64FromPgp(publicKeyPgp);
                const v6PacketBytes = base64ToBytes(base64PublicKey);

                // Extract the raw SLH-DSA public key from the v6 packet
                const rawPk = extractRawPublicKeyFromV6Packet(v6PacketBytes);
                const publicKeyHex = Array.from(rawPk, byte => byte.toString(16).padStart(2, '0')).join('');

                // Extract the base64 signature payload (contains salt || signature)
                const base64Signature = extractBase64FromPgp(sigToVerify);

                const result = verify(publicKeyHex, msgToVerify, base64Signature);
                setVerificationResult(result);
            } catch (error) {
                console.error('Verification failed:', error);
                setVerificationResult(false);
            } finally {
                setIsVerifying(false);
            }
        }, 50);
    };

    const canVerify = !!publicKeyPgp && (
        mode === 'clearsign' ? !!clearSignedInput : (!!message && !!signature)
    );

    return (
        <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200 space-y-6">
            <h2 className="text-2xl font-semibold text-gray-800">Verify Signature</h2>

            {/* Mode selector */}
            <div className="flex rounded-md shadow-sm border border-gray-300 overflow-hidden w-fit">
                <button
                    onClick={() => { setMode('clearsign'); resetResult(); }}
                    className={`px-4 py-2 text-sm font-medium transition ${mode === 'clearsign' ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}
                >
                    Paste clearsigned block
                </button>
                <button
                    onClick={() => { setMode('manual'); resetResult(); }}
                    className={`px-4 py-2 text-sm font-medium border-l border-gray-300 transition ${mode === 'manual' ? 'bg-blue-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50'}`}
                >
                    Enter parts separately
                </button>
            </div>

            {/* Public key — always required */}
            <div>
                <label htmlFor="public-key-verify" className="block text-sm font-medium text-gray-700 mb-1">Public Key</label>
                <textarea
                    id="public-key-verify"
                    rows={6}
                    value={publicKeyPgp}
                    onChange={(e) => { setPublicKeyPgp(e.target.value); resetResult(); }}
                    placeholder={`-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----`}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
                />
            </div>

            {mode === 'clearsign' ? (
                <div>
                    <label htmlFor="clearsign-input" className="block text-sm font-medium text-gray-700 mb-1">
                        PGP Signed Message (paste the entire block from the Sign tab)
                    </label>
                    <textarea
                        id="clearsign-input"
                        rows={16}
                        value={clearSignedInput}
                        onChange={(e) => { setClearSignedInput(e.target.value); resetResult(); }}
                        placeholder={`-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA3-512\n\nComment: User ID:\t...\n\nYour message here\n-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----`}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
                    />
                    {parseError && <p className="text-sm text-red-600 mt-1">{parseError}</p>}
                </div>
            ) : (
                <>
                    <div>
                        <label htmlFor="message-to-verify" className="block text-sm font-medium text-gray-700 mb-1">Signed Message (include the Comment: header lines)</label>
                        <textarea
                            id="message-to-verify"
                            rows={8}
                            value={message}
                            onChange={(e) => { setMessage(e.target.value); resetResult(); }}
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
                            onChange={(e) => { setSignature(e.target.value); resetResult(); }}
                            placeholder={`-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----`}
                            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 transition font-mono text-sm"
                        />
                    </div>
                </>
            )}

            <div className="flex items-center space-x-4">
                <button
                    onClick={handleVerify}
                    disabled={isVerifying || !canVerify}
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
