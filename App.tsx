import React, { useState, useEffect, useCallback } from 'react';
import { KeyManagementTab } from './components/KeyManagementTab';
import { SignTab } from './components/SignTab';
import { VerifyTab } from './components/VerifyTab';
import { KeyDetailsModal } from './components/KeyDetailsModal';
import { TabButton } from './components/TabButton';
import { generateKeyPair as generate } from './services/cryptoService';
import type { KeyPair, Tab } from './types';
import { TABS } from './constants';
// FIX: Remove unused LockIcon import as it's not exported from the Icons module.
import { KeyIcon, PencilIcon, CheckBadgeIcon, QuestionIcon, ExclamationTriangleIcon } from './components/icons/Icons';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>(TABS.KEY_MANAGEMENT);
  const [keys, setKeys] = useState<KeyPair[]>([]);
  const [selectedKey, setSelectedKey] = useState<KeyPair | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  useEffect(() => {
    try {
      const storedKeys = localStorage.getItem('pq_keys');
      if (storedKeys) {
        setKeys(JSON.parse(storedKeys));
      }
    } catch (error) {
      console.error("Failed to load keys from localStorage", error);
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem('pq_keys', JSON.stringify(keys));
    } catch (error) {
      console.error("Failed to save keys to localStorage", error);
    }
  }, [keys]);

  const handleGenerateKeyPair = useCallback(async (userId: string, passphrase?: string) => {
    setIsGenerating(true);
    // Use setTimeout to allow the UI to update to the "generating" state
    // before the potentially blocking key generation operation starts.
    setTimeout(async () => {
      try {
        const newKey = await generate(userId, passphrase);
        setKeys(prevKeys => [...prevKeys, newKey]);
        setSelectedKey(newKey);
      } catch (error) {
        console.error("Key generation failed:", error);
        alert("An error occurred during key generation. Please check the console for details.");
      } finally {
        setIsGenerating(false);
      }
    }, 50);
  }, []);

  const renderActiveTab = () => {
    switch (activeTab) {
      case TABS.KEY_MANAGEMENT:
        return <KeyManagementTab onGenerate={handleGenerateKeyPair} keys={keys} isGenerating={isGenerating} onViewKey={setSelectedKey} />;
      case TABS.SIGN:
        return <SignTab keys={keys} />;
      case TABS.VERIFY:
        return <VerifyTab />;
      default:
        return <div className="p-6 bg-white rounded-lg shadow-md "><p>Select a feature above to get started.</p></div>;
    }
  };
  
  const TabIcon: React.FC<{tab: Tab}> = ({ tab }) => {
    switch (tab) {
        case TABS.KEY_MANAGEMENT: return <KeyIcon />;
        case TABS.SIGN: return <PencilIcon />;
        case TABS.VERIFY: return <CheckBadgeIcon />;
        default: return <QuestionIcon />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 text-gray-800 font-sans p-4 sm:p-6 lg:p-8">
      <div className="max-w-7xl mx-auto">
        <header className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900">Post-Quantum Toolkit</h1>
          <p className="text-lg text-gray-600 mt-1">Using SLHDSA256s_MLKEM1024_X448 — Post-Quantum Hybrid Keys</p>
        </header>

        <div className="bg-yellow-50 border-l-4 border-yellow-400 text-yellow-800 p-4 rounded-md shadow-sm mb-8" role="alert">
          <div className="flex items-center">
            <div className="py-1"><ExclamationTriangleIcon/></div>
            <div className="ml-3">
              <p className="font-bold">Important Note</p>
              <p className="text-sm">This application uses the <code className="bg-yellow-100 px-1 rounded">@noble/post-quantum</code> library for cryptographic operations. These operations are computationally intensive and may cause your browser to become unresponsive temporarily, especially during key generation. The generated keys are for demonstration purposes and should not be used for securing real, sensitive data.</p>
            </div>
          </div>
        </div>

        <div className="flex items-center border-b border-gray-200 mb-6">
          {Object.values(TABS).map(tab => (
            <TabButton key={tab} isActive={activeTab === tab} onClick={() => setActiveTab(tab)}>
              <TabIcon tab={tab} />
              {tab}
            </TabButton>
          ))}
        </div>

        <main>
          {renderActiveTab()}
        </main>
      </div>

      {selectedKey && (
        <KeyDetailsModal
          keyPair={selectedKey}
          onClose={() => setSelectedKey(null)}
        />
      )}
    </div>
  );
};

export default App;
