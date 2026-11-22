import React, { useState, useEffect } from 'react';
import { Layout } from './components/Layout';
import { ToastProvider } from './components/Toast';
import { ErrorBoundary } from './components/ErrorBoundary';
import { useTelemetryWebSocket } from './lib/ws';
import { OverviewPage } from './pages/OverviewPage';
import { ReconCvdPage } from './pages/ReconCvdPage';
import { NetArenaPage } from './pages/NetArenaPage';
import { ExploitStudioPage } from './pages/ExploitStudioPage';
import { FuzzRePage } from './pages/FuzzRePage';
import { MalTriagePage } from './pages/MalTriagePage';

export default function App() {
  const getInitialTab = () => {
    if (typeof window !== 'undefined' && window.location.hash) {
      const hash = window.location.hash.replace('#', '').trim();
      const valid = ['overview', 'recon', 'netarena', 'exploit', 'fuzzre', 'maltriage'];
      if (valid.includes(hash)) return hash;
    }
    return 'overview';
  };

  const [activeTab, setActiveTabState] = useState<string>(getInitialTab);
  const { events, isConnected, clearEvents } = useTelemetryWebSocket();

  const setActiveTab = (tab: string) => {
    window.location.hash = tab;
    setActiveTabState(tab);
  };

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '').trim();
      if (['overview', 'recon', 'netarena', 'exploit', 'fuzzre', 'maltriage'].includes(hash)) {
        setActiveTabState(hash);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  return (
    <ToastProvider>
      <Layout activeTab={activeTab} setActiveTab={setActiveTab} isWsConnected={isConnected}>
        <ErrorBoundary fallbackTitle={`${activeTab.toUpperCase()} Workspace Fault`}>
          {activeTab === 'overview' && (
            <OverviewPage events={events} onClearEvents={clearEvents} onNavigate={setActiveTab} />
          )}
          {activeTab === 'recon' && <ReconCvdPage />}
          {activeTab === 'netarena' && <NetArenaPage />}
          {activeTab === 'exploit' && <ExploitStudioPage />}
          {activeTab === 'fuzzre' && <FuzzRePage />}
          {activeTab === 'maltriage' && <MalTriagePage />}
        </ErrorBoundary>
      </Layout>
    </ToastProvider>
  );
}
