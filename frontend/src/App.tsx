import React, { useState } from 'react';
import { Layout } from './components/Layout';
import { useTelemetryWebSocket } from './lib/ws';
import { OverviewPage } from './pages/OverviewPage';
import { ReconCvdPage } from './pages/ReconCvdPage';
import { NetArenaPage } from './pages/NetArenaPage';
import { ExploitStudioPage } from './pages/ExploitStudioPage';
import { FuzzRePage } from './pages/FuzzRePage';
import { MalTriagePage } from './pages/MalTriagePage';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const { events, isConnected, clearEvents } = useTelemetryWebSocket();

  return (
    <Layout activeTab={activeTab} setActiveTab={setActiveTab} isWsConnected={isConnected}>
      {activeTab === 'overview' && (
        <OverviewPage events={events} onClearEvents={clearEvents} onNavigate={setActiveTab} />
      )}
      {activeTab === 'recon' && <ReconCvdPage />}
      {activeTab === 'netarena' && <NetArenaPage />}
      {activeTab === 'exploit' && <ExploitStudioPage />}
      {activeTab === 'fuzzre' && <FuzzRePage />}
      {activeTab === 'maltriage' && <MalTriagePage />}
    </Layout>
  );
}
