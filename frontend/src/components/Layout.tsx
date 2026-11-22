import React, { useState } from 'react';
import {
  Shield,
  LayoutDashboard,
  Radar,
  Network,
  Cpu,
  Bug,
  Biohazard,
  Play,
  CheckCircle2,
  XCircle,
  Loader2,
  Activity,
  Server
} from 'lucide-react';
import { api, ScenarioRunResponse } from '../lib/api';

interface LayoutProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isWsConnected: boolean;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  activeTab,
  setActiveTab,
  isWsConnected,
  children,
}) => {
  const [runningScenario, setRunningScenario] = useState(false);
  const [scenarioResult, setScenarioResult] = useState<ScenarioRunResponse | null>(null);
  const [showScenarioModal, setShowScenarioModal] = useState(false);

  const navItems = [
    { id: 'overview', label: 'Command Matrix', icon: LayoutDashboard },
    { id: 'recon', label: 'Recon & CVD Scope', icon: Radar },
    { id: 'netarena', label: 'Network Arena', icon: Network },
    { id: 'exploit', label: 'Exploit Studio & Stack', icon: Cpu },
    { id: 'fuzzre', label: 'Protocol Fuzz & ACL', icon: Bug },
    { id: 'maltriage', label: 'Malware & Artifact Triage', icon: Biohazard },
  ];

  const handleRunScenario = async () => {
    setRunningScenario(true);
    setShowScenarioModal(true);
    setScenarioResult(null);
    try {
      const res = await api.runPurpleTeam();
      setScenarioResult(res);
    } catch (e: any) {
      alert(`Scenario failed: ${e.message}`);
    } finally {
      setRunningScenario(false);
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between z-20 shrink-0">
        <div>
          {/* Logo Branding */}
          <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-md shadow-cyan-500/20">
                <Shield className="w-5 h-5 text-slate-950 stroke-[2.5]" />
              </div>
              <div>
                <h1 className="font-bold text-base tracking-wider text-white">AEGISFORGE</h1>
                <p className="text-[10px] text-cyan-400 font-mono tracking-widest uppercase">Purple-Team Range</p>
              </div>
            </div>
          </div>

          {/* Mode Pill & Health */}
          <div className="px-4 py-3 border-b border-slate-800/60 bg-slate-950/40 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">Mode:</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                SIMULATION
              </span>
            </div>
            <div className="flex items-center gap-1.5" title={isWsConnected ? "WebSocket Connected" : "Connecting..."}>
              <span className={`w-2 h-2 rounded-full ${isWsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <span className="text-[10px] text-slate-400 font-mono">{isWsConnected ? 'LIVE' : 'SYNC'}</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-blue-600/10 text-cyan-400 border border-cyan-500/30 font-semibold shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Global Purple-Team Trigger */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 space-y-3">
          <button
            onClick={handleRunScenario}
            disabled={runningScenario}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg text-xs font-bold text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-400 hover:from-cyan-300 hover:to-blue-300 transition shadow-lg shadow-cyan-500/25 disabled:opacity-50 cursor-pointer"
          >
            {runningScenario ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Executing Range...
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-slate-950" />
                Run Full Cyber Range
              </>
            )}
          </button>
          <div className="text-[10px] text-center text-slate-500 font-mono">
            RFC1918 Sandbox Strict Guard Active
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 overflow-y-auto bg-slate-950">
        <header className="h-14 border-b border-slate-800 px-6 flex items-center justify-between bg-slate-900/60 backdrop-blur shrink-0 sticky top-0 z-10">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase text-slate-500">Workbench /</span>
            <span className="text-sm font-semibold text-slate-100 capitalize">
              {navItems.find((n) => n.id === activeTab)?.label}
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-950 rounded-md border border-slate-800 text-slate-400 font-mono">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Safety Guard:</span>
              <span className="text-emerald-400 font-bold">ALLOWLIST_ONLY</span>
            </div>
          </div>
        </header>

        <div className="flex-1 p-6">{children}</div>
      </main>

      {/* End-to-End Scenario Execution Modal */}
      {showScenarioModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800/60">
                  <Play className="w-4 h-4 text-cyan-400" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-base">Purple-Team Cyber Range Engagement</h3>
                  <p className="text-xs text-slate-400">Automated 6-Stage Offensive Verification & Defensive Mitigation</p>
                </div>
              </div>
              <button
                onClick={() => setShowScenarioModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 font-mono text-xs">
              {runningScenario && (
                <div className="flex flex-col items-center justify-center py-8 space-y-3">
                  <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                  <p className="text-sm font-sans text-slate-300">Orchestrating multi-stage purple-team attack & defense cycle...</p>
                  <p className="text-xs text-slate-500">Broadcasting live telemetry packets across virtual micro-network.</p>
                </div>
              )}

              {scenarioResult && (
                <div className="space-y-4">
                  <div className="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-xl flex items-center justify-between">
                    <div>
                      <div className="text-emerald-400 font-bold text-sm font-sans">Exercise Successfully Completed</div>
                      <div className="text-slate-400 text-xs mt-0.5">ID: {scenarioResult.scenario_id}</div>
                    </div>
                    <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold text-xs">
                      {scenarioResult.status}
                    </span>
                  </div>

                  <p className="text-slate-300 font-sans text-xs leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800">
                    {scenarioResult.final_report_summary}
                  </p>

                  <div className="space-y-2">
                    <h4 className="font-bold text-slate-200 uppercase tracking-wider text-[11px]">Execution Stages</h4>
                    {scenarioResult.steps.map((st) => (
                      <div
                        key={st.step_id}
                        className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 flex items-start justify-between gap-3"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="text-cyan-400 font-bold">Stage {st.step_id}:</span>
                            <span className="text-white font-medium font-sans">{st.name}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                              {st.module}
                            </span>
                          </div>
                          <p className="text-slate-400 font-sans text-xs leading-normal">{st.details}</p>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                            st.status === 'MITIGATED'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          }`}
                        >
                          {st.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
              <button
                onClick={() => setShowScenarioModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
